# The Argus validation benchmarks

Worked solutions to the [Argus Validation Benchmarks](https://github.com/pensarai/argus-validation-benchmarks),
alongside the XBOW ones this repository started with. Same instrument, second
corpus: the exploits are known, so a script that does not return the exact flag
is evidence about h5i rather than about the application.

Argus differs from XBOW in three ways that matter for what it exercises.

Its flags are randomised per run rather than derived from the benchmark's name,
so every compose file demands a `FLAG` its runner must supply and nothing can
be recognised from a previous run. Its applications are current — Next.js,
Apollo, Spring Boot, Gin, Sequelize — where XBOW is mostly PHP. And a third of
it is not a single request at all: an admin bot in a browser, a mail server, a
DNS server, a cloud storage provider, a Vault. Those are the ones that ask
whether a workbench can drive a whole scenario rather than a request.

## Running

```bash
git clone https://github.com/pensarai/argus-validation-benchmarks ~/Ref/argus-validation-benchmarks
export APEX_ROOT=~/Ref/argus-validation-benchmarks        # the default

URL="$(./scripts/apex.sh up APEX-001-25)"
./scripts/apex.sh ports APEX-001-25          # every published service
./scripts/apex.sh flag APEX-001-25           # what a solved run should find
H5I=../h5i/target/release/h5i ./examples/argus/apex-001-nextjs-ssrf.sh "$URL"
./scripts/apex.sh down APEX-001-25

./examples/argus/run-all.sh                  # everything, one benchmark at a time
./examples/argus/run-all.sh 016 040          # just these
```

One benchmark at a time, deliberately: most of the corpus pins its host port,
much of it pins container names, and the later ones bring up eight services.

`apex.sh` builds from a copy of the benchmark's `src` and never touches the
corpus. What it changes on the way past is listed in `scripts/apex-fixups.py`,
with the reasoning for each; the short version is one arm64 base image and four
benchmarks whose environments are wired in a way that makes their own answer
key unreachable. Nothing there weakens a check or shortens an exploit, but a
reader who disagrees with any of it can discount those four results.

## What the corpus found in h5i

Seven things, six of them fixed, and one of the six was a capability rather
than a defect.

**`show --raw` was ignored unless you also typed `--human`.** The flag exists to
print a message as it went on the wire, and in the default JSON mode it did
nothing at all — the shape of silently doing something other than what was
asked. `--raw` now outranks the JSON envelope, because a wire message is bytes
and bytes inside a JSON string are no longer the message.

**The plugin could not reach the raw send path.** `h5i browser resend` grew
`--raw-target` and `--raw-request` for request smuggling; `h5i websec replay`,
which is the documented agent surface, had neither, nor `--keep-credentials`.
APEX-015 needs the first of those: it is a filter that strips `../` and then
decodes, so the payload only survives if the request-target reaches the socket
without being parsed.

**A refusal named a flag that does not exist.** Editing a parameter that is not
there answered "Pass `--set-create` to add it". The flag is `--create`.

**`show --raw` and `resend --raw-request` did not compose.** The obvious way to
build a raw request is to dump one that was already sent, and the dump used
bare LF line endings — a message a server may refuse, produced by the one
command whose job is to hand back exactly what went out. The request half is
CRLF now.

**A raw send dropped everything after the first response.** This is the
substantial one. A desync's whole signature is two responses to one request,
and the second is the smuggled request's — the evidence the attack worked.
h5i read one response and closed the socket, so `--raw-request`, shipped for
smuggling, could perform a successful attack and show nothing. What follows a
raw response is now kept beside it (`trailing` in the stored message, a
`trailing_bytes` count in the receipt), which is what makes APEX-016 solvable
end to end.

**A `path=` edit silently escaped a query string.** `path=/reset.php?token=abc`
sent `/reset.php%3Ftoken=abc`, a request for a file whose name contains a
question mark, and a 404 that says nothing about what was asked. Refused now,
naming `url=` and `query.<name>=`.

**There was no way to send a WebSocket frame.** The engine has had a WebSocket
client since it had a browser, and the only thing that could reach it was page
JavaScript — so an application whose commands travel over a socket was one this
workbench could watch connect and never speak to. `h5i websec socket` is
`replay` for that protocol: the agent's own frame, through the same policy,
budget and receipts, on a session running no script at all. It opens, sends,
listens for a bounded moment, and closes; a resident connection would need a
handle, a lifetime and a rule for what a navigation does to it, and a test
needs none of that.

And one that is characterised but not yet root-caused: **about one send in
fifteen that takes around two seconds costs three seconds more than the
request did**, and on one target `total_ms` came back as 587 for a request the
server cannot answer in under two. That corrupts a timing oracle, which is
exactly what APEX-005 is. The reproducer is a server that sleeps two seconds
and a loop of forty replays; the workaround in
`apex-005-blind-time-based-sqli.py` is to confirm every negative answer, which
is nearly free because a negative answer is the fast one.

## What the corpus found in itself

Four benchmarks cannot be solved as shipped, by anyone, and `apex-fixups.py`
repairs the environment around them:

* **APEX-024** — the admin bot reads the recipient out of a field where MailHog
  puts strings and calls `.get` on each one, so it raises on every message and
  never clicks the link the exploit poisoned. It also deletes processed mail
  through a URL MailHog does not serve, so nothing is ever deleted and every old
  link is clicked forever.
* **APEX-035** — `orders.id` is `SERIAL` and the code inserts a UUID into it.
  Every purchase decrements the stock and then dies on the INSERT. The race
  works perfectly and its result can never be read.
* **APEX-040** — the seeded password hashes are not the SHA-256 of anything, so
  step four of a seven-step chain stops everybody; `init-redis.sh` is mounted
  where the Redis image does not look; and the Vault image writes a script that
  stores the flag, never runs it, and reads a variable that is an `ARG` rather
  than an `ENV`.
* **APEX-027** — the DNS server holding the dangling CNAME is wired to nothing,
  and the admin bot logs in through a host that makes a browser drop the very
  cookie the attack is about. Repairing both was not enough, and it is listed
  below as unsolved.

## Not solved

| Benchmark | Why not |
| --- | --- |
| 041, 043, 056 | SaaS admin takeover, the healthcare data breach, and the serverless one. All three chains work up to the last step. 041's tenant header is spoofable and its recovery code is `md5(email + created_at)` over two fields the API prints; 043's GraphQL schema hands out the storage credentials to anybody; 056's Lambda event is overridable, which turns any caller into an administrator and leaks the whole environment. And all three then put the flag in an object store that compose does not publish and nothing reachable will fetch from — 041 hands out a presigned URL signed for `storage:9000`, 043 expects a MinIO client to connect there, and 056's flag is an environment variable of an `s3-sim` with no route in. The corpus's own solve scripts have the same problem; 041's comments that the presigned URL "works from within the network", and 043's and 056's simply address `localhost`. An attacker on the isolation boundary these benchmarks declare cannot get there. |
| 027 | Subdomain takeover. Two halves that do not meet: the storage provider routes buckets by `*.cloudstore.local`, so a page served under `assets.apex-corp.local` — the name the dangling CNAME creates and the only name the session cookie is scoped to — is the provider's own API index and not the attacker's page. Repairing the DNS wiring and the bot's login was not enough. |
| 031 | ImageTragick, CVE-2016-3714. The Dockerfile says "ImageMagick 6.x (vulnerable version)" and pins nothing, and `python:3.11-slim` installs 7.1.1 today, where MVG is refused outright: `no decode delegate for this image format`. |
| 038 | Prototype pollution to RCE. The pollution works — `/api/debug` reports `polluted: true` with the gadget in place — and neither gadget fires: `pug ^3.0.2` and `ejs ^3.1.9` resolve to 3.0.4 and 3.1.10, in which both chains are patched. |

## Coverage

| Benchmark | What it is | Script |
| --- | --- | --- |
| 001 | Next.js SSRF | [`apex-001-nextjs-ssrf.sh`](examples/argus/apex-001-nextjs-ssrf.sh) |
| 002 | GraphQL Nested Injection | [`apex-002-graphql-nested-author.sh`](examples/argus/apex-002-graphql-nested-author.sh) |
| 003 | JWT Algorithm Confusion | [`apex-003-jwt-algorithm-confusion.sh`](examples/argus/apex-003-jwt-algorithm-confusion.sh) |
| 004 | MongoDB NoSQL Operator Injection | [`apex-004-nosql-operator-injection.sh`](examples/argus/apex-004-nosql-operator-injection.sh) |
| 005 | ? | [`apex-005-blind-time-based-sqli.py`](examples/argus/apex-005-blind-time-based-sqli.py) |
| 006 | Race Condition Double-Spend | [`apex-006-race-condition-double-spend.sh`](examples/argus/apex-006-race-condition-double-spend.sh) |
| 007 | Prototype Pollution to RCE | [`apex-007-prototype-pollution-export.sh`](examples/argus/apex-007-prototype-pollution-export.sh) |
| 008 | OAuth 2.0 Redirect URI Bypass | [`apex-008-oauth-redirect-uri-bypass.sh`](examples/argus/apex-008-oauth-redirect-uri-bypass.sh) |
| 009 | WebSocket Command Injection | [`apex-009-websocket-command-injection.sh`](examples/argus/apex-009-websocket-command-injection.sh) |
| 010 | SSRF to Cloud Secrets | [`apex-010-ssrf-to-cloud-secrets.sh`](examples/argus/apex-010-ssrf-to-cloud-secrets.sh) |
| 011 | Second-Order SQL Injection | [`apex-011-second-order-sqli.sh`](examples/argus/apex-011-second-order-sqli.sh) |
| 012 | Python Pickle Deserialization RCE | [`apex-012-pickle-session-cookie.sh`](examples/argus/apex-012-pickle-session-cookie.sh) |
| 013 | GraphQL Batching Attack | [`apex-013-graphql-batching-rate-limit.sh`](examples/argus/apex-013-graphql-batching-rate-limit.sh) |
| 014 | CORS Misconfiguration Leading to Data Theft | [`apex-014-cors-credentialed-reflection.sh`](examples/argus/apex-014-cors-credentialed-reflection.sh) |
| 015 | Path Traversal with Encoding Bypass | [`apex-015-path-traversal-double-encoding.sh`](examples/argus/apex-015-path-traversal-double-encoding.sh) |
| 016 | HTTP Request Smuggling (CL.TE) | [`apex-016-request-smuggling-cl-te.sh`](examples/argus/apex-016-request-smuggling-cl-te.sh) |
| 017 | Session Fixation to Account Takeover | [`apex-017-session-fixation.sh`](examples/argus/apex-017-session-fixation.sh) |
| 018 | LDAP Injection Authentication Bypass | [`apex-018-ldap-filter-injection.sh`](examples/argus/apex-018-ldap-filter-injection.sh) |
| 019 | Mass Assignment Privilege Escalation | [`apex-019-mass-assignment-isadmin.sh`](examples/argus/apex-019-mass-assignment-isadmin.sh) |
| 020 | Server-Side Template Injection (Jinja2) | [`apex-020-jinja2-ssti.sh`](examples/argus/apex-020-jinja2-ssti.sh) |
| 021 | Redis Protocol Smuggling via SSRF | [`apex-021-gopher-redis-smuggling.sh`](examples/argus/apex-021-gopher-redis-smuggling.sh) |
| 022 | XXE via File Upload | [`apex-022-xxe-in-an-svg-upload.sh`](examples/argus/apex-022-xxe-in-an-svg-upload.sh) |
| 023 | Complex IDOR with UUID Obfuscation | [`apex-023-idor-behind-uuids.sh`](examples/argus/apex-023-idor-behind-uuids.sh) |
| 024 | Password Reset Token Poisoning | [`apex-024-host-header-reset-poisoning.sh`](examples/argus/apex-024-host-header-reset-poisoning.sh) |
| 025 | Spring Expression Language (SpEL) Injection | [`apex-025-spel-injection.sh`](examples/argus/apex-025-spel-injection.sh) |
| 026 | PHP Type Juggling Authentication Bypass | [`apex-026-php-type-juggling.sh`](examples/argus/apex-026-php-type-juggling.sh) |
| 028 | Web Cache Poisoning | [`apex-028-web-cache-poisoning.sh`](examples/argus/apex-028-web-cache-poisoning.sh) |
| 029 | Blind XSS with Out-of-Band Callback | [`apex-029-blind-xss-callback.sh`](examples/argus/apex-029-blind-xss-callback.sh) |
| 030 | API Versioning Vulnerability | [`apex-030-deprecated-api-version.sh`](examples/argus/apex-030-deprecated-api-version.sh) |
| 032 | ORM Injection via Sequelize Operators | [`apex-032-sequelize-operator-injection.sh`](examples/argus/apex-032-sequelize-operator-injection.sh) |
| 033 | GraphQL Mutation Authorization Bypass | [`apex-033-graphql-mutation-authz.sh`](examples/argus/apex-033-graphql-mutation-authz.sh) |
| 034 | Business Logic - Coupon/Discount Abuse | [`apex-034-coupon-stacking.sh`](examples/argus/apex-034-coupon-stacking.sh) |
| 035 | Inventory Race Condition | [`apex-035-inventory-race.sh`](examples/argus/apex-035-inventory-race.sh) |
| 036 | MFA Bypass via Response Manipulation | [`apex-036-mfa-temp-token-is-valid.sh`](examples/argus/apex-036-mfa-temp-token-is-valid.sh) |
| 037 | Predictable Token Generation (Weak PRNG) | [`apex-037-predictable-reset-token.sh`](examples/argus/apex-037-predictable-reset-token.sh) |
| 039 | CRLF Injection for Response Splitting | [`apex-039-crlf-response-splitting.sh`](examples/argus/apex-039-crlf-response-splitting.sh) |
| 040 | The Gauntlet | [`apex-040-the-gauntlet-chain.sh`](examples/argus/apex-040-the-gauntlet-chain.sh) |
| 042 | CI/CD Pipeline Poisoning | [`apex-042-cicd-pipeline-poisoning.sh`](examples/argus/apex-042-cicd-pipeline-poisoning.sh) |
| 044 | TradeFi Arbitrage Exploit | [`apex-044-tradefi-settlement-chain.sh`](examples/argus/apex-044-tradefi-settlement-chain.sh) |
| 045 | IoT Command Center Breach | [`apex-045-iot-firmware-command-injection.sh`](examples/argus/apex-045-iot-firmware-command-injection.sh) |
| 046 | FederAuth SAML Bypass | [`apex-046-ssti-in-the-sso-admin-portal.sh`](examples/argus/apex-046-ssti-in-the-sso-admin-portal.sh) |
| 047 | Service Mesh Sidecar Hijack | [`apex-047-service-mesh-ssrf.sh`](examples/argus/apex-047-service-mesh-ssrf.sh) |
| 048 | LegacyBridge Migration Exploit | [`apex-048-legacy-object-injection.sh`](examples/argus/apex-048-legacy-object-injection.sh) |
| 049 | WAF Gauntlet | [`apex-049-waf-sql-filter-evasion.sh`](examples/argus/apex-049-waf-sql-filter-evasion.sh) |
| 050 | WAF Fortress | [`apex-050-waf-xss-filter-bypass.sh`](examples/argus/apex-050-waf-xss-filter-bypass.sh) |
| 051 | GhostNet Recon | [`apex-051-ghostnet-jwt-to-vault.sh`](examples/argus/apex-051-ghostnet-jwt-to-vault.sh) |
| 052 | PluginVault Language Sandbox Escape | [`apex-052-plugin-sandbox-escape.sh`](examples/argus/apex-052-plugin-sandbox-escape.sh) |
| 053 | StreamJack Real-Time Exploitation | [`apex-053-pickle-through-the-queue.sh`](examples/argus/apex-053-pickle-through-the-queue.sh) |
| 054 | MediaPipeline RCE Chain | [`apex-054-media-pipeline-chain.sh`](examples/argus/apex-054-media-pipeline-chain.sh) |
| 055 | CloudBreak K8s Compromise | [`apex-055-cloudbreak-k8s-chain.sh`](examples/argus/apex-055-cloudbreak-k8s-chain.sh) |
| 057 | TenantEscape Isolation Failure | [`apex-057-tenant-escape-via-shared-cache.sh`](examples/argus/apex-057-tenant-escape-via-shared-cache.sh) |
| 058 | DefenseMatrix Evasion | [`apex-058-waf-pattern-gap.sh`](examples/argus/apex-058-waf-pattern-gap.sh) |
| 059 | DocuLeaks Document Processing Chain | [`apex-059-pdf-html-injection-ssrf.sh`](examples/argus/apex-059-pdf-html-injection-ssrf.sh) |
| 060 | The Labyrinth | [`apex-060-the-labyrinth-chain.sh`](examples/argus/apex-060-the-labyrinth-chain.sh) |
