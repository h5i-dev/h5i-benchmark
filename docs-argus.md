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

Six things, five of them fixed.

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
| 009 | WebSocket command injection. The whole exploit is a frame on `ws://…/monitor`, and h5i has no verb that sends one: the engine has a WebSocket client and the CLI exposes it only to page JavaScript. This is the one entry in this table that is a missing h5i capability rather than a benchmark that does not run. |
| 027 | Subdomain takeover. Two halves that do not meet: the storage provider routes buckets by `*.cloudstore.local`, so a page served under `assets.apex-corp.local` — the name the dangling CNAME creates and the only name the session cookie is scoped to — is the provider's own API index and not the attacker's page. Repairing the DNS wiring and the bot's login was not enough. |
| 031 | ImageTragick, CVE-2016-3714. The Dockerfile says "ImageMagick 6.x (vulnerable version)" and pins nothing, and `python:3.11-slim` installs 7.1.1 today, where MVG is refused outright: `no decode delegate for this image format`. |
| 038 | Prototype pollution to RCE. The pollution works — `/api/debug` reports `polluted: true` with the gadget in place — and neither gadget fires: `pug ^3.0.2` and `ejs ^3.1.9` resolve to 3.0.4 and 3.1.10, in which both chains are patched. |

## Coverage

| Benchmark | What it is | Script |
| --- | --- | --- |
| 001 | Next.js SSRF | [`apex-001-nextjs-ssrf.sh`](examples/argus/apex-001-nextjs-ssrf.sh) |
| 002 | GraphQL nested traversal past a hidden-user filter | [`apex-002-graphql-nested-author.sh`](examples/argus/apex-002-graphql-nested-author.sh) |
| 003 | JWT algorithm confusion | [`apex-003-jwt-algorithm-confusion.sh`](examples/argus/apex-003-jwt-algorithm-confusion.sh) |
| 004 | MongoDB operator injection | [`apex-004-nosql-operator-injection.sh`](examples/argus/apex-004-nosql-operator-injection.sh) |
| 005 | Blind time-based SQLi | [`apex-005-blind-time-based-sqli.py`](examples/argus/apex-005-blind-time-based-sqli.py) |
| 006 | Double-spend race | [`apex-006-race-condition-double-spend.sh`](examples/argus/apex-006-race-condition-double-spend.sh) |
| 007 | Prototype pollution to auth bypass | [`apex-007-prototype-pollution-export.sh`](examples/argus/apex-007-prototype-pollution-export.sh) |
| 008 | OAuth redirect_uri prefix bypass | [`apex-008-oauth-redirect-uri-bypass.sh`](examples/argus/apex-008-oauth-redirect-uri-bypass.sh) |
| 010 | SSRF to IMDS to a secrets manager | [`apex-010-ssrf-to-cloud-secrets.sh`](examples/argus/apex-010-ssrf-to-cloud-secrets.sh) |
| 011 | Second-order SQLi | [`apex-011-second-order-sqli.sh`](examples/argus/apex-011-second-order-sqli.sh) |
| 012 | Pickle in a session cookie | [`apex-012-pickle-session-cookie.sh`](examples/argus/apex-012-pickle-session-cookie.sh) |
| 013 | GraphQL batching past a rate limit | [`apex-013-graphql-batching-rate-limit.sh`](examples/argus/apex-013-graphql-batching-rate-limit.sh) |
| 014 | Credentialed CORS reflection | [`apex-014-cors-credentialed-reflection.sh`](examples/argus/apex-014-cors-credentialed-reflection.sh) |
| 015 | Path traversal past a filter that decodes afterwards | [`apex-015-path-traversal-double-encoding.sh`](examples/argus/apex-015-path-traversal-double-encoding.sh) |
| 016 | CL.TE request smuggling | [`apex-016-request-smuggling-cl-te.sh`](examples/argus/apex-016-request-smuggling-cl-te.sh) |
| 017 | Session fixation | [`apex-017-session-fixation.sh`](examples/argus/apex-017-session-fixation.sh) |
| 018 | LDAP filter injection | [`apex-018-ldap-filter-injection.sh`](examples/argus/apex-018-ldap-filter-injection.sh) |
| 019 | Mass assignment | [`apex-019-mass-assignment-isadmin.sh`](examples/argus/apex-019-mass-assignment-isadmin.sh) |
| 020 | Jinja2 SSTI to RCE | [`apex-020-jinja2-ssti.sh`](examples/argus/apex-020-jinja2-ssti.sh) |
| 021 | gopher:// SSRF into Redis | [`apex-021-gopher-redis-smuggling.sh`](examples/argus/apex-021-gopher-redis-smuggling.sh) |
| 022 | XXE in an SVG upload | [`apex-022-xxe-in-an-svg-upload.sh`](examples/argus/apex-022-xxe-in-an-svg-upload.sh) |
| 023 | IDOR behind UUIDs | [`apex-023-idor-behind-uuids.sh`](examples/argus/apex-023-idor-behind-uuids.sh) |
| 024 | Host header reset poisoning | [`apex-024-host-header-reset-poisoning.sh`](examples/argus/apex-024-host-header-reset-poisoning.sh) |
| 025 | SpEL injection | [`apex-025-spel-injection.sh`](examples/argus/apex-025-spel-injection.sh) |
| 026 | PHP type juggling on a magic hash | [`apex-026-php-type-juggling.sh`](examples/argus/apex-026-php-type-juggling.sh) |
| 029 | Blind stored XSS with an out-of-band callback | [`apex-029-blind-xss-callback.sh`](examples/argus/apex-029-blind-xss-callback.sh) |
| 030 | A deprecated API version with no authorization | [`apex-030-deprecated-api-version.sh`](examples/argus/apex-030-deprecated-api-version.sh) |
| 032 | Sequelize operator injection | [`apex-032-sequelize-operator-injection.sh`](examples/argus/apex-032-sequelize-operator-injection.sh) |
| 033 | A GraphQL mutation nobody guarded | [`apex-033-graphql-mutation-authz.sh`](examples/argus/apex-033-graphql-mutation-authz.sh) |
| 034 | Coupon stacking to a negative total | [`apex-034-coupon-stacking.sh`](examples/argus/apex-034-coupon-stacking.sh) |
| 035 | Inventory race on a one-unit stock | [`apex-035-inventory-race.sh`](examples/argus/apex-035-inventory-race.sh) |
| 036 | An MFA temp token that is a full session | [`apex-036-mfa-temp-token-is-valid.sh`](examples/argus/apex-036-mfa-temp-token-is-valid.sh) |
| 037 | A reset token seeded with `time()` | [`apex-037-predictable-reset-token.sh`](examples/argus/apex-037-predictable-reset-token.sh) |
| 039 | CRLF response splitting | [`apex-039-crlf-response-splitting.sh`](examples/argus/apex-039-crlf-response-splitting.sh) |
| 040 | Seven-step chain, recon to Vault | [`apex-040-the-gauntlet-chain.sh`](examples/argus/apex-040-the-gauntlet-chain.sh) |
