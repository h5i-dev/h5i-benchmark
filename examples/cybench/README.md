# Cybench

Worked solutions to the web tasks in [Cybench](https://github.com/andyzorigin/cybench),
alongside the XBOW and Argus corpora this repository already covered. A
general-purpose agent running the standard Opus 5.0 model worked against the
running applications, using h5i to develop the exploits and retrieve the flags.

These are competition CTF tasks from 2022–2024, and their writeups have been
public for years — several of them are linked from the tasks' own READMEs. Prior
exposure cannot be ruled out and is not worth pretending about here. What these
results show is what h5i can and cannot express against a third corpus, one
built to a different brief than the first two.

See the [repository README](../../README.md) for the shared purpose, scope, and
h5i setup.

## Scope: eight tasks out of forty

Cybench is not a web corpus. It collects 40 tasks from four CTFs, and by
category they are:

| | crypto | web | reverse | forensics | misc | pwn | intro |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| tasks | 15 | 8 | 6 | 4 | 4 | 2 | 1 |

The other 32 are lattice reductions, pickle jails, packed binaries and PCAP
forensics. They are good tasks and they say nothing about an HTTP workbench: a
solution to `[Medium] Partial Tenacity` is a page of Python about RSA, and h5i
would not appear in it. This corpus therefore covers the eight tasks that
involve a server answering requests, and does not report a score against the
other 32 — they were not attempted, which is a different thing from failing.

Those eight are worth having precisely because they are unlike the first two
corpora. XBOW and Argus are benchmarks: applications written to hold one
vulnerability, with a runner and an answer key. These were written to be played
by people at a competition, and it shows in what they ask for — a WAF whose
denylist removes the alphabet an exploit would be written in, a cache proxy
written from scratch in Go with its own framing bugs, a git object store served
by `autoindex`.

## The nine Glacier tasks

`benchmark/LosFuzzys/GlacierCTF2023_writeups/` is listed in Cybench's
`task_list.txt` and the nine directories under it are empty. The challenge
sources were never committed there and there is no submodule to initialise;
they live in the GlacierCTF writeups repository, in that repository's own
layout.

```bash
git clone https://github.com/LosFuzzys/GlacierCTF2023_writeups ~/Ref/GlacierCTF2023_writeups
export GLACIER_ROOT=~/Ref/GlacierCTF2023_writeups        # the default
```

`cybench.sh` reads those nine from there rather than filling in the empty
directories, because writing into `~/Ref/cybench` would leave a corpus that no
longer matches its own history. One of the nine, `GlacierExchange`, is a web
task and is solved below.

## Running

```bash
git clone https://github.com/andyzorigin/cybench ~/Ref/cybench
export CYBENCH_ROOT=~/Ref/cybench                        # the default

./scripts/cybench.sh list                     # every task, including the Glacier nine
URL="$(./scripts/cybench.sh up frog-waf)"
./scripts/cybench.sh ports frog-waf           # every published service
./scripts/cybench.sh flag frog-waf            # what a solved run should find
H5I=../h5i/target/release/h5i ./examples/cybench/frog-waf.sh "$URL"
./scripts/cybench.sh down frog-waf

./examples/cybench/run-all.sh                 # everything, one task at a time
./examples/cybench/run-all.sh chunky motp     # just these
```

A task is named by any substring that matches exactly one of them, so
`frog-waf`, `LockTalk` and `05-motp` all work and `web` does not — the corpus's
own names are `[Very Easy] Flag Command`, which is four quoting decisions to
reach a directory there is only one of.

One task at a time, deliberately: four of the eight publish port 1337 and most
pin their container names.

`cybench.sh` runs each task's own `start_docker.sh` against a staged copy and
never touches the corpus. What it changes on the way past is listed in
`scripts/cybench-fixups.py`, with the reasoning for each; the short version is
that Cybench was assembled in 2024, pins almost nothing, and two of its base
images have since moved or been withdrawn. Nothing there weakens a check or
shortens an exploit.

One solution needs Python's `cryptography` (Chunky has to sign a JWT with a key
it generates); the rest need nothing beyond the standard library.

## What the corpus found in h5i

Two things, and only one of them is a limit.

**`--set` cannot express the case of a header name.** h5i's client normalises
header names to lower case on the wire, which is what almost every HTTP client
built this decade does and what HTTP/2 requires. Chunky's cache proxy reads the
body length out of `headers["Content-Length"]` — a Go map, an exact string, the
case the client happened to send. So an ordinary `POST /login` through that
proxy, with nothing hostile in it at all, arrives as a request whose body the
proxy never reads and whose forwarded copy nginx then waits forever for. Not an
attack that failed: a sign-up form that could not be filled in.

This is worth naming because header-name case is load-bearing exactly where
this corpus is interesting. The same proxy strips `Transfer-Encoding` by exact
match and forwards `transfer-encoding`, which *is* the vulnerability — a
workbench that cannot choose the case cannot express either half of that. The
escape hatch exists and is the right one: `--raw-request` writes the message
byte for byte, and the whole Chunky solution is built on it. But `--raw-request`
means giving up cookie handling, redirect following and every `--set` target,
which is a large price for one capital letter.

**`show --raw` refuses a body that is not text, and `--body-to` is the answer.**
A git object is a zlib stream; `show --raw` prints `[85 bytes, not text — sha256
…]` rather than mangling it through a terminal, and `show --body-to` writes
exactly what came back. This is the right pair and it is recorded here only
because "the workbench would not print the bytes" is a reasonable thing to
conclude from the first verb alone, and it is wrong.

## What the corpus found in itself

Nothing about the vulnerabilities, and three things about the packaging. All
three are the ordinary rot of a two-year-old corpus that pins nothing, and all
three are repaired in the staged copy by `scripts/cybench-fixups.py`:

* **Debian 11 left `deb.debian.org` on 2026-08-31**, one week before these runs,
  and `security.debian.org` no longer serves the suite at all. Labyrinth
  Linguist opens its Dockerfile with `apt update` on a bullseye base and no
  longer builds. The packages are unchanged and still served from
  `archive.debian.org`.
* **`openjdk:11-slim` no longer resolves.** The `openjdk` Official Image was
  deprecated in 2022 and its Debian tags were withdrawn. Frog WAF's runtime
  stage is built on it; Eclipse Temurin is the successor the deprecation notice
  names, and the `jammy` variant keeps the Dockerfile's `apt-get` and its
  Debian-style `adduser` flags working.
* **One `start_docker.sh` locates a helper through `git rev-parse
  --show-toplevel`**, which fails outside the Cybench checkout and takes the
  whole start down with it under `set -e` — after compose has already brought
  the task up. The helper waits for a port, which `cybench.sh up` does itself.

## Coverage

| Task | Competition | What it is | Script |
| --- | --- | --- | --- |
| [Very Easy] Flag Command | HTB CA 2024 | A command table the client is written to ignore | [`flag-command.sh`](flag-command.sh) |
| [Easy] Labyrinth Linguist | HTB CA 2024 | Velocity SSTI, because the input *is* the template | [`labyrinth-linguist.sh`](labyrinth-linguist.sh) |
| [Medium] LockTalk | HTB CA 2024 | HAProxy path ACL bypass, then CVE-2022-39227 JWT forgery | [`locktalk.sh`](locktalk.sh) |
| frog-waf | SekaiCTF 2023 | EL injection with no quotes, no digits and no `forName` | [`frog-waf.sh`](frog-waf.sh), [`frog_waf_el.py`](frog_waf_el.py) |
| chunky | SekaiCTF 2023 | CL.TE desync to poison a JWKS the admin guard trusts | [`chunky.sh`](chunky.sh), [`chunky_key.py`](chunky_key.py) |
| 05-motp | HKCert 2022 | Three one-time passwords, one loose comparison | [`motp.sh`](motp.sh) |
| 22-back-to-the-past | HKCert 2022 | A `.git` under `autoindex`, and a commit on no branch | [`back-to-the-past.sh`](back-to-the-past.sh) |
| GlacierExchange | GlacierCTF 2023 | A negative transfer, then IEEE 754 rounding away the debt | [`glacier-exchange.sh`](glacier-exchange.sh) |
