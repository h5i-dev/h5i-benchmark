#!/usr/bin/env bash
# Build, start and stop one XBOW validation benchmark, and print its URL.
#
# A thin wrapper over the benchmarks' own `make`, so what runs is what the
# corpus intends. It exists because `make run` prints no address: the compose
# files publish container ports on whatever the host has free, and every script
# that drives one needs to find out which.
#
#   xben.sh build XBEN-006-24
#   URL="$(xben.sh up XBEN-006-24)"
#   xben.sh down XBEN-006-24
#   xben.sh flag XBEN-006-24      # what a solved run should find
set -uo pipefail

XBEN_ROOT="${XBEN_ROOT:-$HOME/Ref/validation-benchmarks}"
ACTION="${1:?build|up|down|flag|info}"
NAME="${2:?XBEN-nnn-yy}"
DIR="$XBEN_ROOT/benchmarks/$NAME"
[ -d "$DIR" ] || { echo "no benchmark $NAME under $XBEN_ROOT" >&2; exit 2; }

# The flag is `FLAG{sha256(NAME)}`, exactly as common.mk computes it, so a run
# can be scored without anybody being told the answer up front.
flag() { printf 'FLAG{%s}\n' "$(printf '%s' "${NAME^^}" | sha256sum | cut -d' ' -f1)"; }

# The corpus was written in 2024 for an x86 machine, and several things now stop
# it running on a current Docker on arm64. None is worth editing the corpus for,
# so the compose file and the Dockerfiles it points at are rewritten on the way
# past. Every substitution, and why:
#
#   * `mysql:5.7` and `mongo` were never published for arm64, and emulating
#     them is worse than slow: 5.7's first-run initialisation sometimes never
#     finishes. MariaDB 10.11 speaks the same protocol and reads the same
#     `MYSQL_*` variables. `mysql:8` is left alone — it has an arm64 image.
#   * `php:8.3.6-apache` publishes an arm64 image that reports arm64 and then
#     fails every exec with "exec format error"; `node:14-alpine` still runs but
#     the dependencies its `package.json` resolves to today do not. Both get the
#     nearest working tag.
#   * Debian buster left the mirrors, so `apt-get update` 404s in every image
#     built on it. Its packages are still at archive.debian.org, behind a
#     Release signature that expired with the release.
#   * `lxml` publishes no arm64 wheel for these pins, so pip builds it and needs
#     C headers that a `-slim` image does not carry.
#   * Composer now refuses to resolve a dependency with a published advisory,
#     and the deliberately-old dependency *is* the benchmark.
#   * `expose: [3306:3306]` is a mapping in a field that takes a bare port.
#     Older compose tolerated it; current Docker refuses the whole project.
#   * A pinned host port means two benchmarks cannot run at once, which is the
#     normal state of an afternoon's work here.
#
# And two that are not portability at all, but the difference between a
# benchmark that runs and one that can be solved: `args: [FLAG]` resolves to
# empty and beats the `--build-arg` on the command line, and dropping a
# database's build step drops the `sed` that put the flag in its seed data.
#
# A *rewritten* file rather than an override, because compose merges list
# fields by appending: an override cannot remove the entry that breaks it.
COMPOSE="$DIR/docker-compose.yml"
FIXED="/tmp/xben-${NAME}-compose.yml"
python3 - "$COMPOSE" "$FIXED" "$DIR" "$(flag)" <<'PY'
import sys, yaml, os, re

# Point apt at the archive, and stop it rejecting a Release file whose
# signature expired when the release did.
#
# Guarded on the sources actually naming buster, because this line is inserted
# into every image that runs apt and the rewrite would break a current one:
# bookworm is on deb.debian.org and is not on archive.debian.org.
ARCHIVE_SOURCES = (
    "RUN if grep -qs buster /etc/apt/sources.list; then sed -i"
    " -e 's|deb.debian.org/debian|archive.debian.org/debian|g'"
    " -e 's|security.debian.org/debian-security|archive.debian.org/debian-security|g'"
    " -e '/buster-updates/d' /etc/apt/sources.list"
    " && echo 'Acquire::Check-Valid-Until \"false\";'"
    " > /etc/apt/apt.conf.d/99-archived-release; fi"
)

HEADERS_FOR_LXML = (
    "RUN apt-get update && apt-get install -y --no-install-recommends"
    " gcc libxml2-dev libxslt1-dev zlib1g-dev && rm -rf /var/lib/apt/lists/*"
)
source, target, base, flag = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
spec = yaml.safe_load(open(source)) or {}
for name, body in (spec.get("services") or {}).items():
    body = body or {}
    image = str(body.get("image", ""))
    build = body.get("build")
    # A `db` service built `FROM mysql:5.7.x` is the same arm64 problem one
    # level down, and emulating that image is worse than useless here: mysql
    # 5.7's entrypoint hangs forever under qemu on this host, and some of these
    # images carry an amd64 Go binary that segfaults outright. MariaDB 10.11
    # speaks the same protocol, reads the same `MYSQL_*` variables and the same
    # `docker-entrypoint-initdb.d`, and has an arm64 image.
    context = build if isinstance(build, str) else (build or {}).get("context", "")
    dockerfile = os.path.join(base, str(context), "Dockerfile") if context else ""
    inherits_mysql = False
    if dockerfile and os.path.exists(dockerfile):
        with open(dockerfile) as handle:
            head = handle.read(400)
        # Only 5.x. `mysql:8` publishes a working arm64 image, so substituting
        # it would swap the database out for no reason and lose the build step
        # that seeds the flag; 5.7 was never published for arm64 and hangs
        # forever under emulation on this host.
        inherits_mysql = "FROM mysql:5" in head
        if inherits_mysql:
            body.pop("build", None)
            body["image"] = "mariadb:10.11"
            env = body.get("environment") or []
            # Carry the credentials the Dockerfile set, which the app expects.
            for line in head.splitlines():
                if line.startswith("ENV MYSQL_"):
                    env.append(line[len("ENV "):].strip())
            body["environment"] = env
            # And carry whatever it copied into the init directory. That is
            # where these images create the application's user and seed its
            # tables; dropping the build without it produces a database that
            # starts perfectly and refuses every login, which reads like an
            # application bug rather than a substitution that lost a file.
            mounts = body.get("volumes") or []
            # Not `source`: that is the compose file this script is reading.
            context_dir = os.path.join(base, str(context))
            for line in head.splitlines():
                line = line.strip()
                if line.startswith(("ADD ", "COPY ")) and "docker-entrypoint-initdb.d" in line:
                    parts = line.split()
                    for item in parts[1:-1]:
                        local = os.path.join(context_dir, item)
                        if not os.path.exists(local):
                            continue
                        # The dropped build was also where the flag was written
                        # into this file, by a `sed` a line or two further down.
                        # Mounting the original mounts the placeholder, and the
                        # benchmark then seeds a database whose secret is the
                        # literal text `${FLAG}`.
                        seeded = f"{target}.{name}.{os.path.basename(item)}"
                        with open(local) as handle:
                            body_text = handle.read()
                        # The dropped build's own `sed` says what the
                        # placeholder is called; the corpus uses at least four
                        # spellings and guessing a fixed list seeds one database
                        # with the literal placeholder and no way to tell.
                        placeholders = set(["${FLAG}", "@FLAG@", "$FLAG"])
                        placeholders.update(
                            re.findall(r"sed\s+-i\s+[\"']?s/([^/]+)/\$\{?FLAG\}?/", head)
                        )
                        for placeholder in placeholders:
                            body_text = body_text.replace(placeholder, flag)
                        # A dump taken from MySQL 8 names a collation MariaDB
                        # does not have, and the seed dies on line 4 with
                        # "Unknown collation" — which reads like a broken
                        # benchmark rather than a substituted database.
                        body_text = body_text.replace(
                            "utf8mb4_0900_ai_ci", "utf8mb4_general_ci"
                        )
                        with open(seeded, "w") as out:
                            out.write(body_text)
                        mounts.append(
                            f"{seeded}:/docker-entrypoint-initdb.d/{os.path.basename(item)}:ro")
            if mounts:
                body["volumes"] = mounts
    if image.startswith("mysql:5"):
        # Same substitution for a service that names the image directly. Under
        # emulation this one is not merely slow: mysql 5.7's first-run
        # initialisation sometimes never completes at all, and a benchmark that
        # hangs looks exactly like a benchmark that is broken.
        body["image"] = "mariadb:10.11"
        body.pop("platform", None)
    elif image.startswith("mongo"):
        body["platform"] = "linux/amd64"
    if body.get("expose"):
        body["expose"] = [str(e).split(":")[-1] for e in body["expose"]]
    if body.get("ports"):
        # Only the container port. Several of these files pin a host port, and
        # two benchmarks that pin the same one cannot run at once — which is the
        # normal state of an afternoon's work here. The runner reads back
        # whatever docker chose, so nothing needs the number to be fixed.
        body["ports"] = [str(p).split(":")[-1] for p in body["ports"]]
    # Debian buster left the mirrors. Ten of these images are `FROM
    # python:2.7.18-slim`, which is buster, and their first `apt-get update`
    # now 404s on deb.debian.org, so the build dies before the application is
    # even copied in. The packages are still published, at archive.debian.org,
    # with expired Release signatures that apt refuses by date alone.
    #
    # Rewritten through `dockerfile_inline` rather than by editing the corpus:
    # the build context stays the benchmark's own directory, every other line of
    # its Dockerfile is untouched, and nothing is written back into the checkout.
    #
    # Composer is the second case. These images install a pinned, deliberately
    # old library — the vulnerability *is* the benchmark — and a current
    # composer refuses to resolve a version with a published advisory. The
    # refusal is right for real projects and wrong here, so the check is turned
    # off for the build rather than the pin being moved.
    if dockerfile and os.path.exists(dockerfile):
        original = open(dockerfile).read()
        lines = original.splitlines()
        patched_lines = False
        # Two kinds of base image that no longer work, for two reasons:
        #
        #   * `php:8.3.6-apache` publishes an arm64 image that reports arm64 and
        #     then fails every exec with "exec format error". The tags either
        #     side of it are fine.
        #   * `node:14-alpine` still runs, and the dependencies these
        #     `package.json` files resolve to today do not: an unpinned
        #     transitive dependency now uses `||=`, which Node 14 cannot parse,
        #     so the service dies at require time.
        #
        # A patch bump and a runtime bump change nothing either benchmark is
        # about, and the alternative is not running them at all.
        for broken, working in {
            "php:8.3.6-apache": "php:8.3.7-apache",
            "node:14-alpine": "node:20-alpine",
        }.items():
            if broken in original:
                lines = [line.replace(broken, working) for line in lines]
                patched_lines = True
        if "apt-get" in original or "apt " in original:
            for index, line in enumerate(lines):
                if line.strip().upper().startswith("FROM "):
                    lines.insert(index + 1, ARCHIVE_SOURCES)
                    patched_lines = True
                    break
        # `lxml` publishes no arm64 wheel for these pins, so pip falls back to
        # building it and stops at "Please make sure the libxml2 and libxslt
        # development packages are installed". Named rather than general: this
        # is the one package in the corpus that needs C headers, and adding a
        # toolchain to every python image to be safe is a worse trade.
        # Packages that reach lxml, directly or through a dependency. A named
        # set rather than a rule: it grows when a build says so, which is
        # better than adding a C toolchain to every python image on the chance
        # that one of them needs it.
        WANTS_LIBXML = ("lxml", "zeep")
        needs_headers = any(package in original for package in WANTS_LIBXML)
        if context:
            # Not `name`: that is the service being rewritten.
            for listed in ("requirements.txt", "requeriments.txt"):
                listing = os.path.join(base, str(context), listed)
                if os.path.exists(listing):
                    listed_text = open(listing).read()
                    if any(package in listed_text for package in WANTS_LIBXML):
                        needs_headers = True
        if needs_headers and "pip install" in original:
            for index, line in enumerate(lines):
                if "pip install" in line:
                    lines.insert(index, HEADERS_FOR_LXML)
                    patched_lines = True
                    break
        if "composer install" in original:
            lines = [
                line.replace(
                    "composer install",
                    "composer config --global policy.advisories.block false"
                    " && composer install",
                )
                if "composer install" in line and "policy.advisories" not in line
                else line
                for line in lines
            ]
            patched_lines = True
        if patched_lines:
            build_spec = body.get("build")
            if isinstance(build_spec, str):
                build_spec = {"context": build_spec}
                body["build"] = build_spec
            if isinstance(build_spec, dict):
                # Written beside the rewritten compose file and named by
                # absolute path, not folded in as `dockerfile_inline`: this
                # docker drops every build argument when the Dockerfile is
                # inline, which delivers an empty FLAG to the image and a
                # benchmark that runs and cannot be solved.
                patched = f"{target}.{name}.Dockerfile"
                with open(patched, "w") as out:
                    out.write("\n".join(lines) + "\n")
                build_spec["dockerfile"] = patched

    # `args: [FLAG]` is compose's "take this build argument from the
    # environment". The environment here does not have it, and an unresolved
    # bare argument beats the `--build-arg` on the command line rather than
    # deferring to it, so the flag reaches the image empty: these Dockerfiles
    # `sed` it into a file, and an empty value deletes the placeholder. The
    # benchmark then runs perfectly and cannot be solved.
    #
    # Written out as `FLAG: <value>` here so nothing is left to resolve.
    build = body.get("build")
    if isinstance(build, dict) and build.get("args") is not None:
        args = build["args"]
        names = args if isinstance(args, list) else list(args)
        resolved = {}
        for entry in names:
            # Not `name`: that is the service being rewritten, and rebinding it
            # here writes the service back under the build argument's name.
            argument = str(entry).split("=", 1)[0]
            resolved[argument] = flag if argument.lower() == "flag" else ""
        build["args"] = resolved

    # Build contexts are relative to the file, which now lives in /tmp.
    build = body.get("build")
    if isinstance(build, str):
        body["build"] = os.path.abspath(os.path.join(base, build))
    elif isinstance(build, dict) and "context" in build:
        build["context"] = os.path.abspath(os.path.join(base, build["context"]))
    spec["services"][name] = body
with open(target, "w") as out:
    yaml.safe_dump(spec, out)
PY
COMPOSE_FILES=(-f "$FIXED")
# One project name whatever file is used, so `up` and `down` agree.
export COMPOSE_PROJECT_NAME="xben-${NAME,,}"

case "$ACTION" in
  build)
    (cd "$DIR" && docker compose "${COMPOSE_FILES[@]}" build \
        --build-arg FLAG="$(flag)" --build-arg flag="$(flag)" >/dev/null 2>&1) ||
        { echo "build failed: $NAME" >&2; exit 1; } ;;
  flag)  flag ;;
  info)  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["name"]); print("  level", d.get("level"), "tags", ",".join(d.get("tags",[])))' "$DIR/benchmark.json" ;;
  down)  (cd "$DIR" && docker compose "${COMPOSE_FILES[@]}" down -v --remove-orphans >/dev/null 2>&1); exit 0 ;;
  up)
    # Build first, always. `up` builds a missing image on its own and does it
    # with no `--build-arg`, which leaves the flag empty: these Dockerfiles
    # `sed` the flag into a file, and an empty argument deletes the placeholder
    # instead of replacing it. The benchmark then runs perfectly and cannot be
    # solved, which is the worst way for this to fail.
    (cd "$DIR" && docker compose "${COMPOSE_FILES[@]}" build \
        --build-arg FLAG="$(flag)" --build-arg flag="$(flag)" >/dev/null 2>&1) ||
        { echo "build failed: $NAME" >&2; exit 1; }
    # And a clean slate. A database volume left behind by an earlier run of the
    # same benchmark is initialised for a different server: mysql refuses to
    # start on a data directory mariadb wrote, and the failure reads like a
    # broken benchmark rather than a leftover.
    (cd "$DIR" && docker compose "${COMPOSE_FILES[@]}" down -v --remove-orphans >/dev/null 2>&1)
    (cd "$DIR" && docker compose "${COMPOSE_FILES[@]}" up -d --wait >/dev/null 2>&1) || {
      # `--wait` fails when a healthcheck never passes. The containers may still
      # be usable, so this reports rather than gives up, and the caller decides.
      echo "warning: $NAME did not report healthy" >&2
    }
    # The published port that answers HTTP.
    #
    # Every published port, not the first one: a benchmark that publishes 22
    # alongside 80 would otherwise be reported as never coming up, because
    # nothing on the SSH port ever answers a GET.
    #
    # Long, because a database initialising its data directory for the first
    # time takes a minute or two and the app waits for it.
    for _ in $(seq 1 180); do
      ports="$(cd "$DIR" && docker compose "${COMPOSE_FILES[@]}" ps --format json 2>/dev/null |
        python3 -c '
import json, sys
seen = []
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        row = json.loads(line)
    except Exception:
        continue
    rows = row if isinstance(row, list) else [row]
    for one in rows:
        for pub in one.get("Publishers") or []:
            port = pub.get("PublishedPort")
            if port and port not in seen:
                seen.append(port)
# The container port says which is the web one; 80 and 8080 first, then the
# rest in the order docker listed them.
print(" ".join(str(p) for p in seen))
')"
      for port in $ports; do
        if [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$port/" 2>/dev/null)" != "000" ]; then
            echo "http://127.0.0.1:$port"
            exit 0
        fi
      done
      sleep 1
    done
    echo "no published port for $NAME" >&2; exit 1 ;;
  *) echo "unknown action $ACTION" >&2; exit 2 ;;
esac
