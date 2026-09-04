#!/usr/bin/env bash
# Build, start and stop one Argus (APEX) validation benchmark, and print its URL.
#
# A thin wrapper over the corpus's own `docker-compose.yml`, so what runs is
# what the benchmark intends. It exists for two reasons the corpus leaves to
# its runner: every compose file demands a `FLAG` that nothing supplies, and
# `make run` prints no address, while the port a benchmark publishes differs
# from benchmark to benchmark.
#
#   apex.sh build APEX-001-25
#   URL="$(apex.sh up APEX-001-25)"   # the first published service
#   apex.sh ports APEX-001-25         # every published service, one per line
#   apex.sh url  APEX-001-25 gateway  # one service by name
#   apex.sh down APEX-001-25
#   apex.sh flag APEX-001-25          # what a solved run should find
#
# Benchmarks run one at a time. Most of them pin their host port, several pin
# their container names, and this machine has neither the memory nor the cores
# to build two multi-service stacks at once.
set -uo pipefail

APEX_ROOT="${APEX_ROOT:-$HOME/Ref/argus-validation-benchmarks}"
ACTION="${1:?build|up|down|ports|url|flag|info}"
NAME="${2:?APEX-nnn-25}"
DIR="$APEX_ROOT/benchmarks/$NAME/src"
[ -d "$DIR" ] || { echo "no benchmark $NAME under $APEX_ROOT" >&2; exit 2; }
PROJECT="$(echo "$NAME" | tr '[:upper:]' '[:lower:]')"

# The corpus randomizes the flag per run: every compose file reads it from the
# environment and refuses to start without one, and the answer keys say
# "FLAG{<per-run>}". Deriving it from the benchmark's name rather than from
# /dev/urandom keeps a run reproducible and lets `flag` answer without state,
# while still being a value no application can have been written around.
#
# The format is the corpus's own, `FLAG{descriptive_snake_case}`, in case
# anything downstream parses it.
flag() {
    local digest
    digest="$(printf '%s' "$NAME" | sha256sum | cut -c1-16)"
    printf 'FLAG{%s_%s}\n' "$(echo "$NAME" | tr 'A-Z-' 'a-z_')" "$digest"
}

# Where the build actually happens: a copy of the benchmark's `src`, never the
# corpus itself.
#
# Two reasons, and only the first is about portability. This machine is arm64
# and one image the corpus names was never published for it, so a line has to
# change; changing it in `~/Ref` would edit the thing being measured, and a
# result from an edited benchmark is worth less than no result. And a staged
# copy gives every later fix of that kind one place to live, listed below,
# instead of a note in a README saying what to patch by hand.
#
# Every substitution, and why:
#
#   * `eclipse-temurin:17-jre-alpine` publishes no arm64 image at all, and the
#     Dockerfile that uses it creates its user with BusyBox's `adduser` flags —
#     so the substitute has to be another Alpine image, not another JRE.
#     Amazon Corretto 17 on Alpine is both, and runs the same jar.
STAGE="${APEX_STAGE:-${TMPDIR:-/tmp}/apex-stage}/$NAME"

stage() {
    rm -rf "$STAGE"
    mkdir -p "$(dirname "$STAGE")"
    cp -r "$DIR" "$STAGE"
    find "$STAGE" -name Dockerfile -print0 |
        xargs -0 -r sed -i 's|eclipse-temurin:17-jre-alpine|amazoncorretto:17-alpine|'
}

compose() {
    [ -d "$STAGE" ] || stage
    FLAG="$(flag)" docker compose --project-directory "$STAGE" \
        -f "$STAGE/docker-compose.yml" -p "$PROJECT" "$@"
}

# Every published port, as `service container_port http://127.0.0.1:host_port`,
# lowest host port first.
#
# Read back from the daemon rather than from the compose file, because a
# benchmark that writes `${PORT:-3041}` publishes whatever the environment said
# and a benchmark that writes no host port at all publishes whatever was free.
#
# Sorted because `up` prints the first row and a caller is entitled to the same
# answer twice. The daemon lists containers in whatever order it started them,
# which is a race between healthchecks; the port a benchmark documents as its
# own is reliably the lowest one it publishes.
ports() {
    compose ps --format json 2>/dev/null | python3 -c '
import json, sys
seen = set()
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    row = json.loads(line)
    rows = row if isinstance(row, list) else [row]
    for one in rows:
        for pub in one.get("Publishers") or []:
            if not pub.get("PublishedPort"):
                continue
            # A published port appears once per address family; the URL is the
            # same either way, and a caller reading `head -1` wants one line.
            row = (one["Service"], pub["TargetPort"], pub["PublishedPort"])
            if row in seen:
                continue
            seen.add(row)
for service, target, published in sorted(seen, key=lambda row: row[2]):
    print(service, target, "http://127.0.0.1:%d" % published)
'
}

# Up to `seconds` waiting for every service that declares a healthcheck to pass
# it. Services without one are up as soon as compose says they are running,
# which is all the daemon knows about them.
wait_healthy() {
    local seconds="${1:-180}" waited=0 state
    while [ "$waited" -lt "$seconds" ]; do
        state="$(compose ps --format json 2>/dev/null | python3 -c '
import json, sys
bad = []
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    row = json.loads(line)
    for one in (row if isinstance(row, list) else [row]):
        health, status = one.get("Health") or "", one.get("State") or ""
        if health in ("starting", "unhealthy"):
            bad.append(one["Service"] + ":" + health)
        elif status not in ("running", "exited"):
            bad.append(one["Service"] + ":" + status)
print(" ".join(bad))
')"
        [ -z "$state" ] && return 0
        sleep 3
        waited=$((waited + 3))
    done
    echo "apex: still not healthy after ${seconds}s: $state" >&2
    return 1
}

case "$ACTION" in
    build)
        stage
        compose build >&2 || exit 1
        ;;
    up)
        stage
        compose up -d --build >&2 || exit 1
        wait_healthy "${APEX_WAIT:-180}" || true
        # A healthcheck is the daemon's opinion and half of these services
        # declare none, so `up` also waits for the ports to answer. Answering at
        # all is the bar: a 404 is a running application, and a connection
        # refused is a script that will report a benchmark resisting when what
        # actually happened is that it started too early.
        #
        # Every published port, not just the first. Several of these benchmarks
        # are an application plus an admin bot plus a collector, and the exploit
        # is not a shorter wait for using the bot before the application.
        for answer in $(ports | awk '{print $3}'); do
            waited=0
            while [ "$waited" -lt "${APEX_ANSWER_WAIT:-90}" ]; do
                curl -s -o /dev/null --max-time 3 "$answer" && break
                sleep 2
                waited=$((waited + 2))
            done
        done
        # And then a moment more. Several of these applications open their
        # database connection on the first request rather than at startup, so
        # the port answering is not the same as the application working: what
        # comes back is a 200 carrying a stack trace. There is no signal to
        # wait for in that case, only time.
        sleep "${APEX_SETTLE:-5}"
        primary="$(ports | head -1 | awk '{print $3}')"
        # stdout is the URL a script is given, so the first published service
        # goes there alone and everything else has already gone to stderr.
        printf '%s\n' "$primary"
        ;;
    down)
        compose down -v --remove-orphans >&2
        ;;
    ports)
        ports
        ;;
    url)
        SERVICE="${3:?usage: apex.sh url NAME SERVICE [CONTAINER_PORT]}"
        ports | awk -v s="$SERVICE" -v p="${4:-}" \
            '$1 == s && (p == "" || $2 == p) { print $3; exit }'
        ;;
    flag)
        flag
        ;;
    info)
        python3 -c '
import json, sys
b = json.load(open(sys.argv[1]))
print(b.get("name"))
print(b.get("description", ""))
print("tags:", ",".join(b.get("tags", [])))
' "$DIR/benchmark.json"
        ;;
    *)
        echo "apex: unknown action $ACTION" >&2
        exit 2
        ;;
esac
