#!/usr/bin/env bash
# Start and stop one Cybench task, and print its URL.
#
# A thin wrapper over each task's own `start_docker.sh`, so what runs is what
# the task intends. It exists for the three things Cybench leaves to its
# harness: the task directory is a long path with spaces and brackets in it,
# the published port differs from task to task and is written in a compose file
# that is not always at the top of the task, and the answer key lives in two
# different places depending on which competition the task came from.
#
#   cybench.sh list                   # every task this can start, one per line
#   URL="$(cybench.sh up frog-waf)"   # the first published service
#   cybench.sh ports frog-waf         # every published service, one per line
#   cybench.sh url chunky cache       # one service by name
#   cybench.sh flag frog-waf          # what a solved run should find
#   cybench.sh down frog-waf
#
# The task is named by any substring that matches exactly one task, so
# `frog-waf`, `LockTalk` and `05-motp` all work and `web` does not.
#
# Tasks run one at a time. Every web task in the corpus pins its host port and
# most of them pin their container names too, so two at once is a port
# collision rather than a result. Four of them want 1337.
set -uo pipefail

CYBENCH_ROOT="${CYBENCH_ROOT:-$HOME/Ref/cybench}"
# The nine LosFuzzys tasks are listed in Cybench's `task_list.txt` and their
# directories are empty: the challenge sources were never committed there, and
# there is no submodule to initialise either. They live in the GlacierCTF
# writeups repository instead, which has its own layout, so this reaches into a
# separate checkout rather than filling in the empty directories — writing into
# `~/Ref/cybench` would leave a corpus that no longer matches its own history.
#
#   git clone https://github.com/LosFuzzys/GlacierCTF2023_writeups
GLACIER_ROOT="${GLACIER_ROOT:-$HOME/Ref/GlacierCTF2023_writeups}"

# Cybench puts every task on a user-defined bridge called `shared_net` and
# declares it `external`, because its agent runs in a container that joins the
# same network and addresses the task by container name. Nothing here runs in
# a container, so the network matters only in that compose refuses to start
# without it.
NETWORK="shared_net"

ACTION="${1:?list|up|down|ports|url|flag|dir|stage|info}"

# Every task, as a path, newest layout first. Cybench's own `task_list.txt` is
# the authority for what a task is; the Glacier rows in it point at empty
# directories, so those are replaced by the equivalent path in the writeups
# checkout.
tasks() {
    local line rest
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        case "$line" in
            benchmark/LosFuzzys/GlacierCTF2023_writeups/*)
                rest="${line#benchmark/LosFuzzys/GlacierCTF2023_writeups/}"
                [ -d "$GLACIER_ROOT/$rest" ] && printf '%s\n' "$GLACIER_ROOT/$rest"
                ;;
            *)
                [ -d "$CYBENCH_ROOT/$line" ] && printf '%s\n' "$CYBENCH_ROOT/$line"
                ;;
        esac
    done < "$CYBENCH_ROOT/task_list.txt"
}

# The one task whose path contains NAME, or an error naming the alternatives.
# Substring rather than exact, because the corpus's own names are
# `[Very Easy] Flag Command` and typing that at a shell is four quoting
# decisions to reach a directory there is only one of.
resolve() {
    local name="$1" hits
    hits="$(tasks | grep -i -- "$name")"
    case "$(printf '%s' "$hits" | grep -c .)" in
        1) printf '%s\n' "$hits" ;;
        0) echo "cybench: no task matching '$name'" >&2; return 2 ;;
        *) { echo "cybench: '$name' matches more than one task:"
             printf '%s\n' "$hits" | sed 's|^|  |'; } >&2; return 2 ;;
    esac
}

# The compose file the task starts. Cybench tasks keep it at the top of the
# task or one directory down (`dist/`, `env/`), and name it either way round;
# `start_docker.sh` knows which, and this has to know too because `docker
# compose ps` cannot be asked about a project it was not pointed at.
compose_file() {
    local dir="$1" candidate
    for candidate in "$dir/docker-compose.yml" "$dir/compose.yml" \
                     "$dir/dist/docker-compose.yml" "$dir/env/docker-compose.yml" \
                     "$dir/challenge/docker-compose.yml"; do
        [ -f "$candidate" ] && { printf '%s\n' "$candidate"; return 0; }
    done
    candidate="$(find "$dir" -maxdepth 2 -name 'docker-compose.yml' -o -maxdepth 2 -name 'compose.yml' 2>/dev/null | head -1)"
    [ -n "$candidate" ] && { printf '%s\n' "$candidate"; return 0; }
    return 1
}

# Where the build actually happens: a copy of the task, never the corpus.
#
# Cybench was assembled in 2024 and pins almost nothing, so several of these
# tasks no longer build for reasons that have nothing to do with the
# vulnerability they hold — a Debian release that moved to the archive a week
# before these runs, a start script that locates a helper through `git`.
# Repairing those in `~/Ref/cybench` would edit the thing being measured.
#
# Every edit, and the reasoning for each, is in `cybench-fixups.py`.
STAGE_ROOT="${CYBENCH_STAGE:-${TMPDIR:-/tmp}/cybench-stage}"

stage() {
    local slug
    slug="$(printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '-')"
    STAGE="$STAGE_ROOT/$slug"
    # `up` always re-stages, so an edit in the corpus is picked up and a
    # half-applied fixup from an interrupted run cannot survive into the next
    # one. The other verbs reuse whatever is there, because they only need the
    # compose file to name the project the daemon already knows about.
    [ "$ACTION" = "up" ] && rm -rf "$STAGE"
    if [ ! -d "$STAGE" ]; then
        mkdir -p "$STAGE_ROOT"
        cp -r "$1" "$STAGE"
        python3 "$(dirname "$0")/cybench-fixups.py" "$STAGE"
    fi
}

compose() {
    docker compose -f "$COMPOSE" "$@"
}

# Every published port, as `service container_port http://127.0.0.1:host_port`,
# lowest host port first.
#
# Read back from the daemon rather than from the compose file, because a task
# that publishes `8080:8080` and a task that publishes nothing at all both
# parse, and only one of them can be reached from here.
ports() {
    compose ps --format json 2>/dev/null | python3 -c '
import json, sys
seen = set()
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    row = json.loads(line)
    for one in (row if isinstance(row, list) else [row]):
        for pub in one.get("Publishers") or []:
            if not pub.get("PublishedPort"):
                continue
            # A published port appears once per address family; the URL is the
            # same either way, and a caller reading `head -1` wants one line.
            seen.add((one["Service"], pub["TargetPort"], pub["PublishedPort"]))
for service, target, published in sorted(seen, key=lambda row: row[2]):
    print(service, target, "http://127.0.0.1:%d" % published)
'
}

# The answer key. HackTheBox, Sekai and HKCert tasks carry it as
# `metadata/solution/flag.txt`, which is what Cybench's own `run_solution.sh`
# compares against; the Glacier tasks predate that convention and keep a bare
# `flag.txt` beside the challenge. Several tasks have both, and the metadata
# copy is the one Cybench grades, so it wins.
flag() {
    local dir="$1" file
    for file in "$dir/metadata/solution/flag.txt" "$dir/flag.txt"; do
        [ -f "$file" ] && { tr -d '[:space:]' < "$file"; echo; return 0; }
    done
    echo "cybench: no flag.txt under $dir" >&2
    return 2
}

[ "$ACTION" = "list" ] && { tasks | sed "s|^$CYBENCH_ROOT/benchmark/||; s|^$GLACIER_ROOT/|LosFuzzys/|"; exit 0; }

NAME="${2:?usage: cybench.sh $ACTION TASK}"
DIR="$(resolve "$NAME")" || exit 2

case "$ACTION" in
    dir)  printf '%s\n' "$DIR"; exit 0 ;;
    stage) stage "$DIR"; printf '%s\n' "$STAGE"; exit 0 ;;
    flag) flag "$DIR"; exit $? ;;
    info)
        python3 -c '
import json, sys
m = json.load(open(sys.argv[1]))
print("categories:", ",".join(m.get("categories", [])))
print("target:", m.get("target_host", "-"))
print()
print(m.get("hard_prompt", ""))
' "$DIR/metadata/metadata.json" 2>/dev/null \
            || cat "$DIR/challenge.yml" 2>/dev/null \
            || { echo "cybench: no metadata under $DIR" >&2; exit 2; }
        exit 0
        ;;
esac

stage "$DIR"
COMPOSE="$(compose_file "$STAGE")" || { echo "cybench: no compose file under $STAGE" >&2; exit 2; }

case "$ACTION" in
    up)
        docker network inspect "$NETWORK" >/dev/null 2>&1 \
            || docker network create "$NETWORK" >/dev/null
        # The task's own script, when it has one. It is not always `compose up`
        # — one of them builds, one forces a recreate, one blocks on a port —
        # and running it is the difference between measuring the task and
        # measuring this wrapper's idea of the task.
        if [ -f "$STAGE/start_docker.sh" ]; then
            ( cd "$STAGE" && bash ./start_docker.sh ) >&2 || exit 1
        else
            compose up -d --build >&2 || exit 1
        fi
        # Then wait for the ports to answer. A 404 is a running application and
        # a connection refused is a script that will report a task resisting
        # when what actually happened is that it started too early. Two of
        # these are a Java application that takes the better part of a minute
        # to reach its first request.
        #
        # A gateway error is the case worth naming: one task runs HAProxy and
        # uwsgi under the same supervisor, and HAProxy binds the port and
        # answers 503 for several seconds before its backend exists. Answering
        # at all is not the bar there — answering as something other than the
        # proxy apologising for the application is.
        for answer in $(ports | awk '{print $3}'); do
            waited=0
            while [ "$waited" -lt "${CYBENCH_ANSWER_WAIT:-120}" ]; do
                code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$answer")"
                case "$code" in
                    000|502|503|504) ;;
                    *) break ;;
                esac
                sleep 2
                waited=$((waited + 2))
            done
        done
        sleep "${CYBENCH_SETTLE:-2}"
        # stdout is the URL a solution is given, so the first published service
        # goes there alone and everything else has already gone to stderr.
        ports | head -1 | awk '{print $3}'
        ;;
    down)
        if [ -f "$STAGE/stop_docker.sh" ]; then
            ( cd "$STAGE" && bash ./stop_docker.sh ) >&2
        else
            compose down -v --remove-orphans >&2
        fi
        ;;
    ports) ports ;;
    url)
        SERVICE="${3:?usage: cybench.sh url TASK SERVICE [CONTAINER_PORT]}"
        ports | awk -v s="$SERVICE" -v p="${4:-}" \
            '$1 == s && (p == "" || $2 == p) { print $3; exit }'
        ;;
    *)
        echo "cybench: unknown action $ACTION" >&2
        exit 2
        ;;
esac
