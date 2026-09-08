"""Repairs applied to a staged copy of one Cybench task, never to the corpus.

Cybench was assembled in 2024 and pins almost nothing. Everything here is the
same kind of edit — a build that no longer builds, for a reason that has
nothing to do with the vulnerability being measured — and none of it touches an
application's behaviour.

The line held here: repair only what stops the environment coming up the way
the task's own documentation says it does. Never weaken a check, never widen a
vulnerability, never make an exploit shorter. Every edit is listed below so a
reader who disagrees can discount those results.

    cybench-fixups.py "/path/to/staged/task"
"""

import pathlib
import re
import sys

# Debian 11 left its normal home on 2026-08-31, one week before these runs, so
# a task built on a bullseye base whose Dockerfile opens with `apt update` now
# fails outright: the release files on `deb.debian.org` are expired and
# `security.debian.org` no longer serves the suite at all. The packages
# themselves are unchanged and still served, from `archive.debian.org`.
#
# Among the web tasks that is Labyrinth Linguist, on `maven:3.8.5-openjdk-11-
# slim`. MOTP is bullseye too and never runs `apt`, so it is left alone.
#
# `bullseye-updates` and `bullseye-security` are dropped rather than
# redirected. The updates suite was folded into the archive's point release and
# the security suite was never copied there under that name, so both are 404s;
# what remains is the same package set the task was built against in 2024,
# which is closer to what the task intended than a newer one would be.
BULLSEYE_REPAIR = (
    "sed -i 's|deb.debian.org|archive.debian.org|g; "
    "/security.debian.org/d; /bullseye-updates/d' /etc/apt/sources.list "
    "&& apt-get -o Acquire::Check-Valid-Until=false update"
)

# The forms these Dockerfiles actually use to refresh the package index. Each
# is replaced by the repair above, which ends in the same `update`.
APT_UPDATE = re.compile(r"\bapt(?:-get)?\s+update\b")


def bullseye(stage):
    """`apt update` on a Debian 11 base, after Debian 11 moved to the archive."""
    for path in list(stage.rglob("Dockerfile")) + list(stage.rglob("Dockerfile.*")):
        text = path.read_text(errors="surrogateescape")
        # Only images that are actually bullseye. Alpine tasks in this corpus
        # run `apk update` and are unaffected; a bookworm base is still served
        # from `deb.debian.org` and must be left alone.
        if not re.search(r"^FROM .*(bullseye|maven:3\.8\.5-openjdk-11-slim)", text, re.M):
            continue
        fixed = APT_UPDATE.sub(BULLSEYE_REPAIR, text, count=1)
        if fixed != text:
            path.write_text(fixed, errors="surrogateescape")


# Base images the corpus names that Docker Hub no longer serves. The
# replacement has to match the one the Dockerfile was written against closely
# enough that the rest of the file still runs — same JDK major version, same
# distribution family, so `apt-get` and `adduser` keep their flags.
WITHDRAWN_IMAGES = {
    # The `openjdk` Official Image was deprecated in 2022 and its Debian-based
    # tags were withdrawn; `11-slim` no longer resolves at all. Eclipse
    # Temurin is the successor the deprecation notice names. The `jammy`
    # variant keeps this Dockerfile's `apt-get install` and its Debian-style
    # `adduser --system --group` working, which an Alpine variant would not.
    "openjdk:11-slim": "eclipse-temurin:11-jre-jammy",
}


def withdrawn_base_images(stage):
    """`FROM` an image that has since been pulled from Docker Hub."""
    for path in list(stage.rglob("Dockerfile")) + list(stage.rglob("Dockerfile.*")):
        text = path.read_text(errors="surrogateescape")
        fixed = text
        for old, replacement in WITHDRAWN_IMAGES.items():
            fixed = re.sub(r"(?m)^(FROM\s+)%s\b" % re.escape(old),
                           r"\g<1>" + replacement, fixed)
        if fixed != text:
            path.write_text(fixed, errors="surrogateescape")


def start_docker_without_git(stage):
    """`start_docker.sh` that resolves a path through `git rev-parse`.

    One task ends its start script by blocking on a port, and finds the script
    that does the blocking through `git rev-parse --show-toplevel`. A staged
    copy is not inside the Cybench checkout, so the command fails and `set -e`
    takes the whole start down with it — after compose has already brought the
    task up. The wait is the only thing lost, and `cybench.sh up` waits for the
    published ports itself.
    """
    script = stage / "start_docker.sh"
    if not script.exists():
        return
    text = script.read_text()
    if "rev-parse" not in text:
        return
    kept = []
    for line in text.splitlines(True):
        if "rev-parse" in line or "check_port.py" in line:
            kept.append("# removed by cybench-fixups.py: " + line.lstrip())
            continue
        kept.append(line)
    script.write_text("".join(kept))


def main():
    stage = pathlib.Path(sys.argv[1])
    bullseye(stage)
    withdrawn_base_images(stage)
    start_docker_without_git(stage)


if __name__ == "__main__":
    main()
