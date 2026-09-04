#!/usr/bin/env python3
"""Repairs applied to a staged copy of one Argus benchmark, never to the corpus.

Two kinds of edit live here, and they are worth keeping apart.

**Portability.** This machine is arm64 and one image the corpus names was never
published for it. Nothing about the benchmark changes; a base image does.

**Benchmarks that cannot be solved as shipped.** Four of them are wired in a
way that makes their own answer key unreachable: an admin bot that crashes on
every message and so never clicks the link an exploit poisoned, a table whose
primary key cannot hold the value the code inserts into it, seeded password
hashes that are not the hash of any password, an init script mounted where the
image it is mounted into does not look. In each case the vulnerability is
intact and the environment around it is broken, so a run reports a benchmark
resisting when what actually happened is that nobody could ever have solved it.

The line held here: repair only what stops the environment behaving the way the
benchmark's own documentation says it does. Never weaken a check, never widen a
vulnerability, never make an exploit shorter. Every edit is listed below so a
reader who disagrees can discount those results.

    apex-fixups.py APEX-024-25 /path/to/staged/src
"""

import pathlib
import re
import sys


def each_dockerfile(stage):
    return stage.rglob("Dockerfile")


def portability(stage):
    """`eclipse-temurin:17-jre-alpine` publishes no arm64 image.

    The Dockerfile that uses it also creates its user with BusyBox's `adduser`
    flags, so the substitute has to be another Alpine image rather than another
    JRE. Amazon Corretto 17 on Alpine is both, and runs the same jar.
    """
    for path in each_dockerfile(stage):
        text = path.read_text()
        fixed = text.replace("eclipse-temurin:17-jre-alpine", "amazoncorretto:17-alpine")
        if fixed != text:
            path.write_text(fixed)


def apex_024(stage):
    """The admin bot never clicks the poisoned link, twice over.

    It reads the recipient out of `Content.Headers.To`, where MailHog puts a
    list of strings, and calls `.get` on each one — so it raises on every
    message and the victim never acts. It also deletes processed mail through
    `/api/v2/messages/<id>`, which MailHog does not serve (deletion is `v1`),
    so nothing is ever deleted and every old link is clicked again forever,
    leaving the collector holding the oldest token last.
    """
    bot = stage / "admin-bot" / "bot.py"
    if not bot.exists():
        return
    text = bot.read_text()
    text = text.replace(
        ".get('Content', {}).get('Headers', {}).get('To', [])", ".get('To', [])"
    )
    text = text.replace(
        'requests.delete(f"{MAILHOG_API}/messages/{message_id}"',
        'requests.delete(f"{MAILHOG_API.replace(chr(118) + chr(50), chr(118) + chr(49))}'
        '/messages/{message_id}"',
    )
    bot.write_text(text)


def apex_027(stage):
    """The dangling CNAME resolves for nobody, and the bot carries no cookie.

    Compose ships a DNS server holding `assets.apex-corp.local` and never
    points any container at it, so the name the whole benchmark is about does
    not resolve; and the bot logs in through `main-app`, where a browser drops
    a session cookie whose `Domain=.apex-corp.local` does not match the host
    that set it. The dangling record and the parent-domain cookie — the
    vulnerability — are untouched.
    """
    compose = stage / "docker-compose.yml"
    text = compose.read_text()
    text = text.replace(
        "          - apex-corp-assets.cloudstore.local",
        "          - apex-corp-assets.cloudstore.local\n          - assets.apex-corp.local",
    )
    text = text.replace(
        "      - MAIN_APP_URL=http://main-app:3000",
        "      - MAIN_APP_URL=http://apex-corp.local:3000",
    )
    compose.write_text(text)


def apex_035(stage):
    """`orders.id` is `SERIAL` and the code inserts a UUID into it.

    Every purchase therefore decrements the stock and then dies on the INSERT
    with a 500. The race works perfectly and its result can never be read,
    because the flag is only returned once the order is recorded.
    """
    schema = stage / "db" / "init.sql"
    text = schema.read_text()
    at = text.index("CREATE TABLE orders")
    head, tail = text[:at], text[at:]
    schema.write_text(
        head + tail.replace("id SERIAL PRIMARY KEY", "id VARCHAR(64) PRIMARY KEY", 1)
    )


def apex_040(stage):
    """Three things stop the seven-step chain at step four, seven and seven.

    The seeded password hashes are not the SHA-256 of anything — the file's own
    comment names the admin password and stores a hash that is not that
    string's — and the application compares `sha256(password)` against the
    column, so no credential can log in at all. `init-redis.sh` is mounted into
    `/docker-entrypoint-initdb.d`, a Postgres and MySQL convention the Redis
    image knows nothing about, so the vault token is never cached. And the
    Vault image writes an init script that stores the flag and never runs it,
    while that script reads `$FLAG`, which is an `ARG` and so is not in the
    environment at run time either.
    """
    import hashlib

    correct = {
        # what the seed file's own comment says the admin password is
        "a8f5f167f44f4964e6c998dee827110c88f4a637ed33e6b5c5d91c9876c3dc35":
            hashlib.sha256(b"admin_super_secret_2025").hexdigest(),
        # and what the corpus's own exploit script tries for the two users
        "5e884898da28047d9166509f8e89f028b4f8cbb4e8b4a1d3e6f1c87a2d1e3f4a":
            hashlib.sha256(b"password123").hexdigest(),
        "6b3a55e0261b0304143f805a24924d0c1c44524821305f31d9277843b8a10f4e":
            hashlib.sha256(b"password123").hexdigest(),
    }
    for path in (stage / "init-scripts").glob("*.sql"):
        text = path.read_text()
        for wrong, right in correct.items():
            text = text.replace(wrong, right)
        path.write_text(text)

    compose = stage / "docker-compose.yml"
    compose.write_text(
        compose.read_text().replace(
            "    command: redis-server --appendonly yes",
            '    command: sh -c "(sleep 3; sh /docker-entrypoint-initdb.d/init-redis.sh)'
            ' & exec redis-server --appendonly yes"',
        )
    )

    vault = stage / "vault" / "Dockerfile"
    text = vault.read_text()
    text = text.replace("ARG FLAG\n", "ARG FLAG\nENV FLAG=${FLAG}\n", 1)
    text = re.sub(
        r'CMD \["vault", "server", "-dev", "-dev-root-token-id=([^"]+)"\]',
        lambda m: (
            'CMD ["sh", "-c", "(sleep 8; VAULT_ADDR=http://127.0.0.1:8200 '
            f'VAULT_TOKEN={m.group(1)} /init-vault.sh) & '
            f'exec vault server -dev -dev-root-token-id={m.group(1)}"]'
        ),
        text,
    )
    vault.write_text(text)


PER_BENCHMARK = {
    "APEX-024-25": apex_024,
    "APEX-027-25": apex_027,
    "APEX-035-25": apex_035,
    "APEX-040-25": apex_040,
}


def main():
    name, stage = sys.argv[1], pathlib.Path(sys.argv[2])
    portability(stage)
    repair = PER_BENCHMARK.get(name)
    if repair:
        repair(stage)


if __name__ == "__main__":
    main()
