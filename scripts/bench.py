#!/usr/bin/env python3
"""Build and run one XBOW validation benchmark, without `docker compose`.

The benchmarks ship `docker-compose.yml` files, and the compose v2 plugin is not
everywhere. What they actually use is a small subset: build a context with a
`FLAG` build argument, publish a port, sometimes wait for a database first. That
subset is `docker build` and `docker run` on a private network, which is what
this does.

Not a compose implementation. It reads the fields these files use and refuses
loudly on anything else, because a runner that silently ignored a `volumes:` or
a `command:` would start a container that is not the benchmark and then report
whatever that container did.

    ./bench.py build XBEN-001-24
    ./bench.py up    XBEN-001-24      # prints the URL on stdout
    ./bench.py down  XBEN-001-24
    ./bench.py flag  XBEN-001-24      # the flag this build was given

The flag is `FLAG{sha256(BENCHMARK-NAME)}`, exactly as `common.mk` computes it,
so a run can be scored without anybody being told the answer.
"""

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import time

import yaml

ROOT = pathlib.Path(
    os.environ.get("XBEN_ROOT", pathlib.Path.home() / "Ref" / "validation-benchmarks")
)

# What this runner understands. Anything else in a service is a reason to stop:
# see the module docstring.
KNOWN_KEYS = {
    "build", "image", "ports", "expose", "healthcheck", "depends_on",
    "environment", "networks", "container_name", "restart", "links", "command",
}


def die(message):
    print(f"bench: {message}", file=sys.stderr)
    sys.exit(2)


def run(args, **kwargs):
    return subprocess.run(args, check=False, capture_output=True, text=True, **kwargs)


def flag_for(name):
    """`FLAG{sha256(NAME)}`, as common.mk computes it."""
    digest = hashlib.sha256(name.upper().encode()).hexdigest()
    return "FLAG{" + digest + "}"


def compose_of(name):
    path = ROOT / "benchmarks" / name / "docker-compose.yml"
    if not path.is_file():
        die(f"no benchmark {name} at {path}")
    with open(path) as handle:
        return yaml.safe_load(handle)


def services_of(name):
    spec = compose_of(name)
    services = spec.get("services") or {}
    for service, body in services.items():
        unknown = set(body or {}) - KNOWN_KEYS
        if unknown:
            die(f"{name}/{service} uses {sorted(unknown)}, which this runner does not do")
    return services


def image_name(name, service):
    return f"xben/{name.lower()}-{service.lower()}"


def net_name(name):
    return f"xben-{name.lower()}"


def build(name):
    services = services_of(name)
    flag = flag_for(name)
    base = ROOT / "benchmarks" / name
    for service, body in services.items():
        body = body or {}
        if "build" not in body:
            # A prebuilt image: pull it now so `up` does not pay for it and so a
            # pull failure is reported as a build failure, which is what it is.
            image = body.get("image")
            if not image:
                die(f"{name}/{service} has neither build nor image")
            result = run(["docker", "pull", image])
            if result.returncode != 0:
                die(f"{name}/{service}: could not pull {image}\n{result.stderr.strip()}")
            continue

        spec = body["build"]
        context = spec if isinstance(spec, str) else spec.get("context", ".")
        args = [] if isinstance(spec, str) else (spec.get("args") or [])
        argv = ["docker", "build", "-t", image_name(name, service)]
        # `args: [- FLAG]` means "pass the FLAG from the environment". Both
        # spellings appear across the corpus, so both are supplied.
        for arg in args:
            key = arg.split("=", 1)[0] if isinstance(arg, str) else str(arg)
            argv += ["--build-arg", f"{key}={flag}"]
        if not args:
            argv += ["--build-arg", f"FLAG={flag}", "--build-arg", f"flag={flag}"]
        argv.append(str((base / context).resolve()))
        print(f"  building {service} …", flush=True)
        result = run(argv)
        if result.returncode != 0:
            tail = "\n".join(result.stderr.strip().splitlines()[-12:])
            die(f"{name}/{service} did not build:\n{tail}")
    print(f"  built {name} with {flag}")


def published_port(container):
    """The host port docker gave a container, whatever it published."""
    result = run(["docker", "port", container])
    for line in result.stdout.splitlines():
        # "80/tcp -> 0.0.0.0:32768"
        found = re.search(r"->\s+[\d.]+:(\d+)", line)
        if found:
            return int(found.group(1))
    return None


def up(name, timeout=120):
    services = services_of(name)
    down(name, quiet=True)
    run(["docker", "network", "create", net_name(name)])

    # Dependencies first, then the rest. `depends_on` is the only ordering these
    # files express, and it is always shallow.
    ordered = sorted(
        services.items(),
        key=lambda pair: 0 if not (pair[1] or {}).get("depends_on") else 1,
    )
    web = None
    for service, body in ordered:
        body = body or {}
        argv = [
            "docker", "run", "-d",
            "--name", f"{net_name(name)}-{service}",
            "--network", net_name(name),
            # The compose service name is how the app finds its database.
            "--network-alias", service,
        ]
        for entry in body.get("environment") or []:
            if isinstance(entry, str):
                argv += ["-e", entry]
            else:
                for key, value in entry.items():
                    argv += ["-e", f"{key}={value}"]
        for spec in body.get("ports") or []:
            # "80", "80:80" and 5000 all mean "publish the container's port on
            # some host port we will look up afterwards".
            inner = str(spec).split(":")[-1]
            argv += ["-p", inner]
            web = f"{net_name(name)}-{service}"
        if body.get("command"):
            command = body["command"]
            argv.append(image_name(name, service) if "build" in body else body["image"])
            argv += command if isinstance(command, list) else command.split()
        else:
            argv.append(image_name(name, service) if "build" in body else body["image"])

        result = run(argv)
        if result.returncode != 0:
            die(f"{name}/{service} did not start:\n{result.stderr.strip()}")

        # A dependency has to be answering before the app starts, or the app
        # exits and the run reports an application bug that is really a startup
        # race. Polled rather than trusting the healthcheck, because a container
        # without one still has to be up.
        if any((other or {}).get("depends_on") for _, other in services.items()):
            time.sleep(1)

    if web is None:
        die(f"{name} publishes no port, so there is nothing to drive")

    port = None
    deadline = time.time() + timeout
    while time.time() < deadline:
        port = published_port(web)
        if port:
            probe = run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                         "--max-time", "3", f"http://127.0.0.1:{port}/"])
            if probe.stdout.strip() not in ("", "000"):
                break
        # Still coming up. A container that has already exited will never come
        # up, and saying so beats waiting out the timeout.
        state = run(["docker", "inspect", "-f", "{{.State.Status}}", web]).stdout.strip()
        if state == "exited":
            logs = run(["docker", "logs", "--tail", "15", web])
            die(f"{name}: the web container exited\n{logs.stdout}{logs.stderr}")
        time.sleep(1)
    else:
        die(f"{name}: nothing answered on the published port within {timeout}s")

    print(f"http://127.0.0.1:{port}")


def down(name, quiet=False):
    result = run(["docker", "ps", "-aq", "--filter", f"name={net_name(name)}-"])
    ids = [line for line in result.stdout.split() if line]
    if ids:
        run(["docker", "rm", "-f", *ids])
    run(["docker", "network", "rm", net_name(name)])
    if not quiet:
        print(f"  stopped {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["build", "up", "down", "flag", "info"])
    parser.add_argument("benchmark")
    args = parser.parse_args()

    if args.action == "flag":
        print(flag_for(args.benchmark))
    elif args.action == "info":
        path = ROOT / "benchmarks" / args.benchmark / "benchmark.json"
        with open(path) as handle:
            meta = json.load(handle)
        print(json.dumps({k: meta[k] for k in ("name", "level", "tags") if k in meta}, indent=2))
    elif args.action == "build":
        build(args.benchmark)
    elif args.action == "up":
        up(args.benchmark)
    elif args.action == "down":
        down(args.benchmark)


if __name__ == "__main__":
    main()
