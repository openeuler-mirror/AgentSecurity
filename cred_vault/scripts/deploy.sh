#!/usr/bin/env bash
# Deployment script for the three-process credential vault (no systemd).
#
#   credstore  ── AF_UNIX store socket ── credproxyd ── mgmt.sock ── credclient
#                                        └─ transparent TLS capture (0.0.0.0:4100)
#
# Subcommands:
#   up         create directories, copy binaries, start credstore then
#              credproxyd, export the MITM CA certificate for distribution,
#              then verify with `credclient validate`. With a capture section
#              in the bootstrap config the daemon installs the netfilter rules
#              itself and refuses startup if they cannot be installed.
#   stop       stop credproxyd then credstore. Capture rules are deliberately
#              kept, so traffic cannot bypass the proxy while it is down.
#   uninstall  stop the daemon, remove the capture rules with
#              `credproxyd uninstall-capture`, then stop credstore. This is
#              the only path that removes the rules.
#   status     show processes, sockets, listeners and the capture chains.
#
# `up` is idempotent: running processes are left alone and rule installation is
# idempotent. The vault is never deleted by this script.
#
# Requires root (directories, sockets, netfilter). The vault data directory
# must be 0700 and owned by the credstore uid.
#
# Environment (defaults follow the binaries):
#   BIN_DIR             binaries to deploy             (repo target/release)
#   PREFIX              install root                    /opt/credsvault
#   STATE_DIR           runtime dir (sockets, logs)     /run/credsvault
#   DATA_DIR            vault                           /var/lib/cvstore
#   STORE_SOCKET        credstore socket                /run/cvstore/store.sock
#   MGMT_SOCKET         management socket               $STATE_DIR/mgmt.sock
#   CA_FILE             exported MITM CA cert (PEM)     /etc/credsvault/ca.pem
#   CONFIG_FILE         daemon bootstrap config         /etc/credsvault/credproxyd.json
#   LISTEN_TRANSPARENT  transparent listener            (bootstrap config; default 0.0.0.0:4100)
#   CAPTURE_INTERFACE   VM/sandbox bridge; empty = do not touch netfilter
#   CAPTURE_SUBNET      bridge subnet, e.g. 192.168.56.0/24
#   CAPTURE_GATEWAY     host address on that bridge, e.g. 192.168.56.1
#
# The root password is never read by this script; run it through sudo yourself.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

BIN_DIR="${BIN_DIR:-$REPO_DIR/target/release}"
PREFIX="${PREFIX:-/opt/credsvault}"
STATE_DIR="${STATE_DIR:-/run/credsvault}"
DATA_DIR="${DATA_DIR:-/var/lib/cvstore}"
STORE_SOCKET="${STORE_SOCKET:-/run/cvstore/store.sock}"
MGMT_SOCKET="${MGMT_SOCKET:-$STATE_DIR/mgmt.sock}"
CA_FILE="${CA_FILE:-/etc/credsvault/ca.pem}"
CONFIG_FILE="${CONFIG_FILE:-/etc/credsvault/credproxyd.json}"
LISTEN_TRANSPARENT="${LISTEN_TRANSPARENT:-}"
CAPTURE_INTERFACE="${CAPTURE_INTERFACE:-}"
CAPTURE_SUBNET="${CAPTURE_SUBNET:-}"
CAPTURE_GATEWAY="${CAPTURE_GATEWAY:-}"

STORE_PID_FILE="$STATE_DIR/credstore.pid"
DAEMON_PID_FILE="$STATE_DIR/credproxyd.pid"
STORE_LOG="$STATE_DIR/credstore.log"
DAEMON_LOG="$STATE_DIR/credproxyd.log"

CTL=("$PREFIX/bin/credclient" --mgmt-socket "$MGMT_SOCKET")

say() { printf '%s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

need_root() {
    [ "$(id -u)" -eq 0 ] || die "must run as root (directories, sockets, netfilter)"
}

pid_alive() { # pid-file
    [ -s "$1" ] || return 1
    local pid
    pid=$(cat "$1")
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

wait_for() { # path, seconds
    local i
    for i in $(seq 1 $(( $2 * 10 ))); do
        [ -e "$1" ] && return 0
        sleep 0.1
    done
    return 1
}

# ------------------------------------------------------------------ directories
prepare_dirs() {
    install -d -m 0700 "$DATA_DIR"
    chmod 0700 "$DATA_DIR"
    install -d -m 0755 "$STATE_DIR" "$(dirname "$STORE_SOCKET")" "$(dirname "$MGMT_SOCKET")"
    install -d -m 0755 "$(dirname "$CA_FILE")" "$(dirname "$CONFIG_FILE")"
    install -d -m 0755 "$PREFIX" "$PREFIX/bin"
}

install_bins() {
    local b
    for b in credstore credproxyd credclient; do
        [ -x "$BIN_DIR/$b" ] || die "$BIN_DIR/$b not found (cargo build --release)"
        if [ "$(readlink -f "$BIN_DIR/$b")" != "$(readlink -f "$PREFIX/bin/$b" 2>/dev/null || echo -)" ]; then
            install -m 0755 "$BIN_DIR/$b" "$PREFIX/bin/$b"
        fi
    done
}

# The transparent listener: an explicit LISTEN_TRANSPARENT wins; otherwise the
# value already in the bootstrap config is preserved, so re-running `up` does
# not silently move a deployed listener back to the default.
effective_listen() {
    if [ -n "$LISTEN_TRANSPARENT" ]; then
        printf '%s' "$LISTEN_TRANSPARENT"
        return
    fi
    if [ -f "$CONFIG_FILE" ]; then
        python3 - "$CONFIG_FILE" <<'PY' 2>/dev/null
import json, sys
try:
    print(json.load(open(sys.argv[1])).get("listen_transparent", "0.0.0.0:4100"))
except Exception:
    print("0.0.0.0:4100")
PY
        return
    fi
    printf '0.0.0.0:4100'
}

# The daemon's bootstrap parameters: store and management sockets, the
# transparent listener, plus the deployment-specific capture inputs. Only the
# CA lives in the daemon's own state file and is changed through `credclient`.
write_daemon_config() {
    local tmp esc_store esc_mgmt listen esc_listen
    esc_store="${STORE_SOCKET//\\/\\\\}"; esc_store="${esc_store//\"/\\\"}"
    esc_mgmt="${MGMT_SOCKET//\\/\\\\}";   esc_mgmt="${esc_mgmt//\"/\\\"}"
    listen="$(effective_listen)"
    esc_listen="${listen//\"/\\\"}"
    tmp="$CONFIG_FILE.tmp.$$"
    if [ -n "$CAPTURE_INTERFACE" ]; then
        [ -n "$CAPTURE_SUBNET" ] && [ -n "$CAPTURE_GATEWAY" ] \
            || die "CAPTURE_INTERFACE set: CAPTURE_SUBNET and CAPTURE_GATEWAY are required"
        local esc_if esc_subnet esc_gw
        esc_if="${CAPTURE_INTERFACE//\"/\\\"}"
        esc_subnet="${CAPTURE_SUBNET//\"/\\\"}"
        esc_gw="${CAPTURE_GATEWAY//\"/\\\"}"
        {
            printf '{\n  "store_socket": "%s",\n  "mgmt_socket": "%s",\n' \
                "$esc_store" "$esc_mgmt"
            printf '  "listen_transparent": "%s",\n' "$esc_listen"
            printf '  "capture": {\n    "interface": "%s",\n    "subnet": "%s",\n    "gateway": "%s"\n  }\n}\n' \
                "$esc_if" "$esc_subnet" "$esc_gw"
        } >"$tmp"
        say "bootstrap config $CONFIG_FILE (store $STORE_SOCKET, mgmt $MGMT_SOCKET, listen $listen, capture $CAPTURE_INTERFACE $CAPTURE_SUBNET via $CAPTURE_GATEWAY)"
    else
        {
            printf '{\n  "store_socket": "%s",\n  "mgmt_socket": "%s",\n' \
                "$esc_store" "$esc_mgmt"
            printf '  "listen_transparent": "%s"\n}\n' "$esc_listen"
        } >"$tmp"
        say "bootstrap config $CONFIG_FILE (store $STORE_SOCKET, mgmt $MGMT_SOCKET, listen $listen, netfilter untouched)"
    fi
    chmod 0644 "$tmp"
    mv -f "$tmp" "$CONFIG_FILE"
}

# --------------------------------------------------------------------- services
start_store() {
    if pid_alive "$STORE_PID_FILE"; then
        say "credstore already running (pid $(cat "$STORE_PID_FILE"))"
        return
    fi
    rm -f "$STORE_SOCKET"
    setsid "$PREFIX/bin/credstore" run --socket "$STORE_SOCKET" --data "$DATA_DIR" \
        >>"$STORE_LOG" 2>&1 &
    echo $! >"$STORE_PID_FILE"
    wait_for "$STORE_SOCKET" 10 || { tail -20 "$STORE_LOG" >&2; die "credstore did not bind $STORE_SOCKET"; }
    say "credstore started (pid $(cat "$STORE_PID_FILE"), socket $STORE_SOCKET, vault $DATA_DIR)"
}

stop_store() {
    if pid_alive "$STORE_PID_FILE"; then
        kill "$(cat "$STORE_PID_FILE")" 2>/dev/null || true
        for _ in $(seq 1 50); do
            pid_alive "$STORE_PID_FILE" || break
            sleep 0.1
        done
        say "credstore stopped"
    fi
    rm -f "$STORE_PID_FILE" "$STORE_SOCKET"
}

start_daemon() {
    if pid_alive "$DAEMON_PID_FILE"; then
        say "credproxyd already running (pid $(cat "$DAEMON_PID_FILE"))"
        return
    fi
    setsid "$PREFIX/bin/credproxyd" run --config "$CONFIG_FILE" >>"$DAEMON_LOG" 2>&1 &
    echo $! >"$DAEMON_PID_FILE"
    wait_for "$MGMT_SOCKET" 20 || { tail -20 "$DAEMON_LOG" >&2; die "credproxyd did not start"; }
    say "credproxyd started (pid $(cat "$DAEMON_PID_FILE"), management socket $MGMT_SOCKET)"
}

stop_daemon() {
    if pid_alive "$DAEMON_PID_FILE"; then
        kill "$(cat "$DAEMON_PID_FILE")" 2>/dev/null || true
        for _ in $(seq 1 50); do
            pid_alive "$DAEMON_PID_FILE" || break
            sleep 0.1
        done
        say "credproxyd stopped"
    fi
    rm -f "$DAEMON_PID_FILE" "$MGMT_SOCKET"
}

restart_daemon() {
    stop_daemon
    start_daemon
}

# The listener is read from the bootstrap config at startup. If the running
# daemon is bound to a different address than the config now says (a changed
# LISTEN_TRANSPARENT, or the variable was removed), restart it so it binds the
# configured address; startup re-installs the capture rules with the new port.
sync_listener() {
    local want bound
    want="$(effective_listen)"
    bound=$("${CTL[@]}" health 2>/dev/null | python3 -c '
import json, sys
print(json.load(sys.stdin).get("listen_transparent", ""))
' 2>/dev/null || true)
    [ -n "$bound" ] || return 0
    if [ "$bound" != "$want" ]; then
        say "listener changed ($bound -> $want); restarting credproxyd"
        restart_daemon
    fi
}

# The CA is generated by the daemon on first start (design §4.2.2); only the
# certificate is exported here. `dump` redacts the private key by default, and
# the extraction writes only `config.ca.cert`, never prints a secret.
export_ca() {
    local tmp
    tmp="$CA_FILE.tmp.$$"
    "${CTL[@]}" dump --format json | python3 -c '
import json, sys
doc = json.load(sys.stdin)
ca = ((doc.get("config") or {}).get("ca") or {})
cert = ca.get("cert")
if not cert:
    sys.exit("daemon dump has no CA certificate")
sys.stdout.write(cert if cert.endswith("\n") else cert + "\n")
' >"$tmp" || { rm -f "$tmp"; die "cannot export the CA certificate from the daemon"; }
    install -m 0644 "$tmp" "$CA_FILE"
    rm -f "$tmp"
    say "CA certificate exported to $CA_FILE (distribute it to agents, never the key)"
}

# ------------------------------------------------------------------- commands
cmd_up() {
    need_root
    if [ -n "$CAPTURE_INTERFACE" ]; then
        command -v iptables >/dev/null || die "iptables is required when CAPTURE_INTERFACE is set"
    fi
    prepare_dirs
    install_bins
    start_store
    write_daemon_config
    start_daemon
    export_ca
    sync_listener
    "${CTL[@]}" validate >/dev/null || die "credclient validate failed"
    say "validate: ok"
    cmd_status
    say ""
    say "next: create a credential, then hand its fake_cred to the agent"
    say "  ${CTL[*]} credential add --name <name> --user-id <id> --user-name <name> \\"
    say "      --allow-host <host> --value-file <file>"
    say "  agent side: put the returned fake_cred where the tool expects the secret"
    say "  guests: install $CA_FILE in the guest trust store"
}

cmd_stop() {
    need_root
    stop_daemon
    stop_store
    say "stopped (vault $DATA_DIR kept; capture rules kept - use '$0 uninstall' to remove them)"
}

cmd_uninstall() {
    need_root
    stop_daemon
    "$PREFIX/bin/credproxyd" uninstall-capture \
        || die "capture rules not removed (is iptables available?)"
    stop_store
    say "capture rules removed; vault $DATA_DIR and daemon state kept"
}

cmd_status() {
    local ok=0
    if pid_alive "$STORE_PID_FILE"; then
        say "credstore   running (pid $(cat "$STORE_PID_FILE"))"
    else
        say "credstore   stopped"; ok=1
    fi
    if pid_alive "$DAEMON_PID_FILE"; then
        say "credproxyd  running (pid $(cat "$DAEMON_PID_FILE"))"
    else
        say "credproxyd  stopped"; ok=1
    fi
    [ -S "$STORE_SOCKET" ] && say "store socket $STORE_SOCKET" || say "store socket missing"
    [ -S "$MGMT_SOCKET" ] && say "mgmt socket  $MGMT_SOCKET" || say "mgmt socket missing"
    if command -v ss >/dev/null; then
        local want port
        want="$(effective_listen)"
        port="${want##*:}"
        say "listener (config): $want"
        ss -ltn 2>/dev/null | awk 'NR==1 || $4 ~ /:'"$port"'$/' || true
    fi
    if command -v iptables >/dev/null; then
        local jumps
        jumps=$({ iptables -t nat -S; iptables -S; } 2>/dev/null | grep -c 'CREDSVAULT_' || true)
        say "capture rules: $jumps reference(s) to CREDSVAULT_PREROUTING"
    fi
    return "$ok"
}

usage() { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; }

case "${1:-up}" in
    up) cmd_up ;;
    stop) cmd_stop ;;
    uninstall) cmd_uninstall ;;
    status) cmd_status ;;
    -h|--help|help) usage ;;
    *) die "unknown subcommand '$1' (up|stop|uninstall|status)" ;;
esac
