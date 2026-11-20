#!/usr/bin/env bash
# End-to-end transparent capture for a VM on a libvirt bridge (the VM form),
# against real public HTTPS servers, using the three-process deployment
# (credstore + credproxyd + credclient).
#
#   guest <GUEST> ── https://httpbin.org (real DNS, real public IP)
#        └─ default route via <GW> (bridge <BRIDGE>)
#             └─ host netfilter CREDSVAULT_PREROUTING (installed by credproxyd)
#                  └─ DNAT → <GW>:<free port> (bootstrap listen_transparent)
#                       └─ SO_ORIGINAL_DST = <real public ip>:443
#                            └─ MITM (leaf signed by the daemon-generated CA)
#                                 └─ substitute / pass through → dial <real ip>:443
#                                      └─ certificate chain validated by webpki roots
#
# The daemon owns the capture rules: it installs and verifies them at startup,
# refuses to start if they cannot be installed, keeps them on stop/crash, and
# removes them only through `credproxyd uninstall-capture` (this script's
# cleanup does exactly that).
#
# No local HTTPS server is involved and no test-only trust root is injected on
# the upstream side: the daemon validates the real servers against public roots
# (upstream_ca is not set). Assertions read the echo services' response bodies,
# so "substituted" / "passed through" is visible in what the remote received,
# not only in the daemon log.
#
# Requires root (netfilter on the host, guest trust store) and Internet from the
# host and the guest. BIN_DIR must be a `--features test-hooks` build: the
# script redirects the daemon's own state file and instance lock into its work
# directory with `--state-file` / `--lock-file`, so it never touches
# /var/lib/credsvault. Usage:
#   cargo build --release --features credproxyd/test-hooks --workspace
#   sudo test/e2e-vm-transparent.sh
# Environment knobs: BRIDGE, SUBNET, VM_LISTEN, GUEST, GUEST_KEY, BOUND_HOST,
# UNBOUND_HOST, BIN_DIR, RUN_DIR, GIT_HOST, GIT_PATH, GIT_USER, GIT_CRED_FILE,
# GIT_BRANCH, DS_API_KEY, DS_CHAT_MODEL. GIT_CRED_FILE (token or password for
# GIT_USER) enables a successful authenticated push; without it the push uses a
# random invalid real value and must be rejected with 401 after substitution.
# DS_API_KEY is the hardcoded test key; it always enables the real-API matrix:
#   valid credential    registered fakecred bound to api.deepseek.com,
#                       real = the valid key            → 200 (substituted)
#   invalid credential  registered fakecred, real = a bogus value
#                       → the daemon substitutes, the API answers 401
#   unregistered token  fakecred-shaped but not in the registry
#                       → forwarded unchanged, 401 (passthrough)
#   real API key        the key itself, sent by the guest through the capture
#                       and directly from the host          → 200
# The key is never printed; it reaches credclient through a 0600 file and the
# guest-side real-key case stages it through ssh stdin into another 0600 header
# file that is removed immediately after the request.
# CREDPROXY_TEST_KEEP=1 keeps the work directory on success.
#
# The root password is never read by this script; run it through sudo yourself.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "FAIL: must run as root (iptables + guest trust store); re-run with sudo" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO_DIR/target/release}"
BRIDGE="${BRIDGE:-virbr-cpb}"
SUBNET="${SUBNET:-192.168.56.0/24}"
GW="${GW:-192.168.56.1}"
# The transparent listener takes a free port on the gateway address by
# default, so the case also runs on a host where a deployed credproxyd already
# binds 4100. `capture` validation accepts exactly `0.0.0.0` or the gateway.
if [ -z "${VM_LISTEN:-}" ]; then
    VM_PORT=$(python3 - "$GW" <<'PY'
import socket, sys
s = socket.socket()
s.bind((sys.argv[1], 0))
print(s.getsockname()[1])
s.close()
PY
)
    [ -n "$VM_PORT" ] || { echo "FAIL: cannot pick a free port on $GW" >&2; exit 1; }
    VM_LISTEN="$GW:$VM_PORT"
fi
GUEST="${GUEST:-root@192.168.56.26}"
GUEST_KEY="${GUEST_KEY:-/home/yxy/.ssh/id_ed25519}"
BOUND_HOST="${BOUND_HOST:-httpbin.org}"
UNBOUND_HOST="${UNBOUND_HOST:-httpbun.com}"
# Built-in DeepSeek key for this test deployment, hardcoded at the operator's
# request. It is written to a 0600 file inside the work directory, never put on
# a command line, never printed, and removed by cleanup. It lives in the
# repository: rotate it if the repository is shared.
DS_API_KEY="${DS_API_KEY:-sk-9fb8d2722c5c4a0b80e54da615d58642}"
DS_CHAT_MODEL="${DS_CHAT_MODEL:-deepseek-chat}"
GIT_HOST="${GIT_HOST:-atomgit.com}"
GIT_PATH="${GIT_PATH:-/yinxyww/itrustee_tzdriver.git}"
GIT_USER="${GIT_USER:-yinxyww}"
GIT_CRED_FILE="${GIT_CRED_FILE:-}"
GIT_BRANCH="${GIT_BRANCH:-credproxy-e2e/$(date -u +%Y%m%dT%H%M%SZ)}"
GIT_WORK=/tmp/credproxy-git-e2e
WORK="${RUN_DIR:-$(mktemp -d /tmp/credproxy-vm.XXXXXX)}"
GUEST_CA=/etc/pki/ca-trust/source/anchors/credproxy-vm.pem
GUEST_BODY=/tmp/credproxy-chat-request.json
GUEST_RESP=/tmp/credproxy-chat-response.json
GUEST_KEY_HDR=/tmp/credproxy-key-header

# The built-in key goes to a 0600 file for `--value-file` and for the log
# check; it lives only for the duration of the run.
DS_KEY_PATH="$WORK/ds.key"
(umask 077 && printf '%s' "$DS_API_KEY" >"$DS_KEY_PATH")

STORE_SOCK="$WORK/run/store.sock"
MGMT_SOCK="$WORK/run/mgmt.sock"
VAULT="$WORK/vault"
DAEMON_ERR="$WORK/daemon.err"

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o LogLevel=ERROR -i "$GUEST_KEY")

FAILED=0
DAEMON_PID=""
STORE_PID=""
GUEST_CA_INSTALLED=0
GIT_WORK_CREATED=0

note() { printf '%s\n' "$*"; }
pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; FAILED=1; }

guest() { ssh "${SSH_OPTS[@]}" "$GUEST" "$@"; }

cleanup() {
    set +e
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null && wait "$DAEMON_PID" 2>/dev/null
    # Rules are owned by the daemon and survive stop/crash by design; the
    # explicit uninstall is the only removal path.
    "$BIN_DIR/credproxyd" uninstall-capture >/dev/null 2>&1 || true
    [ -n "$STORE_PID" ] && kill "$STORE_PID" 2>/dev/null && wait "$STORE_PID" 2>/dev/null
    if [ "$GUEST_CA_INSTALLED" -eq 1 ]; then
        guest "rm -f '$GUEST_CA' && update-ca-trust extract" >/dev/null 2>&1
    fi
    if [ "$FAILED" -eq 0 ] && [ "$GIT_WORK_CREATED" -eq 1 ]; then
        guest "rm -rf '$GIT_WORK'" >/dev/null 2>&1
    fi
    rm -f "$DS_KEY_PATH"
    if [ "$FAILED" -ne 0 ]; then
        echo "--- daemon log (tail) ---"
        tail -40 "$DAEMON_ERR" 2>/dev/null
        echo "--- workdir kept: $WORK ---"
    elif [ -n "${CREDPROXY_TEST_KEEP:-}" ]; then
        echo "--- workdir kept (CREDPROXY_TEST_KEEP): $WORK ---"
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT INT TERM

# ------------------------------------------------------------------ preflight
preflight() {
    for bin in credstore credproxyd credclient; do
        [ -x "$BIN_DIR/$bin" ] || {
            echo "FAIL: $BIN_DIR/$bin is not executable (cargo build --release)" >&2
            exit 1
        }
    done
    ip link show "$BRIDGE" >/dev/null 2>&1 || { echo "FAIL: bridge $BRIDGE missing" >&2; exit 1; }
    command -v iptables >/dev/null || { echo "FAIL: iptables missing" >&2; exit 1; }
    guest true || { echo "FAIL: cannot ssh to $GUEST with $GUEST_KEY" >&2; exit 1; }
    guest 'command -v curl' >/dev/null 2>&1 || { echo "FAIL: guest has no curl" >&2; exit 1; }
    guest 'command -v git' >/dev/null 2>&1 || { echo "FAIL: guest has no git" >&2; exit 1; }
    local h
    for h in "$BOUND_HOST" "$UNBOUND_HOST"; do
        curl -sS -o /dev/null --max-time 15 "https://$h/headers" \
            || { echo "FAIL: host has no Internet for $h" >&2; exit 1; }
    done
    curl -sS -o /dev/null --max-time 15 "https://$GIT_HOST/" \
        || { echo "FAIL: host has no Internet for $GIT_HOST" >&2; exit 1; }
}

# ------------------------------------------------------------------- services
start_store() {
    mkdir -p "$WORK/run" "$VAULT"
    chmod 700 "$VAULT"
    "$BIN_DIR/credstore" run --socket "$STORE_SOCK" --data "$VAULT" \
        >"$WORK/store.log" 2>&1 &
    STORE_PID=$!
    for _ in $(seq 1 100); do [ -S "$STORE_SOCK" ] && break; sleep 0.1; done
    [ -S "$STORE_SOCK" ] || { cat "$WORK/store.log"; fail "credstore did not start"; exit 1; }
}

# The transparent listener address is a bootstrap input. The CA is generated
# by the daemon on first start; the daemon's state file holds only the CA.
start_daemon() {
    cat >"$WORK/bootstrap.json" <<JSON
{
  "store_socket": "$STORE_SOCK",
  "mgmt_socket": "$MGMT_SOCK",
  "listen_transparent": "$VM_LISTEN",
  "capture": {
    "interface": "$BRIDGE",
    "subnet": "$SUBNET",
    "gateway": "$GW"
  }
}
JSON
    # The daemon's own state file (CA) is redirected into the work directory
    # so the run never touches /var/lib/credsvault; that override and the
    # instance-lock override exist only in a `test-hooks` build.
    "$BIN_DIR/credproxyd" run --config "$WORK/bootstrap.json" \
        --state-file "$WORK/daemon.json" --lock-file "$WORK/daemon.lock" \
        >>"$DAEMON_ERR" 2>&1 &
    DAEMON_PID=$!
    for _ in $(seq 1 200); do [ -S "$MGMT_SOCK" ] && break; sleep 0.1; done
    [ -S "$MGMT_SOCK" ] || { tail -20 "$DAEMON_ERR"; fail "credproxyd did not start"; exit 1; }
}

stop_daemon() {
    [ -n "$DAEMON_PID" ] || return 0
    kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
    DAEMON_PID=""
    rm -f "$MGMT_SOCK"
}

# ------------------------------------------------------------------ assertions
# Reads the last value the remote echo service reported for a header.
remote_header() { # body, header-name
    printf '%s' "$1" | python3 -c '
import json,sys
try: doc = json.load(sys.stdin)
except Exception: sys.exit(2)
h = doc.get("headers") or {}
print({str(k).lower(): v for k, v in h.items()}.get(sys.argv[1].lower(), ""))
' "$2"
}

# True when the daemon log carries any non-empty line of a secret file. A file
# ending in a newline would otherwise contribute an empty pattern, and grep
# would match every log line.
log_carries_value_from() { # file
    grep -qF -f <(grep -v '^[[:space:]]*$' "$1") "$DAEMON_ERR" 2>/dev/null
}

assert_substitution() {
    local token=$1 real=$2 body got
    # Pin the address the guest dials: httpbin.org rotates A records, and the
    # original_dst assertion needs the address the guest actually connected to.
    body=$(guest "curl -sS --max-time 30 --resolve $BOUND_HOST:443:$BOUND_IP -H 'Authorization: Bearer $token' https://$BOUND_HOST/headers") || body=""
    got=$(remote_header "$body" authorization || true)
    if [ "$got" = "Bearer $real" ]; then
        pass "$BOUND_HOST received the real value (substituted)"
    else
        fail "$BOUND_HOST did not receive the real value (substitution)"
    fi
}

assert_passthrough() {
    local token=$1 body got
    body=$(guest "curl -sS --max-time 30 -H 'Authorization: Bearer $token' https://$UNBOUND_HOST/headers") || body=""
    got=$(remote_header "$body" authorization || true)
    if [ "$got" = "Bearer $token" ]; then
        pass "$UNBOUND_HOST received the placeholder unchanged (passthrough)"
    else
        fail "$UNBOUND_HOST did not receive the placeholder unchanged"
    fi
}

assert_direct_dial_rejected() {
    local rc=0
    guest "curl -sk --max-time 5 https://$VM_LISTEN/ >/dev/null 2>&1" || rc=$?
    if [ "$rc" -ne 0 ] && grep -q "not redirected" "$DAEMON_ERR"; then
        pass "direct dial to $VM_LISTEN rejected (no redirect)"
    else
        fail "direct dial to $VM_LISTEN was not rejected (rc=$rc)"
    fi
}

assert_host_sni_mismatch() {
    local code
    code=$(guest "curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H 'Host: other.example' https://$BOUND_HOST/headers") || code=000
    if [ "$code" = "403" ] && grep -q "reject inner Host != target" "$DAEMON_ERR"; then
        pass "inner Host != target rejected with 403"
    else
        fail "inner Host != SNI not rejected (status=$code)"
    fi
}

assert_original_dst() {
    local ip=$1
    if [ -n "$ip" ] && grep -q "original_dst=$ip:443" "$DAEMON_ERR"; then
        pass "SO_ORIGINAL_DST is the real public address ($ip)"
    else
        fail "SO_ORIGINAL_DST does not match the address the guest dialed ($ip)"
    fi
}

assert_audit() {
    local real=$1 host_re
    host_re=$(printf '%s' "$BOUND_HOST" | sed 's/\./\\./g')
    # One audit line must carry all attributes: a set of independent greps
    # would also pass if the fields were scattered over different lines.
    if grep -Eq "^audit .*ingress=transparent .*user_id=u-vm .*name=vm-https host=$host_re:443 .*decision=substitute" "$DAEMON_ERR"; then
        pass "audit attributes the substitution to u-vm / vm-https / $BOUND_HOST:443"
    else
        fail "audit line missing or not attributed"
    fi
    if grep -qF "$real" "$DAEMON_ERR"; then
        fail "daemon log carries the real value"
    else
        pass "daemon log never carries the real value"
    fi
}

assert_non_443_not_captured() {
    local before after code
    before=$(grep -c "ingress=transparent" "$DAEMON_ERR" || true)
    code=$(guest "curl -s -o /dev/null -w '%{http_code}' --max-time 30 http://example.com/") || code=000
    after=$(grep -c "ingress=transparent" "$DAEMON_ERR" || true)
    if [ "$code" = "200" ] && [ "$before" = "$after" ]; then
        pass "plain HTTP on port 80 is not captured"
    else
        fail "non-443 request changed the capture set (status=$code lines=$before->$after)"
    fi
}

# Case: git over HTTPS. The guest clones the public repository anonymously
# (passthrough), commits locally, then pushes to a new branch with the
# placeholder in the Basic password position. With GIT_CRED_FILE the daemon
# substitutes the real credential and the push must succeed; without it the
# entry holds a random invalid real and the push must be rejected with 401
# after substitution. The commit carries no secret; the branch is kept.
assert_git_over_https() {
    local token=$1 host_re path_re url rc
    host_re=$(printf '%s' "$GIT_HOST" | sed 's/\./\\./g')
    path_re=$(printf '%s' "$GIT_PATH" | sed 's/\./\\./g')
    url="https://$GIT_USER:$token@$GIT_HOST$GIT_PATH"

    note "case: git clone (public) + commit + push ($GIT_HOST$GIT_PATH -> $GIT_BRANCH)"
    guest "rm -rf '$GIT_WORK' && mkdir -p '$GIT_WORK'" >/dev/null 2>&1 \
        || { fail "cannot prepare $GIT_WORK on the guest"; return; }
    GIT_WORK_CREATED=1

    if guest "GIT_TERMINAL_PROMPT=0 timeout 120 git clone -q https://$GIT_HOST$GIT_PATH '$GIT_WORK/repo'" >/dev/null 2>&1; then
        pass "git clone through the capture succeeded (public repository)"
    else
        fail "git clone through the capture failed"
        return
    fi
    if grep -Eq "^audit .*ingress=transparent name=- fake_cred=- host=$host_re:443 .*method=GET path=$path_re/info/refs status=200 decision=passthrough" "$DAEMON_ERR"; then
        pass "audit records the anonymous git discovery as passthrough"
    else
        fail "git discovery passthrough not audited"
    fi

    local stamp
    stamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    if guest "cd '$GIT_WORK/repo' && printf '%s\n' '$stamp' > credproxy-e2e.txt && git add credproxy-e2e.txt && git -c user.name=credproxy-e2e -c user.email=e2e@credproxy.invalid commit -q -m 'credproxy e2e: transparent capture push test'" >/dev/null 2>&1; then
        pass "test commit created on the guest"
    else
        fail "could not create the test commit on the guest"
        return
    fi

    rc=0
    guest "cd '$GIT_WORK/repo' && GIT_TERMINAL_PROMPT=0 timeout 180 git push -q '$url' HEAD:refs/heads/$GIT_BRANCH" >/dev/null 2>&1 || rc=$?

    if [ -n "$GIT_CRED_FILE" ]; then
        if [ "$rc" -eq 0 ]; then
            pass "git push through the capture succeeded (branch $GIT_BRANCH)"
        else
            fail "git push through the capture failed (rc=$rc)"
        fi
        if grep -Eq "^audit .*ingress=transparent .*name=git-atomgit host=$host_re:443 .*method=POST path=$path_re/git-receive-pack status=200 decision=substitute" "$DAEMON_ERR"; then
            pass "audit records the push as a substituted POST (status 200)"
        else
            fail "push substitution not audited"
        fi
        if log_carries_value_from "$GIT_CRED_FILE"; then
            fail "daemon log carries the real git credential"
        else
            pass "daemon log never carries the real git credential"
        fi
    else
        if [ "$rc" -ne 0 ]; then
            pass "git push with an invalid substituted credential rejected (rc=$rc)"
        else
            fail "git push with an invalid credential unexpectedly succeeded"
        fi
        if grep -Eq "^audit .*ingress=transparent .*name=git-atomgit host=$host_re:443 .*status=401 decision=substitute" "$DAEMON_ERR"; then
            pass "audit shows the push 401 followed a substitution"
        else
            fail "push substitution not audited"
        fi
    fi
}

# Case: a valid credential. The placeholder is registered and bound to the API
# host, the daemon substitutes the real key, and the API accepts it.
assert_real_api() {
    local token=$1 body code
    code=$(guest "curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H 'Authorization: Bearer $token' https://api.deepseek.com/models") || code=000
    if [ "$code" = "200" ]; then
        pass "real API accepted the substituted key (/models 200)"
    else
        fail "real API rejected the substituted key (status=$code)"
    fi
    if grep -Eq "^audit .*ingress=transparent .*name=ds-vm host=api\.deepseek\.com:443 .*decision=substitute" "$DAEMON_ERR"; then
        pass "audit attributes the real-API substitution to ds-vm"
    else
        fail "real-API substitution not audited"
    fi
}

# Case: an invalid credential. The placeholder is registered and bound, so the
# daemon substitutes it; the upstream rejects the substituted value. The audit
# line must show `decision=substitute` with the credential name: a bare 401
# would also be produced if the placeholder had been forwarded unchanged.
assert_invalid_credential() {
    local token=$1 code
    note "case: invalid credential (registered placeholder, bogus real)"
    code=$(guest "curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H 'Authorization: Bearer $token' https://api.deepseek.com/models") || code=000
    if [ "$code" = "401" ]; then
        pass "invalid credential rejected by the real API (401)"
    else
        fail "invalid credential was not rejected (status=$code)"
    fi
    if grep -Eq '^audit .*ingress=transparent .*name=ds-bad host=api\.deepseek\.com:443 .*status=401 decision=substitute' "$DAEMON_ERR"; then
        pass "audit shows the 401 followed a substitution of ds-bad"
    else
        fail "invalid-credential substitution not audited"
    fi
}

# Case: a token that looks like a placeholder (carries the `fcred-` anchor) but
# is not in the registry. Decision 38 forwards it unchanged and the API rejects
# it; the audit line is `name=- fake_cred=- decision=passthrough`.
assert_unregistered_token() {
    local token=$1 code
    note "case: unregistered placeholder token"
    code=$(guest "curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H 'Authorization: Bearer $token' https://api.deepseek.com/models") || code=000
    if [ "$code" = "401" ]; then
        pass "unregistered token forwarded unchanged and rejected (401)"
    else
        fail "unregistered token behaved unexpectedly (status=$code)"
    fi
    if grep -Eq '^audit .*ingress=transparent name=- fake_cred=- host=api\.deepseek\.com:443 .*status=401 decision=passthrough' "$DAEMON_ERR"; then
        pass "audit shows the unregistered token was passed through, not substituted"
    else
        fail "unregistered-token passthrough not audited"
    fi
}

# Case: the real API key used by the guest through the capture. It is not a
# registered placeholder, so the daemon forwards it unchanged and the API
# accepts it. The key reaches the guest on ssh stdin and lives in a 0600 header
# file for one request, so it is never part of a command line on either side.
assert_real_key_passthrough() {
    local code
    note "case: real API key sent by the guest through the capture"
    printf 'Authorization: Bearer %s\n' "$DS_KEY" \
        | guest "umask 077 && cat > '$GUEST_KEY_HDR'" \
        || { fail "could not stage the key header on the guest"; return; }
    code=$(guest "curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H @'$GUEST_KEY_HDR' https://api.deepseek.com/models") || code=000
    guest "rm -f '$GUEST_KEY_HDR'" >/dev/null 2>&1 || true
    if [ "$code" = "200" ]; then
        pass "real API key passed through the capture and accepted (200)"
    else
        fail "real API key did not work through the capture (status=$code)"
    fi
    if grep -Eq '^audit .*ingress=transparent name=- fake_cred=- host=api\.deepseek\.com:443 .*status=200 decision=passthrough' "$DAEMON_ERR"; then
        pass "audit shows the real-key request was passed through"
    else
        fail "real-key passthrough not audited"
    fi
}

# Case: the same key straight to the API with no proxy in the path. This is the
# control that separates "the key is valid" from "the proxy works".
assert_real_key_direct() {
    local code
    note "case: real API key used directly from the host"
    printf 'Authorization: Bearer %s\n' "$DS_KEY" >"$WORK/key.header"
    chmod 600 "$WORK/key.header"
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
        -H @"$WORK/key.header" https://api.deepseek.com/models) || code=000
    rm -f "$WORK/key.header"
    if [ "$code" = "200" ]; then
        pass "real API key accepted directly by the API (200)"
    else
        fail "real API key rejected when used directly (status=$code)"
    fi
}

# Case: a real chat completion issued by curl *inside the guest*. This is
# stronger than the /models case above in three ways: the credential travels in
# a POST with a JSON body rather than on a bare GET, the response carries model
# output, and the verdict is what the remote model returned — not only a status
# line. The guest still holds nothing but the placeholder token; the key stays
# in the script's DS_API_KEY and reaches the vault through `--value-file`.
assert_real_api_chat() {
    local token=$1 code body content
    note "case: guest curl → POST https://api.deepseek.com/chat/completions ($DS_CHAT_MODEL)"

    # The request body is staged on the guest so the JSON never has to survive
    # several layers of shell quoting on its way through ssh.
    if ! printf '{"model":"%s","messages":[{"role":"user","content":"Reply with the single word: ok"}],"max_tokens":8,"stream":false}' "$DS_CHAT_MODEL" \
        | guest "cat > '$GUEST_BODY'"; then
        fail "could not stage the request body on the guest"
        return
    fi

    code=$(guest "curl -sS --max-time 60 -o '$GUEST_RESP' -w '%{http_code}' \
        -H 'Authorization: Bearer $token' -H 'Content-Type: application/json' \
        --data-binary @'$GUEST_BODY' https://api.deepseek.com/chat/completions") || code=000
    body=$(guest "cat '$GUEST_RESP' 2>/dev/null") || body=""
    guest "rm -f '$GUEST_BODY' '$GUEST_RESP'" >/dev/null 2>&1 || true

    # A reasoning model may put its answer in `reasoning_content`; either field
    # being non-empty shows the API produced model output for this request.
    content=$(printf '%s' "$body" | python3 -c '
import json, sys
try:
    doc = json.load(sys.stdin)
except Exception:
    sys.exit(2)
choice = (doc.get("choices") or [{}])[0]
msg = choice.get("message") or {}
print((msg.get("content") or msg.get("reasoning_content") or "").strip())
' 2>/dev/null) || content=""

    if [ "$code" = "200" ] && [ -n "$content" ]; then
        pass "guest curl got a real completion (200, ${#content} bytes of model output)"
    elif [ "$code" = "200" ]; then
        fail "guest curl got 200 but the body carries no model output"
    else
        fail "guest curl could not complete the chat request (status=$code)"
    fi

    # The one audit line must name the method and path as well as the decision:
    # a bare "decision=substitute" would also match the /models case.
    if grep -Eq "^audit .*ingress=transparent .*name=ds-vm host=api\.deepseek\.com:443 method=POST path=/chat/completions status=200 decision=substitute" "$DAEMON_ERR"; then
        pass "audit records the chat request as a POST substitution on ds-vm"
    else
        fail "chat request not audited as a POST substitution"
    fi

    # The key stays in a file: no command line or shell variable holds it.
    if log_carries_value_from "$DS_KEY_PATH"; then
        fail "daemon log carries the real API key"
    else
        pass "daemon log never carries the real API key"
    fi

    # Negative control: the same token, sent from the host straight to the API
    # with no proxy in the path, must be rejected. That is what makes the 200
    # above evidence of substitution rather than of a working credential.
    local direct
    direct=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
        -H "Authorization: Bearer $token" https://api.deepseek.com/models) || direct=000
    if [ "$direct" = "401" ]; then
        pass "the guest's token is rejected by the API when sent directly (401)"
    else
        fail "direct use of the token was not rejected (status=$direct)"
    fi
}

# ----------------------------------------------------------------------- main
preflight
note "workdir $WORK"
start_store
start_daemon

grep -q "capture .* on $VM_LISTEN" "$DAEMON_ERR" \
    || { tail -20 "$DAEMON_ERR"; fail "daemon did not install capture rules"; exit 1; }
pass "transparent listener $VM_LISTEN bound and capture rules installed"
iptables -t nat -S CREDSVAULT_PREROUTING 2>/dev/null | grep -q "DNAT --to-destination $VM_LISTEN" \
    && pass "CREDSVAULT_PREROUTING DNATs 443 -> $VM_LISTEN" \
    || fail "capture chain has no DNAT to $VM_LISTEN"

# The daemon generates the CA on first start; export only its certificate.
"$BIN_DIR/credclient" --mgmt-socket "$MGMT_SOCK" dump --format json | python3 -c '
import json, sys
doc = json.load(sys.stdin)
ca = (doc.get("config") or {}).get("ca") or {}
cert = ca.get("cert")
if not cert:
    sys.exit("no CA in dump")
sys.stdout.write(cert if cert.endswith("\n") else cert + "\n")
' >"$WORK/ca.pem" || { fail "cannot export the daemon CA"; exit 1; }
pass "CA exported from the daemon ($(grep -c 'BEGIN CERTIFICATE' "$WORK/ca.pem") cert)"

# The real value goes in on stdin, so it never appears on a command line.
REAL=$(openssl rand -hex 16)
ADD_JSON=$(printf '%s' "$REAL" | "$BIN_DIR/credclient" --mgmt-socket "$MGMT_SOCK" credential add \
    --name vm-https --user-id u-vm --user-name alice --allow-host "$BOUND_HOST")
TOKEN=$(printf '%s' "$ADD_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["fake_cred"])')
pass "credential added (guest holds only the fakecred)"

# git over HTTPS: the fakecred goes in the Basic password position. With a
# credential file the real value is the token/password; without it a random
# invalid value keeps the substitution path testable as a negative case.
if [ -n "$GIT_CRED_FILE" ]; then
    GIT_JSON=$("$BIN_DIR/credclient" --mgmt-socket "$MGMT_SOCK" credential add \
        --name git-atomgit --user-id u-vm --user-name alice --allow-host "$GIT_HOST" \
        --value-file "$GIT_CRED_FILE")
else
    GIT_JSON=$(openssl rand -hex 16 | "$BIN_DIR/credclient" --mgmt-socket "$MGMT_SOCK" credential add \
        --name git-atomgit --user-id u-vm --user-name alice --allow-host "$GIT_HOST")
fi
GIT_TOKEN=$(printf '%s' "$GIT_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["fake_cred"])')
pass "git credential added (bound to $GIT_HOST)"

DS_KEY=$(cat "$DS_KEY_PATH") || DS_KEY=""
[ -n "$DS_KEY" ] || { fail "hardcoded DS_API_KEY is empty"; exit 1; }
DS_JSON=$("$BIN_DIR/credclient" --mgmt-socket "$MGMT_SOCK" credential add \
    --name ds-vm --user-id u-vm --user-name alice --allow-host "api.deepseek.com" \
    --value-file "$DS_KEY_PATH")
DS_TOKEN=$(printf '%s' "$DS_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["fake_cred"])')
pass "real-API credential added (hardcoded key)"

# Same destination and binding, bogus real value. Substitution still
# happens, so a 401 proves the API rejected the substituted value rather
# than the fakecred being forwarded.
BAD_REAL="sk-$(openssl rand -hex 16)"
DS_BAD_JSON=$(printf '%s' "$BAD_REAL" | "$BIN_DIR/credclient" --mgmt-socket "$MGMT_SOCK" credential add \
    --name ds-bad --user-id u-vm --user-name alice --allow-host "api.deepseek.com")
DS_BAD_TOKEN=$(printf '%s' "$DS_BAD_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["fake_cred"])')
pass "invalid-credential entry added (ds-bad, random real value)"

# Guest trust: the CA exported from the daemon is the one that signs MITM leaves.
scp "${SSH_OPTS[@]}" -q "$WORK/ca.pem" "$GUEST:$GUEST_CA"
guest "update-ca-trust extract"
GUEST_CA_INSTALLED=1
pass "guest trusts the MITM CA"

BOUND_IP=$(guest "getent ahostsv4 $BOUND_HOST | awk 'NR==1{print \$1}'") || BOUND_IP=""
[ -n "$BOUND_IP" ] || BOUND_IP=$(getent ahostsv4 "$BOUND_HOST" | awk 'NR==1{print $1}') || BOUND_IP=""
[ -n "$BOUND_IP" ] || { fail "cannot resolve $BOUND_HOST on the guest or the host"; exit 1; }
note "pinned $BOUND_HOST -> $BOUND_IP"

assert_substitution "$TOKEN" "$REAL"
assert_passthrough "$TOKEN"
assert_original_dst "$BOUND_IP"
assert_host_sni_mismatch
assert_direct_dial_rejected
assert_audit "$REAL"
assert_non_443_not_captured
assert_git_over_https "$GIT_TOKEN"
assert_real_api "$DS_TOKEN"
assert_real_api_chat "$DS_TOKEN"
assert_invalid_credential "$DS_BAD_TOKEN"
UNREGISTERED_TOKEN="fcred-$(openssl rand -hex 16)"
assert_unregistered_token "$UNREGISTERED_TOKEN"
assert_real_key_passthrough
assert_real_key_direct

if [ "$FAILED" -ne 0 ]; then
    echo "RESULT: FAILED"
    exit 1
fi
echo "RESULT: OK"
