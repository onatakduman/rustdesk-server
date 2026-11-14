#!/usr/bin/env bash
# Runs secure_tcp_probe against throwaway hbbs instances on this machine.
# Each instance gets an empty working directory, so it makes its own key pair
# and database there, and both are deleted afterwards.
#
#   secure_tcp_test.sh <patched hbbs> <stock hbbs> <secure_tcp_probe> [address]
#
# The address defaults to 127.0.0.1. Given another address of this machine, the
# nat check also covers the NAT test port, which is the admin console on 127.0.0.1.
set -u
PATCHED=$(realpath "$1")
STOCK=$(realpath "$2")
PROBE=$(realpath "$3")
addr=${4:-127.0.0.1}
# hbbs also reads its options from the environment (KEY, PORT, ...), so the
# variables here are named differently and none of them is exported.
port=31116
failed=0

start_hbbs() { # <binary> [hbbs arguments]
    local bin=$1
    shift
    port=$((port + 10))
    WORK=$(mktemp -d)
    (cd "$WORK" && exec "$bin" -p "$port" "$@") >"$WORK/hbbs.log" 2>&1 &
    PID=$!
    for _ in $(seq 100); do
        grep -q ' Start$' "$WORK/hbbs.log" && break
        sleep 0.1
    done
    pubkey=$(cat "$WORK/id_ed25519.pub")
    echo "--- started: $(basename "$bin") -p $port $*   (server public key: $pubkey)"
}

stop_hbbs() {
    kill "$PID"
    wait "$PID" 2>/dev/null
    echo "--- hbbs log:"
    grep -v -e 'update_pk' "$WORK/hbbs.log" | sed 's/^/    /'
    rm -rf "$WORK"
    echo
}

check() { # <expected exit code> <probe mode> <title>
    local want=$1 mode=$2
    shift 2
    echo "[$*]"
    echo "  \$ secure_tcp_probe $mode $addr:$port <server public key>"
    "$PROBE" "$mode" "$addr:$port" "$pubkey"
    local got=$?
    if [ "$got" = "$want" ]; then
        echo "  => exit $got, as expected"
    else
        echo "  => exit $got, EXPECTED $want"
        failed=1
    fi
    echo
}

echo "===== patched hbbs, started the usual way (-k _ -r <relay>)"
start_hbbs "$PATCHED" -k _ -r 127.0.0.1:21117
check 0 secure "a+b: KeyExchange on accept, then an encrypted request and response"
check 0 plain "c: plain request without a handshake"
check 0 bad "extra: malformed key exchange answers"
check 0 nat "extra: NAT type test in plain"
check 0 ws "extra: WebSocket port"
check 0 e2e-secure "extra: punch hole and relay rounds, controlling side on secure TCP"
check 0 e2e-plain "extra: punch hole and relay rounds, controlling side in plain"
stop_hbbs

echo "===== patched hbbs without -k (the key is enforced by default)"
start_hbbs "$PATCHED"
check 0 secure "a+b again"
stop_hbbs

echo "===== patched hbbs with an empty key (-k ''): no key, no offer"
start_hbbs "$PATCHED" -k ''
check 1 secure "no KeyExchange expected, the probe waits out the client's 18 s READ_TIMEOUT"
check 0 plain "plain request"
stop_hbbs

echo "===== control: stock 1.1.16 hbbs (-k _ -r <relay>)"
start_hbbs "$STOCK" -k _ -r 127.0.0.1:21117
check 1 secure "d: no KeyExchange arrives, the probe waits out the client's 18 s READ_TIMEOUT"
check 0 plain "baseline: plain request"
check 0 nat "baseline: NAT type test in plain"
check 0 ws "baseline: WebSocket port"
check 0 e2e-plain "baseline: punch hole and relay rounds in plain"
stop_hbbs

if [ "$failed" = 0 ]; then
    echo "ALL CHECKS AS EXPECTED"
else
    echo "SOME CHECKS NOT AS EXPECTED"
fi
exit "$failed"
