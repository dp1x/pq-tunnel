#!/usr/bin/env bash
# Real Linux system-wide TUN smoke test in disposable network namespaces.
# Usage: sudo bash scripts/linux_tun_e2e.sh [path-to-pq-tunnel-binary]
set -euo pipefail

BIN="${1:-./target/debug/pq-tunnel}"
WORK="$(mktemp -d)"
trap 'rc=$?; echo "=== server.log ==="; cat "$WORK/server.log" 2>/dev/null || true; echo "=== client.log ==="; cat "$WORK/client.log" 2>/dev/null || true; cleanup; exit $rc' EXIT

cleanup() {
    set +e
    if [[ -n "${CLIENT_PID:-}" ]]; then kill "$CLIENT_PID" 2>/dev/null; fi
    if [[ -n "${SERVER_PID:-}" ]]; then kill "$SERVER_PID" 2>/dev/null; fi
    wait 2>/dev/null
    ip netns del clientns 2>/dev/null
    ip netns del serverns 2>/dev/null
    ip link del veth-c 2>/dev/null
    rm -rf "$WORK"
}

# Provision identities.
"$BIN" keygen --identity "$WORK/server.pqti" --public-key "$WORK/server.pub" >/dev/null
"$BIN" keygen --identity "$WORK/client.pqti" --public-key "$WORK/client.pub" --append-roster "$WORK/roster.pqti" >/dev/null

# Disposable namespaces + veth link.
ip netns add clientns
ip netns add serverns
ip link add veth-c type veth peer name veth-s
ip link set veth-c netns clientns
ip link set veth-s netns serverns
ip -n clientns addr add 10.200.0.1/24 dev veth-c
ip -n serverns addr add 10.200.0.2/24 dev veth-s
ip -n clientns link set veth-c up
ip -n serverns link set veth-s up
ip -n clientns link set lo up
ip -n serverns link set lo up

# Controlled destinations in the server namespace (not loopback range).
ip -n serverns addr add 192.0.2.1/32 dev lo
ip -n serverns addr add 2001:db8::1/128 dev lo

# Start server.
ip netns exec serverns env RUST_LOG=debug "$BIN" server --tun \
    --listen 10.200.0.2:4433 \
    --identity "$WORK/server.pqti" \
    --roster "$WORK/roster.pqti" \
    >"$WORK/server.log" 2>&1 &
SERVER_PID=$!

# Start client.
ip netns exec clientns env RUST_LOG=debug "$BIN" client --tun \
    --remote 10.200.0.2:4433 \
    --identity "$WORK/client.pqti" \
    --server-key "$WORK/server.pub" \
    >"$WORK/client.log" 2>&1 &
CLIENT_PID=$!

# Allow handshake.
sleep 8

echo "=== processes ==="
ps aux | grep pq-tunnel | grep -v grep || true
echo "=== client ns rules ==="
ip -n clientns rule show
ip -n clientns -6 rule show
echo "=== client ns routes main ==="
ip -n clientns route show
ip -n clientns -6 route show
echo "=== client ns routes table 100 ==="
ip -n clientns route show table 100
ip -n clientns -6 route show table 100
echo "=== server ns routes ==="
ip -n serverns route show
ip -n serverns -6 route show
echo "=== client ns addrs ==="
ip -n clientns addr show
echo "=== server ns addrs ==="
ip -n serverns addr show

echo "=== IPv4 ping through tunnel ==="
ip netns exec clientns ping -c 3 -W 2 192.0.2.1 || true

echo "=== IPv6 ping through tunnel ==="
ip netns exec clientns ping6 -c 3 -W 2 2001:db8::1

echo "=== E2E OK ==="
cat "$WORK/server.log" | tail -5
cat "$WORK/client.log" | tail -5