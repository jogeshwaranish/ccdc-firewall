#!/bin/sh
# Integration test for linux/ccdc-fw.sh. Runs it inside a throwaway network
# namespace and checks real connections from a second namespace, so the host's
# own firewall is never touched.
#
#   sh tests/netns-test.sh [nft|iptables]           rootless (user namespace)
#   sudo sh tests/netns-test.sh [nft|iptables]      as root (CI)
set -eu

BE=${1:-nft}
HERE=$(cd "$(dirname "$0")" && pwd)
FW="$HERE/../linux/ccdc-fw.sh"

if [ "${CCDC_TEST_INNER:-}" != 1 ]; then
	export CCDC_TEST_INNER=1
	if [ "$(id -u)" = 0 ]; then exec unshare -n sh "$0" "$BE"; fi
	exec unshare -rn sh "$0" "$BE"
fi

WORK=$(mktemp -d)
export CCDC_FW_DIR="$WORK/state"
PIDS=""
# shellcheck disable=SC2329  # used by the trap below
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null || true; done; rm -rf "$WORK"; }
trap cleanup EXIT

# Client namespace joined to ours by a veth pair: 10.99.0.1 (server) <-> 10.99.0.2 (client).
ip link set lo up
unshare -n sleep 600 & CPID=$!; PIDS="$PIDS $CPID"
sleep 0.3
ip link add v0 type veth peer name v1
ip link set v1 netns "$CPID"
ip addr add 10.99.0.1/24 dev v0
ip link set v0 up
nsenter -t "$CPID" -n sh -c 'ip link set lo up; ip addr add 10.99.0.2/24 dev v1; ip link set v1 up'

listen() { # name port
	ln -sf "$(command -v python3)" "$WORK/$1"
	"$WORK/$1" -c "import socket,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', $2)); s.listen(8)
while True:
    c,_=s.accept(); c.close()" &
	PIDS="$PIDS $!"
}
mkdir -p "$WORK/srv"
listen httpd 80          # known port            -> allow
listen node 3000         # known server process  -> allow
listen python3 9999      # unknown               -> blocked with --yes
listen nc 4444           # netcat-looking        -> blocked as suspicious
sleep 0.5

can() { # port -> 0 if the client can connect
	nsenter -t "$CPID" -n python3 -c "import socket,sys
s=socket.socket(); s.settimeout(1)
sys.exit(s.connect_ex(('10.99.0.1', $1)))" 2>/dev/null
}
FAIL=0
expect() { # open|closed port label
	if can "$2"; then got=open; else got=closed; fi
	if [ "$got" = "$1" ]; then echo "  ok   $3: $2 $got"; else echo "  FAIL $3: $2 is $got, expected $1"; FAIL=1; fi
}
state() { sed -n "s/^STATUS=//p" "$CCDC_FW_DIR/state" | tail -n 1; }
check_state() { if [ "$(state)" = "$1" ]; then echo "  ok   status $1"; else echo "  FAIL status is $(state), expected $1"; FAIL=1; fi; }

echo "== backend: $BE"
echo "-- baseline (no rules)"
for p in 80 3000 9999 4444; do expect open $p baseline; done

echo "-- scan is read-only"
sh "$FW" scan -b "$BE" > "$WORK/scan.out" 2>&1
if grep -q '4444 .*DENY.*SUSPICIOUS' "$WORK/scan.out"; then echo "  ok   scan flags nc"; else echo "  FAIL scan output:"; cat "$WORK/scan.out"; FAIL=1; fi
expect open 9999 after-scan

echo "-- apply --yes, confirm"
sh "$FW" apply -y -b "$BE" < /dev/null > "$WORK/apply.out" 2>&1 || { cat "$WORK/apply.out"; exit 1; }
check_state pending
"$CCDC_FW_DIR/ccdc-fw.sh" confirm > /dev/null
check_state confirmed
expect open 80 apply; expect open 3000 apply; expect closed 9999 apply; expect closed 4444 apply

echo "-- re-apply with --allow 9999, then revert to the previous rules"
sh "$FW" apply -y -b "$BE" -a 9999 < /dev/null > /dev/null 2>&1
expect open 9999 allow
"$CCDC_FW_DIR/ccdc-fw.sh" revert > /dev/null
check_state confirmed
expect closed 9999 revert; expect open 80 revert

echo "-- rollback timer fires when not confirmed"
sh "$FW" apply -y -b "$BE" -d 80 -r 2 < /dev/null > /dev/null 2>&1
expect closed 80 pending
sleep 4
check_state confirmed
expect open 80 after-timer

echo "-- enforce restores flushed rules"
"$CCDC_FW_DIR/ccdc-fw.sh" enforce
if [ "$BE" = nft ]; then nft delete table inet ccdc_fw; else iptables -D INPUT -j CCDC_IN; iptables -I INPUT 1 -j ACCEPT; fi
expect open 9999 tampered
"$CCDC_FW_DIR/ccdc-fw.sh" enforce
if grep -q TAMPER "$CCDC_FW_DIR/ccdc-fw.log"; then echo "  ok   tamper logged"; else echo "  FAIL no tamper log"; FAIL=1; fi
[ "$BE" = iptables ] && iptables -D INPUT -j ACCEPT
expect closed 9999 enforced; expect open 80 enforced

echo "-- off removes everything"
"$CCDC_FW_DIR/ccdc-fw.sh" off > /dev/null
expect open 9999 off; expect open 4444 off

[ $FAIL = 0 ] && echo "PASS ($BE)" || echo "FAILED ($BE)"
exit $FAIL
