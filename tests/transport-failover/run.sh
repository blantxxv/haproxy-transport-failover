#!/bin/bash
#
# Integration tests for the server transport failover feature.
#
# Three network namespaces are wired with veth pairs:
#
#      ns-tf-cli                ns-tf-hap                 ns-tf-node
#    10.10.1.1/24  <--veth-->  10.10.1.2/24
#                              10.10.2.1/24  <--veth-->  10.10.2.2/24
#      (curl)                   (haproxy)                 (tcp + quic)
#
# The node offers the same service over two transports: plain TCP on
# 10.10.2.2:4443 and QUIC on 10.10.2.2:4443/udp. Each answers with a different
# body so that the transport actually used for the backend connection can be
# told apart from the client side. HAProxy runs in the middle with a backend
# using TCP as its primary transport and QUIC as its fallback transport.
#
# Failures are injected with nftables and tc netem inside the node namespace,
# and every verdict about the transport in use is confirmed at the packet level
# with tcpdump, not only with HAProxy's own logs.
#
# Requirements: root, ip, nft, tc, tcpdump, socat, curl and a haproxy binary
# built with USE_QUIC=1.
#
# Usage: ./run.sh [test-number ...]     (default: all tests)
#        ./run.sh demo                  (narrated walk through the life cycle)

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
HAPROXY=${HAPROXY:-$HERE/../../haproxy}
RUNDIR=${RUNDIR:-/tmp/tf-test}
ARTIFACTS=$RUNDIR/artifacts

NS_CLI=ns-tf-cli
NS_HAP=ns-tf-hap
NS_NODE=ns-tf-node

CLI_IP=10.10.1.1
HAP_IP_CLI=10.10.1.2
HAP_IP_NODE=10.10.2.1
NODE_IP=10.10.2.2

FE_PORT=8080
SVC_PORT=4443
# Health checks are given their own ports so that the captures taken on the
# service port only contain data plane traffic. Failure injection blocks the
# service and the check port of a transport together, since what is simulated
# is a whole transport being unusable on the path.
CHK_PORT_TCP=4444
CHK_PORT_QUIC=4445

CLI_SOCK=$RUNDIR/haproxy.sock

# state machine tuning used by the tests, kept small to keep them fast
TF_FALL=3
TF_RISE=3
TF_PROBE=1s
TF_HOLD=5s
CHK_INTER=1s
CHK_FALL=2
CHK_RISE=1

PASS=0
FAIL=0
FAILED_TESTS=""

say()  { printf '%s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
head1() { printf '\n=== %s ===\n' "$*"; }

nsx()  { ip netns exec "$@"; }

die() { printf 'FATAL: %s\n' "$*" >&2; exit 2; }

# ---------------------------------------------------------------- environment

check_reqs()
{
	local missing=
	for t in ip nft tc tcpdump socat curl awk; do
		command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
	done
	[ -z "$missing" ] || die "missing tools:$missing"
	[ "$(id -u)" = 0 ] || die "must run as root (network namespaces)"
	[ -x "$HAPROXY" ] || die "haproxy binary not found or not executable: $HAPROXY"
	"$HAPROXY" -vv 2>/dev/null | grep -q '+QUIC' || die "$HAPROXY was not built with USE_QUIC=1"
}

cleanup()
{
	local ns
	pkill -f "tcpdump -i tf-node" >/dev/null 2>&1
	pkill -f "$RUNDIR/" >/dev/null 2>&1
	for ns in $NS_CLI $NS_HAP $NS_NODE; do
		ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null
		ip netns del "$ns" 2>/dev/null
	done
	# veth are deleted along with their namespaces
	ip link del tf-cli 2>/dev/null
	ip link del tf-hap2 2>/dev/null
	return 0
}

setup_net()
{
	cleanup
	mkdir -p "$RUNDIR" "$ARTIFACTS"

	ip netns add $NS_CLI  || die "cannot create $NS_CLI"
	ip netns add $NS_HAP  || die "cannot create $NS_HAP"
	ip netns add $NS_NODE || die "cannot create $NS_NODE"

	# client <-> haproxy
	ip link add tf-cli type veth peer name tf-hap1
	ip link set tf-cli  netns $NS_CLI
	ip link set tf-hap1 netns $NS_HAP

	# haproxy <-> node
	ip link add tf-hap2 type veth peer name tf-node
	ip link set tf-hap2 netns $NS_HAP
	ip link set tf-node netns $NS_NODE

	nsx $NS_CLI  ip addr add $CLI_IP/24      dev tf-cli
	nsx $NS_HAP  ip addr add $HAP_IP_CLI/24  dev tf-hap1
	nsx $NS_HAP  ip addr add $HAP_IP_NODE/24 dev tf-hap2
	nsx $NS_NODE ip addr add $NODE_IP/24     dev tf-node

	for ns in $NS_CLI $NS_HAP $NS_NODE; do
		nsx $ns ip link set lo up
	done
	nsx $NS_CLI  ip link set tf-cli  up
	nsx $NS_HAP  ip link set tf-hap1 up
	nsx $NS_HAP  ip link set tf-hap2 up
	nsx $NS_NODE ip link set tf-node up

	# nftables table used by the failure injection helpers
	nsx $NS_NODE nft add table inet tf 2>/dev/null
	nsx $NS_NODE nft add chain inet tf input '{ type filter hook input priority 0; }' 2>/dev/null

	nsx $NS_CLI ping -c1 -W2 $HAP_IP_CLI >/dev/null 2>&1 || die "client cannot reach haproxy ns"
	nsx $NS_HAP ping -c1 -W2 $NODE_IP    >/dev/null 2>&1 || die "haproxy ns cannot reach node ns"
}

gen_certs()
{
	[ -f "$RUNDIR/node.pem" ] && return 0
	openssl req -x509 -newkey rsa:2048 -keyout "$RUNDIR/node.key" \
	        -out "$RUNDIR/node.crt" -days 3 -nodes -subj "/CN=node.tf.test" \
	        -addext "subjectAltName=DNS:node.tf.test,IP:$NODE_IP" >/dev/null 2>&1 \
		|| die "cannot generate the test certificate"
	cat "$RUNDIR/node.crt" "$RUNDIR/node.key" > "$RUNDIR/node.pem"
}

gen_configs()
{
	cat > "$RUNDIR/node.cfg" <<EOF
global
    daemon
    pidfile $RUNDIR/node.pid
    log stdout format raw local0 notice

defaults
    mode http
    timeout connect 3s
    timeout client 15s
    timeout server 15s

# the node reached over plain TCP
frontend tcp_in
    bind $NODE_IP:$SVC_PORT
    http-request return status 200 content-type text/plain string "via-tcp\n"

# the very same node reached over QUIC
frontend quic_in
    bind quic4@$NODE_IP:$SVC_PORT ssl crt $RUNDIR/node.pem alpn h3
    http-request return status 200 content-type text/plain string "via-quic\n"

# health check endpoints, one per transport, on their own ports
frontend tcp_chk
    bind $NODE_IP:$CHK_PORT_TCP
    http-request return status 200 content-type text/plain string "tcp-check\n"

frontend quic_chk
    bind quic4@$NODE_IP:$CHK_PORT_QUIC ssl crt $RUNDIR/node.pem alpn h3
    http-request return status 200 content-type text/plain string "quic-check\n"
EOF

	cat > "$RUNDIR/haproxy.cfg" <<EOF
global
    expose-experimental-directives
    stats socket $CLI_SOCK mode 600 level admin
    stats timeout 1h
    log stdout format raw local0 info

defaults
    log global
    mode http
    option httplog
    timeout connect 1s
    timeout client 15s
    timeout server 15s
    retries 2

frontend fe
    bind $HAP_IP_CLI:$FE_PORT
    default_backend nodes

# Fallback transport: the same node over QUIC.
#
# This server intentionally has no health check of its own, for two reasons:
# it keeps the QUIC packets seen on the service port limited to the data plane,
# which is what the packet level verification needs, and it exercises the other
# source of fallback health, namely the failures observed on live traffic.
# Upstream forces a health check to plain TCP as soon as "port" or "addr" is
# set on the server line, so a QUIC check cannot use a dedicated port.
backend nodes_quic
    timeout connect 2s
    http-reuse never
    server n1 quic4@$NODE_IP:$SVC_PORT ssl verify none alpn h3

# primary transport: TCP, with the QUIC endpoint as its fallback transport.
# "http-reuse never" is only there to make the packet level verification
# deterministic: every client request then opens a new backend connection,
# which is what the captures are meant to observe.
backend nodes
    http-reuse never
    server n1 $NODE_IP:$SVC_PORT check port $CHK_PORT_TCP inter $CHK_INTER fall $CHK_FALL rise $CHK_RISE fallback-transport nodes_quic/n1 transport-fall $TF_FALL transport-rise $TF_RISE transport-probe $TF_PROBE transport-hold $TF_HOLD
EOF
}

start_stack()
{
	nsx $NS_NODE "$HAPROXY" -f "$RUNDIR/node.cfg" > "$RUNDIR/node.log" 2>&1 \
		|| die "cannot start the node"
	nsx $NS_HAP "$HAPROXY" -f "$RUNDIR/haproxy.cfg" > "$RUNDIR/haproxy.log" 2>&1 &
	HAP_PID=$!
	local i
	for i in $(seq 1 50); do
		[ -S "$CLI_SOCK" ] && break
		sleep 0.2
	done
	[ -S "$CLI_SOCK" ] || die "haproxy did not start, see $RUNDIR/haproxy.log"
	# let both health checks settle
	wait_state PRIMARY_ACTIVE 10 || die "initial state is not PRIMARY_ACTIVE"
}

restart_node()
{
	nsx $NS_NODE "$HAPROXY" -f "$RUNDIR/node.cfg" >> "$RUNDIR/node.log" 2>&1
}

# ------------------------------------------------------------------- helpers

cli() { echo "$1" | socat -t2 - "UNIX-CONNECT:$CLI_SOCK" 2>/dev/null; }

tf_field()
{
	cli "show servers transport nodes" | awk -v k="$1" '
		/^nodes\/n1/ { for (i = 1; i <= NF; i++) { split($i, a, "="); if (a[1] == k) { print a[2]; exit } } }'
}

srv_status()
{
	cli "show stat" | awk -F, -v be="$1" -v sv="$2" '$1 == be && $2 == sv { print $18 }'
}

# waits until the state machine reaches <state>, at most <timeout> seconds
wait_state()
{
	local want=$1 timeout=$2 i
	for i in $(seq 1 $((timeout * 5))); do
		[ "$(tf_field state)" = "$want" ] && return 0
		sleep 0.2
	done
	return 1
}

# performs one request from the client namespace and prints the body
req()
{
	nsx $NS_CLI curl -s --max-time 5 "http://$HAP_IP_CLI:$FE_PORT/" 2>/dev/null
}

# performs <n> requests and prints the tally, e.g. "via-quic:5"
req_tally()
{
	local n=$1 i out=
	for i in $(seq 1 "$n"); do
		out="$out$(req)
"
	done
	printf '%s' "$out" | sed '/^$/d' | sort | uniq -c | awk '{printf "%s:%s ", $2, $1}'
}

# ------------------------------------------------------- failure injection

# a transport is blocked as a whole: its service port and its check port
block_tcp_drop()
{
	nsx $NS_NODE nft add rule inet tf input tcp dport \
	    "{ $SVC_PORT, $CHK_PORT_TCP }" drop
}

block_tcp_reset()
{
	nsx $NS_NODE nft add rule inet tf input tcp dport \
	    "{ $SVC_PORT, $CHK_PORT_TCP }" reject with tcp reset
}

block_udp()
{
	nsx $NS_NODE nft add rule inet tf input udp dport \
	    "{ $SVC_PORT, $CHK_PORT_QUIC }" drop
}

unblock_all()      { nsx $NS_NODE nft flush chain inet tf input; }

netem_loss()       { nsx $NS_NODE tc qdisc add dev tf-node root netem loss "$1"; }
netem_clear()      { nsx $NS_NODE tc qdisc del dev tf-node root 2>/dev/null; return 0; }

# ------------------------------------------------------ packet level checks

# starts a capture on the node side; $1 = tag used for the pcap file name
cap_start()
{
	CAP_FILE=$ARTIFACTS/$1.pcap
	CAP_ERR=$RUNDIR/tcpdump-$1.err
	CAP_PIDFILE=$RUNDIR/tcpdump-$1.pid
	rm -f "$CAP_FILE" "$CAP_ERR" "$CAP_PIDFILE"

	# "ip netns exec" forks, so the pid of the background job is not the one
	# of tcpdump. The wrapper shell publishes its own pid then execs into
	# tcpdump, which keeps that pid, and pids are not namespaced anyway.
	# -U writes each packet as it arrives rather than by full buffers.
	# --immediate-mode delivers packets to tcpdump as soon as they arrive
	# instead of waiting for the kernel buffer timeout, otherwise a short
	# capture may be killed before having read anything.
	nsx $NS_NODE sh -c "echo \$\$ > $CAP_PIDFILE; exec tcpdump -i tf-node -nn -s 96 -U --immediate-mode -w $CAP_FILE 'port $SVC_PORT'" \
	     >/dev/null 2>"$CAP_ERR" &

	# do not send any traffic before the capture is attached to the
	# interface, otherwise the first packets are missed
	local i
	for i in $(seq 1 80); do
		grep -q 'listening on' "$CAP_ERR" 2>/dev/null && break
		sleep 0.1
	done
	sleep 0.3
}

cap_stop()
{
	local pid i
	[ -n "${CAP_PIDFILE:-}" ] && [ -s "$CAP_PIDFILE" ] || return 0
	pid=$(cat "$CAP_PIDFILE")
	# leave enough time for the last packets to reach the capture file
	sleep 1.2
	kill "$pid" 2>/dev/null
	# wait for tcpdump to flush and exit, so the capture can be read safely
	for i in $(seq 1 50); do
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
	done
	rm -f "$CAP_PIDFILE"
}

# counts TCP SYNs (connection attempts) seen in the last capture
cap_tcp_syns()
{
	tcpdump -r "$CAP_FILE" -nn "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 and dst port $SVC_PORT" \
	        2>/dev/null | wc -l
}

# counts UDP datagrams towards the service port, i.e. QUIC traffic
cap_udp_pkts()
{
	tcpdump -r "$CAP_FILE" -nn "udp and dst port $SVC_PORT" 2>/dev/null | wc -l
}

# total number of packets in the last capture, used for diagnostics
cap_total()
{
	tcpdump -r "$CAP_FILE" -nn 2>/dev/null | wc -l
}

# --------------------------------------------------------------- assertions

ok()   { PASS=$((PASS + 1)); printf '    [ OK ] %s\n' "$*"; }
nok()  { FAIL=$((FAIL + 1)); printf '    [FAIL] %s\n' "$*"; }

assert_eq()
{
	if [ "$2" = "$3" ]; then ok "$1 ($2)"; else nok "$1: expected '$3', got '$2'"; fi
}

assert_ge()
{
	if [ "$2" -ge "$3" ] 2>/dev/null; then ok "$1 ($2 >= $3)"
	else nok "$1: expected >= $3, got $2"; fi
}

assert_le()
{
	if [ "$2" -le "$3" ] 2>/dev/null; then ok "$1 ($2 <= $3)"
	else nok "$1: expected <= $3, got $2"; fi
}

assert_body()
{
	local want=$1 got
	got=$(req)
	if [ "$got" = "$want" ]; then ok "request served $want"
	else nok "request: expected '$want', got '${got:-<empty>}'"; fi
}

start_test() { CUR_TEST=$1; head1 "Test $1: $2"; }
end_test()
{
	local before=$1
	if [ "$FAIL" -ne "$before" ]; then
		FAILED_TESTS="$FAILED_TESTS $CUR_TEST"
		save_artifacts "test$CUR_TEST"
	fi
}

save_artifacts()
{
	local tag=$1
	local d=$ARTIFACTS/$tag
	mkdir -p "$d"
	cp -f "$RUNDIR/haproxy.cfg" "$RUNDIR/node.cfg" "$d/" 2>/dev/null
	cp -f "$RUNDIR/haproxy.log" "$RUNDIR/node.log" "$d/" 2>/dev/null
	cli "show servers transport" > "$d/servers-transport.txt" 2>/dev/null
	cli "show stat"              > "$d/stats.csv" 2>/dev/null
	nsx $NS_NODE nft list table inet tf > "$d/nft.txt" 2>/dev/null
	info "artifacts saved in $d"
}

# ------------------------------------------------------------------- tests

test1()   # TCP works, UDP works -> TCP is used
{
	local f=$FAIL
	start_test 1 "both transports available, TCP must be used"
	cap_start t1
	assert_body "via-tcp"
	assert_eq "state" "$(tf_field state)" "PRIMARY_ACTIVE"
	assert_eq "current transport" "$(tf_field current)" "primary"
	cap_stop
	info "captured: $(cap_total) packets total on the node link"
	assert_ge "TCP connection attempts captured" "$(cap_tcp_syns)" 1
	assert_eq "QUIC datagrams captured" "$(cap_udp_pkts)" 0
	end_test $f
}

test2()   # only TCP blocked -> fallback after the threshold
{
	local f=$FAIL
	start_test 2 "TCP blocked, UDP left intact, must fail over to QUIC"
	block_tcp_drop
	info "nft: tcp dport $SVC_PORT drop"
	if wait_state FALLBACK_ACTIVE 15; then ok "reached FALLBACK_ACTIVE"
	else nok "did not reach FALLBACK_ACTIVE within 15s"; fi
	cap_start t2
	assert_body "via-quic"
	assert_eq "current transport" "$(tf_field current)" "fallback"
	assert_ge "transport switches" "$(tf_field switches)" 1
	cap_stop
	assert_ge "QUIC datagrams captured" "$(cap_udp_pkts)" 1
	assert_eq "new TCP connection attempts" "$(cap_tcp_syns)" 0
	end_test $f
}

test3()   # TCP restored -> comes back after rise + hold-down
{
	local f=$FAIL
	start_test 3 "TCP restored, must come back only after rise and hold-down"
	# get onto the fallback transport first, this test must not depend on
	# the state left behind by another one
	block_tcp_drop
	if wait_state FALLBACK_ACTIVE 20; then ok "moved to the fallback transport"
	else nok "could not reach FALLBACK_ACTIVE"; fi

	local t0 t1 elapsed
	t0=$(date +%s)
	unblock_all
	info "nft flushed, TCP reachable again"
	# right after unblocking, traffic must still use the fallback transport
	local cur_now
	cur_now=$(tf_field current)
	if [ "$cur_now" = "fallback" ]; then ok "still on fallback right after TCP came back"
	else nok "returned to the primary transport immediately, hysteresis missing"; fi
	if wait_state PRIMARY_ACTIVE 20; then
		t1=$(date +%s)
		elapsed=$((t1 - t0))
		ok "returned to PRIMARY_ACTIVE after ${elapsed}s"
		# transport-rise probes at transport-probe intervals are required,
		# so coming back cannot be instantaneous
		assert_ge "time spent probing before coming back" "$elapsed" 2
	else
		nok "did not return to PRIMARY_ACTIVE within 20s"
	fi
	cap_start t3
	assert_body "via-tcp"
	cap_stop
	assert_ge "TCP connection attempts captured" "$(cap_tcp_syns)" 1
	end_test $f
}

test4()   # packet loss must not trigger a switch
{
	local f=$FAIL
	start_test 4 "moderate TCP packet loss must not trigger a switch"
	local sw_before
	sw_before=$(tf_field switches)
	netem_loss "12%"
	info "tc netem loss 12% on the node link"
	local i served=0
	for i in $(seq 1 12); do
		[ "$(req)" = "via-tcp" ] && served=$((served + 1))
		sleep 0.4
	done
	netem_clear
	info "requests served over TCP despite loss: $served/12"
	assert_eq "switches during loss" "$(tf_field switches)" "$sw_before"
	assert_ge "requests still served over TCP" "$served" 6
	wait_state PRIMARY_ACTIVE 10 >/dev/null
	end_test $f
}

test5()   # blackhole: SYN sent, nothing comes back -> connect timeout
{
	local f=$FAIL
	start_test 5 "TCP blackhole (SYN dropped), failover through connect timeout"
	local t0 t1
	t0=$(date +%s)
	block_tcp_drop
	if wait_state FALLBACK_ACTIVE 20; then
		t1=$(date +%s)
		ok "failed over in $((t1 - t0))s through connect timeout"
	else
		nok "did not fail over within 20s"
	fi
	assert_body "via-quic"
	unblock_all
	wait_state PRIMARY_ACTIVE 25 >/dev/null
	end_test $f
}

test6()   # RST / connection refused -> fast failover
{
	local f=$FAIL
	start_test 6 "TCP reset (connection refused), must fail over quickly"
	local t0 t1
	t0=$(date +%s)
	block_tcp_reset
	info "nft: tcp dport $SVC_PORT reject with tcp reset"
	if wait_state FALLBACK_ACTIVE 15; then
		t1=$(date +%s)
		ok "failed over in $((t1 - t0))s on connection refused"
		assert_le "failover time on refused connections" "$((t1 - t0))" 10
	else
		nok "did not fail over within 15s"
	fi
	assert_body "via-quic"
	unblock_all
	wait_state PRIMARY_ACTIVE 25 >/dev/null
	end_test $f
}

test7()   # both transports down -> clean error, no infinite retry
{
	local f=$FAIL
	start_test 7 "both transports unavailable, must report a clean error"
	block_tcp_drop
	block_udp
	info "nft: both tcp and udp dport $SVC_PORT dropped"
	local t0 code t1
	t0=$(date +%s)
	code=$(nsx $NS_CLI curl -s -o /dev/null -w '%{http_code}' --max-time 12 \
	           "http://$HAP_IP_CLI:$FE_PORT/" 2>/dev/null)
	t1=$(date +%s)
	info "client got HTTP $code in $((t1 - t0))s"
	if [ "$code" = "503" ]; then ok "clean 503 returned, no hang"
	else nok "expected 503, got '$code'"; fi
	assert_le "error returned without hanging" "$((t1 - t0))" 11
	# The server must end up down since no transport is left. Requests keep
	# being sent while waiting, as the failures observed on the fallback
	# transport are what makes it unusable when it has no health check.
	local i st=
	for i in $(seq 1 30); do
		st=$(srv_status nodes n1)
		case "$st" in DOWN*) break;; esac
		req >/dev/null
		sleep 0.5
	done
	case "$st" in
		DOWN*) ok "server reported DOWN while both transports are unusable ($st)";;
		*)     nok "server status is '$st', expected DOWN";;
	esac
	unblock_all
	wait_state PRIMARY_ACTIVE 30 >/dev/null
	end_test $f
}

test8()   # fallback dies after the switch
{
	local f=$FAIL
	start_test 8 "fallback transport dies after the switch"
	block_tcp_drop
	wait_state FALLBACK_ACTIVE 20 >/dev/null || nok "could not reach FALLBACK_ACTIVE"
	assert_body "via-quic"
	block_udp
	info "fallback transport now blocked too"
	local i st=
	for i in $(seq 1 30); do
		st=$(srv_status nodes n1)
		case "$st" in DOWN*) break;; esac
		req >/dev/null
		sleep 0.5
	done
	case "$st" in
		DOWN*) ok "primary unavailable + fallback unavailable is reported ($st)";;
		*)     nok "server status is '$st', expected DOWN";;
	esac
	assert_ge "failures recorded on the fallback transport" "$(tf_field fb_fail)" 1
	info "$(cli 'show servers transport nodes' | grep '^nodes/')"
	unblock_all
	wait_state PRIMARY_ACTIVE 30 >/dev/null
	end_test $f
}

test9()   # flapping TCP must not make the transport flap
{
	local f=$FAIL
	start_test 9 "flapping TCP, hysteresis must limit the number of switches"
	local sw_before sw_after i cycles=5
	sw_before=$(tf_field switches)
	# Each down phase lasts long enough to really break the primary
	# transport, and each up phase is shorter than "transport-hold", so a
	# naive implementation would switch twice per cycle.
	for i in $(seq 1 $cycles); do
		block_tcp_drop
		sleep 4
		unblock_all
		sleep 4
	done
	sw_after=$(tf_field switches)
	info "switches during $cycles up/down cycles of 4s: $((sw_after - sw_before)) (a naive implementation would do $((cycles * 2)))"
	assert_le "transport switches while flapping" "$((sw_after - sw_before))" $cycles
	wait_state PRIMARY_ACTIVE 30 >/dev/null
	assert_body "via-tcp"
	end_test $f
}

test10()  # load test, on both transports
{
	local f=$FAIL
	start_test 10 "load: many concurrent sessions on each transport"
	local total=600 conc=30

	# prints only the number of responses matching <want>, so that the
	# result can be captured without mixing it with progress output
	load_run()
	{
		local want=$1
		nsx $NS_CLI bash -c "
			for i in \$(seq 1 $conc); do
			  (
			    for j in \$(seq 1 \$(($total / $conc))); do
			      curl -s --max-time 8 http://$HAP_IP_CLI:$FE_PORT/ 2>/dev/null
			    done
			  ) &
			done
			wait" 2>/dev/null | grep -c "^$want\$"
	}

	local got
	got=$(load_run "via-tcp")
	info "primary transport: $got/$total responses were 'via-tcp'"
	assert_ge "requests served over TCP under load" "$got" $((total * 90 / 100))

	block_tcp_drop
	wait_state FALLBACK_ACTIVE 20 >/dev/null || nok "could not reach FALLBACK_ACTIVE"
	got=$(load_run "via-quic")
	info "fallback transport: $got/$total responses were 'via-quic'"
	assert_ge "requests served over QUIC under load" "$got" $((total * 80 / 100))
	unblock_all
	wait_state PRIMARY_ACTIVE 30 >/dev/null
	end_test $f
}

# ------------------------------------------------------------------- demo

# Walks through the whole life cycle and reports, for each phase, the state
# machine, what the logs say and what is actually seen on the wire. This is the
# human readable counterpart of the assertions above.
demo_phase()
{
	local title=$1 tag=$2 reqs=${3:-3} i
	local syn udp

	printf '\n--- %s ---\n' "$title"
	cap_start "$tag"
	for i in $(seq 1 "$reqs"); do
		printf '    request %d -> %s\n' "$i" "$(req | tr -d '\n')"
	done
	cap_stop

	syn=$(cap_tcp_syns)
	udp=$(cap_udp_pkts)
	printf '    runtime : %s\n' "$(cli "show servers transport nodes" | grep '^nodes/')"
	printf '    stats   : status=%s transport=%s/%s switches=%s\n' \
	       "$(srv_status nodes n1)" \
	       "$(cli 'show stat' | awk -F, '$1=="nodes" && $2=="n1" {print $119}')" \
	       "$(cli 'show stat' | awk -F, '$1=="nodes" && $2=="n1" {print $120}')" \
	       "$(cli 'show stat' | awk -F, '$1=="nodes" && $2=="n1" {print $122}')"
	printf '    packets : %s new TCP connections, %s QUIC datagrams on the service port\n' \
	       "$syn" "$udp"
	if [ "$syn" -gt 0 ] && [ "$udp" -eq 0 ]; then
		printf '    verdict : traffic flows over TCP\n'
	elif [ "$udp" -gt 0 ] && [ "$syn" -eq 0 ]; then
		printf '    verdict : traffic flows over QUIC\n'
	else
		printf '    verdict : mixed or no traffic (tcp=%s quic=%s)\n' "$syn" "$udp"
	fi
}

demo_run()
{
	local before

	head1 "Transport failover demonstration"
	printf 'thresholds: transport-fall=%s transport-rise=%s transport-probe=%s transport-hold=%s\n' \
	       "$TF_FALL" "$TF_RISE" "$TF_PROBE" "$TF_HOLD"

	demo_phase "1. TCP UP: the primary transport carries the traffic" d1

	before=$(wc -l < "$RUNDIR/haproxy.log")
	block_tcp_drop
	printf '\n>>> injecting failure: nft drop on tcp dport %s and %s\n' "$SVC_PORT" "$CHK_PORT_TCP"
	wait_state FALLBACK_ACTIVE 20 >/dev/null
	demo_phase "2. TCP DOWN: the fallback transport took over" d2
	printf '    logs    :\n'
	tail -n +$((before + 1)) "$RUNDIR/haproxy.log" | grep -i 'transport' | sed 's/^/              /'

	before=$(wc -l < "$RUNDIR/haproxy.log")
	unblock_all
	printf '\n>>> TCP restored, the primary transport is being probed\n'
	# catch the intermediate state while the probes are being counted
	local i
	for i in $(seq 1 40); do
		[ "$(tf_field state)" = "PRIMARY_PROBING" ] && break
		sleep 0.1
	done
	demo_phase "3. TCP RECOVERING: probes succeed, traffic still on the fallback" d3 1

	wait_state PRIMARY_ACTIVE 30 >/dev/null
	demo_phase "4. TCP ACTIVE: traffic is back on the primary transport" d4
	printf '    logs    :\n'
	tail -n +$((before + 1)) "$RUNDIR/haproxy.log" | grep -i 'transport' | sed 's/^/              /'

	printf '\ncaptures kept in %s (d1..d4.pcap)\n' "$ARTIFACTS"
}

# ----------------------------------------------------------------- main

trap 'cleanup' EXIT INT TERM

check_reqs
say "haproxy: $("$HAPROXY" -v 2>/dev/null | head -1)"
say "run dir: $RUNDIR"

setup_net
gen_certs
gen_configs
start_stack
say "stack started: client=$CLI_IP haproxy=$HAP_IP_CLI:$FE_PORT node=$NODE_IP:$SVC_PORT"

TESTS=${*:-1 2 3 4 5 6 7 8 9 10}
for t in $TESTS; do
	netem_clear
	unblock_all
	wait_state PRIMARY_ACTIVE 30 >/dev/null
	case "$t" in
		demo) demo_run ;;
		*)    "test$t" ;;
	esac
done

head1 "Summary"
say "passed assertions: $PASS"
say "failed assertions: $FAIL"
if [ "$FAIL" -eq 0 ]; then
	say "RESULT: PASS"
	exit 0
fi
say "failed tests:$FAILED_TESTS"
say "artifacts in $ARTIFACTS"
say "RESULT: FAIL"
exit 1
