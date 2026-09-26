# Transport failover for HAProxy backends

This branch teaches a HAProxy backend server to keep a **second transport in reserve**. While TCP
works, new connections use TCP. When TCP stops establishing, new connections automatically go over
the fallback transport — typically QUIC. When TCP has been seen working again for long enough, new
connections go back to it. No reload, no external watchdog, no configuration rewriting.

Based on upstream **v3.4.5**.

```
backend nodes_quic                     # fallback transport: its own protocol, xprt, mux, TLS, check
    mode http
    server n1 quic4@10.0.0.2:443 ssl verify none alpn h3 check

backend nodes                          # primary transport: TCP
    mode http
    server n1 10.0.0.2:443 check inter 2s fall 3 rise 2 fallback-transport nodes_quic/n1 transport-fall 3 transport-rise 5 transport-probe 5s transport-hold 30s
```

See `examples/transport-failover.cfg` for a complete configuration and `doc/configuration.txt`
(keyword `fallback-transport`) for the reference documentation.

## Why the fallback transport is another server

Everything that defines a transport in HAProxy is a property of `struct server`: the socket protocol
(`addr_type`, `alt_proto`), the transport layer (`srv->xprt`), the mux (`srv->mux_proto`), the TLS
context (`srv->ssl_ctx`) and the QUIC parameters. Two of these cannot coexist on one server:

* `srv->xprt` is assigned once at init — `xprt_get(XPRT_QUIC)` for a QUIC server, `&ssl_sock`
  otherwise (`src/ssl_sock.c`);
* the `SSL_CTX` is built differently for QUIC — `ssl_sock_new_ssl_ctx(srv_is_quic(srv))`, with
  its own ciphersuite and curve defaults.

So a single server cannot be TCP+TLS on one side and QUIC on the other. Describing the fallback
transport as an ordinary server solves this completely and needs no new transport code: the
referenced server is initialized through the normal path, and since almost everything is looked up
from `conn->target`, aiming the connection at it makes the whole stack follow — protocol, transport
layer, mux, TLS context, QUIC parameters, separate idle connection pools, its own health check and
its own statistics.

The reference itself reuses the syntax and resolution scheme of the existing `track` keyword.

## State machine

```
PRIMARY_ACTIVE ──failures──► PRIMARY_DEGRADED ──transport-fall reached──► FALLBACK_ACTIVE
      ▲                             │                                          │
      │                        success                              first successful probe
      └─────────────────────────────┘                                          ▼
      └──── transport-rise probes AND transport-hold elapsed ──── PRIMARY_PROBING
```

The primary transport is probed by the server's own health check, which already targets it;
`transport-probe` temporarily replaces its interval. Established connections are never migrated —
TCP and QUIC do not share the same semantics — so only new connections are affected.

If the fallback transport becomes unusable too, its health check failure is no longer absorbed and
the server is marked down the usual way, so the load balancer stops selecting it and clients get a
clean 503 instead of an endless retry loop.

## What counts as a transport failure

Counted: connect timeout, connection refused, network or host unreachable, reset while connecting,
and a failed handshake on top of an established transport (which is how a blackholed QUIC handshake
shows up). At most **one failure per session**, so a single client retrying cannot move a whole
server onto its fallback transport.

Not counted: local resource exhaustion (source ports, file descriptors, memory) and TLS
configuration or certificate problems, where switching transport would only hide the real error.

## Observability

```
$ echo "show servers transport" | socat /var/run/haproxy.sock -
# bkname/svname bkid/svid state= current= primary= fallback= fail=cur/thres ...
nodes/n1 4/1 state=FALLBACK_ACTIVE current=fallback primary=down fallback=nodes_quic/n1:up \
  fail=0/3 rise=2/5 fb_fail=0 switches=1 fb_conns=128 prim_fail=3 recov=1 \
  probe=5000ms hold=30000ms last_change=2486ms reason=health check
```

Seven columns are appended to the statistics (`transport_current`, `transport_state`,
`transport_fb_active`, `transport_switches`, `transport_fb_conns`, `transport_prim_failures`,
`transport_recov_attempts`), and the numeric ones are exported by the Prometheus exporter. Every
transition is logged:

```
Server nodes/n1 transport: primary transport declared unusable by its health check, switching to fallback transport nodes_quic/n1.
Server nodes/n1 transport: primary transport probe successful 1/5.
Server nodes/n1 transport: primary transport recovered (primary probes succeeded), switching back from fallback transport nodes_quic/n1.
```

## Known limitation: `mode tcp` cannot use QUIC

Upstream's QUIC mux is registered for HTTP mode only (`PROTO_MODE_HTTP` and `MX_FL_HTX` in
`src/mux_quic.c`), and a QUIC server has that mux forced onto it, so a tcp-mode proxy is rejected at
configuration time:

```
[ALERT] backend 'b' : MUX protocol 'quic' is not usable for server 's1' at [cfg:13].
```

Transport failover itself is transport agnostic, so this is a QUIC limitation rather than a
limitation of this feature. Carrying an arbitrary byte stream over QUIC would need one more piece:
the HTX coupling of the QUIC mux is confined to `src/qcm_http.c` (124 lines), so a raw variant of it
plus a non-HTX `qcc_app_ops` and a second `mux_proto_list` registration in TCP mode would be enough,
with no new framing or reliability protocol since a QUIC stream already provides ordering, flow
control, congestion control and TLS. The cost is interoperability: the far end has to speak the same
thing.

## Tests

```bash
# unit tests of the state machine (build with DEBUG="-DDEBUG_UNIT")
./haproxy -U srv_tf

# regression test
vtest -t 30 reg-tests/checks/transport-failover.vtc

# integration tests in network namespaces (root; needs ip, nft, tc, tcpdump, socat, curl)
sudo ./tests/transport-failover/run.sh          # 10 scenarios, packet level verification
sudo ./tests/transport-failover/run.sh demo      # narrated walk through the life cycle
```

The integration suite wires a client, a HAProxy and a node with veth pairs, offers the node over
both TCP and QUIC, breaks TCP with nftables and tc netem, and confirms with tcpdump which transport
actually carries the traffic — HAProxy's own logs are never the only evidence.
