/*
 * Transport failover between a server's primary and fallback transports.
 *
 * Copyright (C) 2026 HAProxy Technologies
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * A server may reference another server which describes an alternate way to
 * reach the same endpoint, typically QUIC instead of TCP. When the primary
 * transport is confirmed unusable, new connections are directed to that
 * fallback server while the primary one keeps being probed by its own health
 * check. Once the primary transport has been seen working again for long
 * enough, new connections go back to it. Established connections are never
 * migrated: TCP and QUIC do not share the same semantics, only new sessions
 * are affected.
 *
 * The state is only updated on rare events (connection failures, health check
 * results). The connection setup path merely reads it, which is why the
 * feature is entirely hidden behind the SRV_F_TF_ENABLED flag test.
 */

#include <haproxy/api.h>
#include <haproxy/atomic.h>
#include <haproxy/backend.h>
#include <haproxy/chunk.h>
#include <haproxy/check.h>
#include <haproxy/clock.h>
#include <haproxy/connection.h>
#include <haproxy/errors.h>
#include <haproxy/log.h>
#include <haproxy/proxy.h>
#include <haproxy/server.h>
#include <haproxy/server_tf.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>
#include <haproxy/tools.h>

/* default tuning of the transport failover state machine */
#define SRV_TF_DFLT_FALL    3
#define SRV_TF_DFLT_RISE    5
#define SRV_TF_DFLT_PROBE   5000    /* ms */
#define SRV_TF_DFLT_HOLD   30000    /* ms */

static const char *srv_tf_state_names[SRV_TF_ST_ENTRIES] = {
	[SRV_TF_ST_PRIMARY]  = "PRIMARY_ACTIVE",
	[SRV_TF_ST_DEGRADED] = "PRIMARY_DEGRADED",
	[SRV_TF_ST_FALLBACK] = "FALLBACK_ACTIVE",
	[SRV_TF_ST_PROBING]  = "PRIMARY_PROBING",
};

static const char *srv_tf_reason_names[SRV_TF_RS_ENTRIES] = {
	[SRV_TF_RS_NONE]     = "none",
	[SRV_TF_RS_CONN_ERR] = "connection failures",
	[SRV_TF_RS_CHECK]    = "health check",
	[SRV_TF_RS_PROBE_OK] = "primary probes succeeded",
	[SRV_TF_RS_FB_DOWN]  = "fallback transport unusable",
	[SRV_TF_RS_ADMIN]    = "administrative change",
};

const char *srv_tf_state_str(uint state)
{
	if (state >= SRV_TF_ST_ENTRIES)
		return "UNKNOWN";
	return srv_tf_state_names[state];
}

const char *srv_tf_reason_str(uint reason)
{
	if (reason >= SRV_TF_RS_ENTRIES)
		return "unknown";
	return srv_tf_reason_names[reason];
}

/* Applies the default tuning to a fresh transport failover context. Called
 * for every server so that "default-server" inheritance works as usual.
 */
void srv_tf_set_defaults(struct srv_tf *tf)
{
	tf->fall_thres = SRV_TF_DFLT_FALL;
	tf->rise_thres = SRV_TF_DFLT_RISE;
	tf->probe      = SRV_TF_DFLT_PROBE;
	tf->hold       = SRV_TF_DFLT_HOLD;
}

/* Emits a diagnostic message about <srv>'s transport. Only called on state
 * transitions and on probe progress, that is at most once per probe interval,
 * so this cannot flood the logs.
 */
static void srv_tf_log(struct server *srv, int level, const char *fmt, ...)
{
	char msg[256];
	va_list args;

	if (global.mode & MODE_STARTING)
		return;

	va_start(args, fmt);
	if (vsnprintf(msg, sizeof(msg), fmt, args) < 0)
		msg[0] = 0;
	va_end(args);

	ha_warning("Server %s/%s transport: %s.\n", srv->proxy->id, srv->id, msg);
	send_log(srv->proxy, level, "Server %s/%s transport: %s.\n",
	         srv->proxy->id, srv->id, msg);
}

/* Returns non-zero if the fallback transport of <srv> may currently be used.
 * The fallback is rejected when it is administratively or operationally down,
 * or when the data plane recorded too many failures on it. In the latter case
 * a new chance is given once the hold-down delay has elapsed, so that a
 * transient fallback outage does not disable it forever.
 */
static int srv_tf_fb_usable(struct server *srv)
{
	struct server *fb = srv->tf.fb_srv;
	uint fails;

	if (!fb)
		return 0;

	fails = HA_ATOMIC_LOAD(&srv->tf.fb_fail);
	if (fails >= (uint)srv->tf.fall_thres) {
		uint since = HA_ATOMIC_LOAD(&srv->tf.fb_fail_since);

		if (!tick_is_expired(tick_add(since, srv->tf.hold), now_ms))
			return 0;

		/* give the fallback transport another chance */
		HA_ATOMIC_STORE(&srv->tf.fb_fail, 0);
	}

	return srv_currently_usable(fb);
}

/* Moves <srv> onto its fallback transport. Only the thread which wins the
 * state CAS reports the transition, so the log is emitted exactly once.
 */
static void srv_tf_go_fallback(struct server *srv, uint reason)
{
	uint prev = HA_ATOMIC_LOAD(&srv->tf.state);

	do {
		if (prev == SRV_TF_ST_FALLBACK || prev == SRV_TF_ST_PROBING)
			return;
	} while (!HA_ATOMIC_CAS(&srv->tf.state, &prev, SRV_TF_ST_FALLBACK));

	HA_ATOMIC_STORE(&srv->tf.rise, 0);
	HA_ATOMIC_STORE(&srv->tf.fb_since, now_ms);
	HA_ATOMIC_STORE(&srv->tf.last_switch, now_ms);
	HA_ATOMIC_STORE(&srv->tf.reason, reason);
	HA_ATOMIC_INC(&srv->tf.switches);

	if (reason == SRV_TF_RS_CONN_ERR)
		srv_tf_log(srv, LOG_WARNING,
		           "primary transport degraded, %u consecutive failures, "
		           "switching to fallback transport %s/%s",
		           HA_ATOMIC_LOAD(&srv->tf.fail),
		           srv->tf.fb_srv->proxy->id, srv->tf.fb_srv->id);
	else
		srv_tf_log(srv, LOG_WARNING,
		           "primary transport declared unusable by its %s, "
		           "switching to fallback transport %s/%s",
		           srv_tf_reason_str(reason),
		           srv->tf.fb_srv->proxy->id, srv->tf.fb_srv->id);

	/* the primary transport is now probed at its own pace, make the check
	 * task recompute its timer right away.
	 */
	if (srv->check.task)
		task_wakeup(srv->check.task, TASK_WOKEN_MSG);
}

/* Moves <srv> back onto its primary transport. */
static void srv_tf_go_primary(struct server *srv, uint reason)
{
	uint prev = HA_ATOMIC_LOAD(&srv->tf.state);
	int was_fb;

	do {
		if (prev == SRV_TF_ST_PRIMARY)
			return;
	} while (!HA_ATOMIC_CAS(&srv->tf.state, &prev, SRV_TF_ST_PRIMARY));

	was_fb = (prev == SRV_TF_ST_FALLBACK || prev == SRV_TF_ST_PROBING);

	HA_ATOMIC_STORE(&srv->tf.fail, 0);
	HA_ATOMIC_STORE(&srv->tf.rise, 0);
	HA_ATOMIC_STORE(&srv->tf.last_switch, now_ms);
	HA_ATOMIC_STORE(&srv->tf.reason, reason);

	if (was_fb) {
		HA_ATOMIC_INC(&srv->tf.switches);
		srv_tf_log(srv, LOG_NOTICE,
		           "primary transport recovered (%s), switching back from fallback transport %s/%s",
		           srv_tf_reason_str(reason),
		           srv->tf.fb_srv->proxy->id, srv->tf.fb_srv->id);

		if (srv->check.task)
			task_wakeup(srv->check.task, TASK_WOKEN_MSG);
	}
}

/* Returns the server carrying the transport to use for the next connection to
 * <srv>. Slow path of srv_tf_endpoint(), only reached when transport failover
 * is configured.
 */
struct server *__srv_tf_endpoint(struct server *srv)
{
	uint state = HA_ATOMIC_LOAD(&srv->tf.state);

	if (state != SRV_TF_ST_FALLBACK && state != SRV_TF_ST_PROBING)
		return srv;

	/* If the fallback transport is not usable we deliberately fall back to
	 * the primary one: this makes the stream fail fast on a dead endpoint
	 * instead of looping, and it lets the data plane notice that the
	 * primary transport works again even without health checks.
	 */
	if (!srv_tf_fb_usable(srv))
		return srv;

	HA_ATOMIC_INC(&srv->tf.fb_conns);
	return srv->tf.fb_srv;
}

/* Tells whether a failed connection attempt denotes a broken transport or a
 * local/session specific problem which must not be charged to the transport.
 * Returns one of the SRV_TF_ERR_* values.
 */
int srv_tf_classify_conn_err(const struct connection *conn, const struct stream *s)
{
	/* Only the very first attempt of a stream is taken into account: a
	 * single session retrying three times must not look like three
	 * independent failures.
	 */
	if (s && s->conn_retries)
		return SRV_TF_ERR_NONE;

	/* A connect timeout is reported by the stream layer rather than by the
	 * connection itself (SYN lost, blackholed port, ...).
	 */
	if (s && s->conn_err_type == STRM_ET_CONN_TO)
		return SRV_TF_ERR_TRANSP;

	if (!conn)
		return SRV_TF_ERR_NONE;

	switch (conn->err_code) {
	case CO_ER_SOCK_ERR:
		/* connection refused, network or host unreachable, reset while
		 * connecting: the transport really does not work.
		 */
		return SRV_TF_ERR_TRANSP;

	case CO_ER_PRX_EMPTY:
	case CO_ER_PRX_ABORT:
	case CO_ER_PRX_TIMEOUT:
	case CO_ER_SSL_EMPTY:
	case CO_ER_SSL_ABORT:
	case CO_ER_SSL_HANDSHAKE:
	case CO_ER_SSL_HANDSHAKE_HB:
	case CO_ER_SSL_NO_MEM:
		/* the transport was established but the handshake on top of it
		 * failed; for QUIC this is also how a blackholed handshake
		 * shows up, so this counts as a transport failure.
		 */
		return SRV_TF_ERR_TRANSP;

	case CO_ER_FREE_PORTS:
	case CO_ER_ADDR_INUSE:
	case CO_ER_PORT_RANGE:
	case CO_ER_CANT_BIND:
	case CO_ER_CONF_FDLIM:
	case CO_ER_PROC_FDLIM:
	case CO_ER_SYS_FDLIM:
	case CO_ER_SYS_MEMLIM:
	case CO_ER_NOPROTO:
		/* local resource exhaustion, not the endpoint's fault */
		return SRV_TF_ERR_LOCAL;

	case CO_ER_SSL_MISMATCH:
	case CO_ER_SSL_MISMATCH_SNI:
	case CO_ER_SSL_CA_FAIL:
	case CO_ER_SSL_CRT_FAIL:
		/* configuration or certificate problem, switching transport
		 * would not help and would hide the real error.
		 */
		return SRV_TF_ERR_LOCAL;

	case CO_ER_NONE:
		/* no connection level error code: only trust an explicit
		 * connect failure reported by the stream layer.
		 */
		return (s && s->conn_err_type == STRM_ET_CONN_ERR) ?
		        SRV_TF_ERR_TRANSP : SRV_TF_ERR_NONE;

	default:
		return SRV_TF_ERR_NONE;
	}
}

/* Records a failed connection attempt to <srv> made over the transport of
 * <ep> (either <srv> itself or its fallback server). <class> is the result of
 * srv_tf_classify_conn_err().
 */
void srv_tf_report_conn_err(struct server *srv, const struct server *ep, int class)
{
	uint fails;

	if (!(srv->flags & SRV_F_TF_ENABLED) || class != SRV_TF_ERR_TRANSP)
		return;

	if (ep && ep == srv->tf.fb_srv) {
		fails = HA_ATOMIC_ADD_FETCH(&srv->tf.fb_fail, 1);
		if (fails == (uint)srv->tf.fall_thres) {
			HA_ATOMIC_STORE(&srv->tf.fb_fail_since, now_ms);
			HA_ATOMIC_STORE(&srv->tf.reason, SRV_TF_RS_FB_DOWN);
			srv_tf_log(srv, LOG_ALERT,
			           "fallback transport %s/%s also unusable after %u failures, "
			           "no usable transport left",
			           srv->tf.fb_srv->proxy->id, srv->tf.fb_srv->id, fails);

			/* let the health check conclude about the server state
			 * as soon as possible now that no transport is left.
			 */
			if (srv->check.task)
				task_wakeup(srv->check.task, TASK_WOKEN_MSG);
		}
		return;
	}

	HA_ATOMIC_INC(&srv->tf.prim_fail);
	fails = HA_ATOMIC_ADD_FETCH(&srv->tf.fail, 1);

	if (fails < (uint)srv->tf.fall_thres) {
		uint prev = SRV_TF_ST_PRIMARY;

		/* stay on the primary transport but remember it is shaky */
		HA_ATOMIC_CAS(&srv->tf.state, &prev, SRV_TF_ST_DEGRADED);
		return;
	}

	if (srv_tf_fb_usable(srv))
		srv_tf_go_fallback(srv, SRV_TF_RS_CONN_ERR);
}

/* Records a successful connection to <srv> established over <ep>'s transport. */
void srv_tf_report_conn_ok(struct server *srv, const struct server *ep)
{
	uint state;

	if (!(srv->flags & SRV_F_TF_ENABLED))
		return;

	if (ep && ep == srv->tf.fb_srv) {
		HA_ATOMIC_STORE(&srv->tf.fb_fail, 0);
		return;
	}

	/* the primary transport just worked */
	HA_ATOMIC_STORE(&srv->tf.fail, 0);

	state = HA_ATOMIC_LOAD(&srv->tf.state);
	if (state == SRV_TF_ST_DEGRADED)
		srv_tf_go_primary(srv, SRV_TF_RS_CONN_ERR);
}

/* Called from the health check completion path for the server's own health
 * check, with <passed> set when the check succeeded. This is what drives the
 * primary transport probing while the fallback transport is in use.
 */
void srv_tf_report_check(struct server *srv, int passed)
{
	uint state, rise;

	if (!(srv->flags & SRV_F_TF_ENABLED))
		return;

	state = HA_ATOMIC_LOAD(&srv->tf.state);

	if (!passed) {
		HA_ATOMIC_STORE(&srv->tf.rise, 0);
		if (state == SRV_TF_ST_PROBING) {
			uint prev = SRV_TF_ST_PROBING;

			HA_ATOMIC_CAS(&srv->tf.state, &prev, SRV_TF_ST_FALLBACK);
			srv_tf_log(srv, LOG_NOTICE,
			           "primary transport probe failed, staying on fallback transport");
		}
		return;
	}

	/* the primary transport answered */
	HA_ATOMIC_STORE(&srv->tf.fail, 0);

	if (state == SRV_TF_ST_PRIMARY)
		return;

	if (state == SRV_TF_ST_DEGRADED) {
		srv_tf_go_primary(srv, SRV_TF_RS_CHECK);
		return;
	}

	/* on the fallback transport: count the successful probes */
	rise = HA_ATOMIC_ADD_FETCH(&srv->tf.rise, 1);

	if (state == SRV_TF_ST_FALLBACK) {
		uint prev = SRV_TF_ST_FALLBACK;

		if (HA_ATOMIC_CAS(&srv->tf.state, &prev, SRV_TF_ST_PROBING))
			HA_ATOMIC_INC(&srv->tf.recov);
	}

	if (rise < (uint)srv->tf.rise_thres) {
		srv_tf_log(srv, LOG_INFO, "primary transport probe successful %u/%d",
		           rise, srv->tf.rise_thres);
		return;
	}

	/* enough successful probes: honour the hold-down delay before moving
	 * the traffic back, this is what prevents flapping.
	 */
	if (!tick_is_expired(tick_add(HA_ATOMIC_LOAD(&srv->tf.fb_since), srv->tf.hold), now_ms)) {
		srv_tf_log(srv, LOG_INFO,
		           "primary transport probe successful %u/%d, waiting for hold-down to expire",
		           rise, srv->tf.rise_thres);
		return;
	}

	srv_tf_go_primary(srv, SRV_TF_RS_PROBE_OK);
}

/* Called from check_notify_failure() before the server is marked down because
 * of its own health check. Returns non-zero if the failure was absorbed by the
 * transport failover machinery, meaning the server must stay up and serve new
 * connections over its fallback transport.
 */
int srv_tf_absorb_check_failure(struct server *srv)
{
	if (!(srv->flags & SRV_F_TF_ENABLED))
		return 0;

	if (!srv_tf_fb_usable(srv)) {
		/* no transport left, let the server go down as usual */
		return 0;
	}

	srv_tf_go_fallback(srv, SRV_TF_RS_CHECK);
	return 1;
}

/* Returns the health check interval to use for <check>, or 0 when the regular
 * one applies. While the fallback transport is in use, the server's own health
 * check is what probes the primary transport, hence the dedicated interval.
 */
int srv_tf_check_interval(const struct check *check)
{
	const struct server *srv = check->server;

	if (!srv || !(srv->flags & SRV_F_TF_ENABLED) || (check->state & CHK_ST_AGENT))
		return 0;

	if (!srv->tf.probe)
		return 0;

	if (!srv_tf_on_fallback(srv))
		return 0;

	return srv->tf.probe;
}

/* Resolves the "fallback-transport" reference of <srv> and validates that both
 * transports may be used together. <px> is the backend owning <srv>. Returns 0
 * on success, non-zero on error, in which case the error was already reported.
 *
 * Not thread-safe, only called at configuration time.
 */
int srv_tf_init(struct server *srv, struct proxy *px)
{
	struct proxy *fbpx;
	struct server *fb;
	char *pname, *sname;

	if (!srv->tf.fb_name)
		return 0;

	pname = srv->tf.fb_name;
	sname = strrchr(pname, '/');

	if (sname)
		*sname++ = '\0';
	else {
		sname = pname;
		pname = NULL;
	}

	if (pname) {
		fbpx = proxy_be_by_name(pname);
		if (!fbpx) {
			ha_alert("unable to find backend '%s' for the fallback transport of server '%s'.\n",
			         pname, srv->id);
			return 1;
		}
	}
	else
		fbpx = px;

	fb = server_find_by_name(fbpx, sname);
	if (!fb) {
		ha_alert("unable to find server '%s' in backend '%s' for the fallback transport of server '%s'.\n",
		         sname, fbpx->id, srv->id);
		return 1;
	}

	if (fb == srv) {
		ha_alert("server '%s/%s' cannot use itself as a fallback transport.\n",
		         px->id, srv->id);
		return 1;
	}

	/* transport failover cannot be chained: the fallback transport must be
	 * a plain server. This test is order independent as it looks at the
	 * configuration rather than at the resolved state.
	 */
	if (fb->tf.fb_name) {
		ha_alert("server '%s/%s' cannot be used as the fallback transport of '%s/%s' "
		         "because it defines a fallback transport itself.\n",
		         fbpx->id, fb->id, px->id, srv->id);
		return 1;
	}

	if (fb->flags & SRV_F_DYNAMIC) {
		ha_alert("server '%s/%s' cannot be used as a fallback transport as it is a "
		         "dynamic server.\n", fbpx->id, fb->id);
		return 1;
	}

	if (fbpx->mode != px->mode) {
		ha_alert("server '%s/%s' cannot be used as a fallback transport of '%s/%s' : "
		         "backends '%s' and '%s' do not run in the same mode.\n",
		         fbpx->id, fb->id, px->id, srv->id, fbpx->id, px->id);
		return 1;
	}

	if (!srv->do_check) {
		ha_alert("server '%s/%s' uses a fallback transport and therefore requires "
		         "'check' so that its primary transport can be probed.\n",
		         px->id, srv->id);
		return 1;
	}

	if (srv->tf.rise_thres <= 0 || srv->tf.fall_thres <= 0) {
		ha_alert("server '%s/%s' : 'transport-fall' and 'transport-rise' must be "
		         "strictly positive.\n", px->id, srv->id);
		return 1;
	}

	if (!fb->do_check)
		ha_warning("server '%s/%s' is used as a fallback transport without 'check' : "
		           "its availability will only be deduced from live traffic.\n",
		           fbpx->id, fb->id);

	srv->tf.fb_srv = fb;
	srv->flags |= SRV_F_TF_ENABLED;
	fb->flags |= SRV_F_TF_FALLBACK | SRV_F_NON_PURGEABLE;
	HA_ATOMIC_STORE(&srv->tf.state, SRV_TF_ST_PRIMARY);

	return 0;
}

void srv_tf_deinit(struct server *srv)
{
	ha_free(&srv->tf.fb_name);
	srv->tf.fb_srv = NULL;
}

/* Appends a human readable description of <srv>'s transport state into <buf>.
 * Returns 0 if the buffer was too small, non-zero otherwise.
 */
int srv_tf_dump(struct buffer *buf, const struct server *srv)
{
	const struct srv_tf *tf = &srv->tf;
	uint state = HA_ATOMIC_LOAD(&tf->state);
	uint last = HA_ATOMIC_LOAD(&tf->last_switch);
	int on_fb = (state == SRV_TF_ST_FALLBACK || state == SRV_TF_ST_PROBING);

	chunk_appendf(buf,
	              "%s/%s %d/%d state=%s current=%s primary=%s fallback=%s/%s:%s "
	              "fail=%u/%d rise=%u/%d fb_fail=%u switches=%u fb_conns=%u "
	              "prim_fail=%u recov=%u probe=%dms hold=%dms last_change=%dms reason=%s\n",
	              srv->proxy->id, srv->id, srv->proxy->uuid, srv->puid,
	              srv_tf_state_str(state),
	              on_fb ? "fallback" : "primary",
	              (state == SRV_TF_ST_PRIMARY) ? "up" :
	              (state == SRV_TF_ST_DEGRADED) ? "degraded" : "down",
	              tf->fb_srv ? tf->fb_srv->proxy->id : "-",
	              tf->fb_srv ? tf->fb_srv->id : "-",
	              (tf->fb_srv && srv_currently_usable(tf->fb_srv)) ? "up" : "down",
	              HA_ATOMIC_LOAD(&tf->fail), tf->fall_thres,
	              HA_ATOMIC_LOAD(&tf->rise), tf->rise_thres,
	              HA_ATOMIC_LOAD(&tf->fb_fail),
	              HA_ATOMIC_LOAD(&tf->switches),
	              HA_ATOMIC_LOAD(&tf->fb_conns),
	              HA_ATOMIC_LOAD(&tf->prim_fail),
	              HA_ATOMIC_LOAD(&tf->recov),
	              tf->probe, tf->hold,
	              last ? (int)(now_ms - last) : -1,
	              srv_tf_reason_str(HA_ATOMIC_LOAD(&tf->reason)));

	return 1;
}
