/*
 * include/haproxy/server_tf.h
 * Transport failover between a server's primary and fallback transports.
 *
 * Copyright (C) 2026 HAProxy Technologies
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_SERVER_TF_H
#define _HAPROXY_SERVER_TF_H

#include <haproxy/api.h>
#include <haproxy/server-t.h>

/* transport failure classes reported by the data plane */
#define SRV_TF_ERR_NONE     0  /* not a transport-level failure */
#define SRV_TF_ERR_TRANSP   1  /* the transport itself looks unusable */
#define SRV_TF_ERR_LOCAL    2  /* local or session specific failure, do not count */

struct check;
struct connection;
struct stream;

struct server *__srv_tf_endpoint(struct server *srv);
void srv_tf_report_conn_err(struct server *srv, const struct server *ep, int class);
void srv_tf_report_conn_ok(struct server *srv, const struct server *ep);
int srv_tf_absorb_check_failure(struct server *srv);
void srv_tf_report_check(struct server *srv, int passed);
int srv_tf_classify_conn_err(const struct connection *conn, const struct stream *s);
int srv_tf_init(struct server *srv, struct proxy *px);
void srv_tf_deinit(struct server *srv);
void srv_tf_set_defaults(struct srv_tf *tf);
const char *srv_tf_state_str(uint state);
const char *srv_tf_reason_str(uint reason);
int srv_tf_dump(struct buffer *buf, const struct server *srv);
int srv_tf_check_interval(const struct check *check);

/* Returns the server holding the transport to use for the next connection to
 * <srv>. It is <srv> itself unless transport failover is configured and the
 * primary transport is currently considered unusable. This is called on the
 * connection setup path, hence the flag test placed first so that servers
 * without transport failover are not impacted at all.
 */
static inline struct server *srv_tf_endpoint(struct server *srv)
{
	if (likely(!(srv->flags & SRV_F_TF_ENABLED)))
		return srv;
	return __srv_tf_endpoint(srv);
}

/* Returns non-zero if <srv> currently runs on its fallback transport. */
static inline int srv_tf_on_fallback(const struct server *srv)
{
	uint state;

	if (!(srv->flags & SRV_F_TF_ENABLED))
		return 0;

	state = HA_ATOMIC_LOAD(&srv->tf.state);
	return state == SRV_TF_ST_FALLBACK || state == SRV_TF_ST_PROBING;
}

#endif /* _HAPROXY_SERVER_TF_H */
