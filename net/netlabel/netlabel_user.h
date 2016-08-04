/*
 * NetLabel NETLINK Interface
 *
 * This file defines the NETLINK interface for the NetLabel system.  The
 * NetLabel system manages static and dynamic label mappings for network
 * protocols such as CIPSO and RIPSO.
 *
 * Author: Paul Moore <paul@paul-moore.com>
 *
 */

/*
 * (c) Copyright Hewlett-Packard Development Company, L.P., 2006
 *
 * This program is free software;  you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY;  without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 * the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program;  if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */

#ifndef _NETLABEL_USER_H
#define _NETLABEL_USER_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/capability.h>
#include <linux/audit.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <net/netlabel.h>

/* NetLabel NETLINK helper functions */

extern struct security_operations *netlbl_active_lsm;

/**
 * netlbl_secid_to_secctx - call the registered secid_to_secctx LSM hook
 * @secid - The secid to convert
 * @secdata - Where to put the result
 * @seclen - Where to put the length of the result
 *
 * Returns: the result of calling the hook.
 */
static inline int netlbl_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
	if (netlbl_active_lsm == NULL)
		return -EINVAL;
	return netlbl_active_lsm->secid_to_secctx(secid, secdata, seclen);
}

/**
 * netlbl_release_secctx - call the registered release_secctx LSM hook
 * @secdata - The security context to release
 * @seclen - The size of the context to release
 *
 */
static inline void netlbl_release_secctx(char *secdata, u32 seclen)
{
	if (netlbl_active_lsm != NULL)
		netlbl_active_lsm->release_secctx(secdata, seclen);
}

/**
 * netlbl_secctx_to_secid - call the registered seccts_to_secid LSM hook
 * @secdata - The security context
 * @seclen - The size of the security context
 * @secid - Where to put the result
 *
 * Returns: the result of calling the hook
 */
static inline int netlbl_secctx_to_secid(const char *secdata, u32 seclen,
					 u32 *secid)
{
	if (netlbl_active_lsm == NULL) {
		*secid = 0;
		return -EINVAL;
	}
	return netlbl_active_lsm->secctx_to_secid(secdata, seclen, secid);
}

/**
 * netlbl_task_getsecid - call the registered task_getsecid LSM hook
 * @p - The task
 * @secid - Where to put the secid
 *
 */
static inline void netlbl_task_getsecid(struct task_struct *p, u32 *secid)
{
	if (netlbl_active_lsm)
		netlbl_active_lsm->task_getsecid(p, secid);
}

/**
 * netlbl_netlink_auditinfo - Fetch the audit information from a NETLINK msg
 * @skb: the packet
 * @audit_info: NetLabel audit information
 */
static inline void netlbl_netlink_auditinfo(struct sk_buff *skb,
					    struct netlbl_audit *audit_info)
{
	netlbl_task_getsecid(current, &audit_info->secid);
	audit_info->loginuid = audit_get_loginuid(current);
	audit_info->sessionid = audit_get_sessionid(current);
}

/* NetLabel NETLINK I/O functions */

int netlbl_netlink_init(void);

/* NetLabel Audit Functions */

struct audit_buffer *netlbl_audit_start_common(int type,
					      struct netlbl_audit *audit_info);

#endif
