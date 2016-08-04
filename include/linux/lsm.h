/*
 *
 * Copyright (C) 2012 Casey Schaufler <casey@schaufler-ca.com>
 * Copyright (C) 2012 Intel Corporation
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 *
 * Author:
 *	Casey Schaufler <casey@schaufler-ca.com>
 *
 */
#ifndef _LINUX_LSM_H
#define _LINUX_LSM_H

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/msg.h>
#include <linux/key.h>
#include <net/sock.h>
#include <linux/security.h>

/*
 * Just a set of slots for each LSM to keep its blob in.
 */
struct lsm_blob {
	int	lsm_setcount;			/* Number of blobs set */
	void	*lsm_blobs[COMPOSER_MAX];	/* LSM specific blobs */
};

static inline struct lsm_blob *lsm_alloc_blob(gfp_t gfp)
{
	return kzalloc(sizeof(struct lsm_blob), gfp);
}

static inline void *lsm_get_blob(const struct lsm_blob *bp, const int lsm)
{
	if (bp == NULL)
		return NULL;
	return bp->lsm_blobs[lsm];
}

static inline void lsm_set_blob(void **vpp, void *value, const int lsm)
{
	struct lsm_blob *bp = *vpp;

	if (value == NULL && bp->lsm_blobs[lsm] != NULL)
		bp->lsm_setcount--;
	if (value != NULL && bp->lsm_blobs[lsm] == NULL)
		bp->lsm_setcount++;

	bp->lsm_blobs[lsm] = value;
}

static inline void *lsm_get_cred(const struct cred *cred,
					const struct security_operations *sop)
{
	return lsm_get_blob(cred->security, sop->order);
}

static inline void lsm_set_cred(struct cred *cred, void *value,
					const struct security_operations *sop)
{
	lsm_set_blob(&cred->security, value, sop->order);
}

static inline int lsm_set_init_cred(struct cred *cred, void *value,
					const struct security_operations *sop)
{
	if (cred->security == NULL) {
		cred->security = lsm_alloc_blob(GFP_KERNEL);
		if (cred->security == NULL)
			return -ENOMEM;
	}

	lsm_set_blob(&cred->security, value, sop->order);
	return 0;
}

static inline void *lsm_get_file(const struct file *file,
					const struct security_operations *sop)
{
	return lsm_get_blob(file->f_security, sop->order);
}

static inline void lsm_set_file(struct file *file, void *value,
					const struct security_operations *sop)
{
	lsm_set_blob(&file->f_security, value, sop->order);
}

static inline void *lsm_get_inode(const struct inode *inode,
					const struct security_operations *sop)
{
	return lsm_get_blob(inode->i_security, sop->order);
}

static inline void lsm_set_inode(struct inode *inode, void *value,
					const struct security_operations *sop)
{
	lsm_set_blob(&inode->i_security, value, sop->order);
}

static inline void *lsm_get_super(const struct super_block *super,
					const struct security_operations *sop)
{
	return lsm_get_blob(super->s_security, sop->order);
}

static inline void lsm_set_super(struct super_block *super, void *value,
					const struct security_operations *sop)
{
	lsm_set_blob(&super->s_security, value, sop->order);
}

static inline void *lsm_get_ipc(const struct kern_ipc_perm *ipc,
					const struct security_operations *sop)
{
	return lsm_get_blob(ipc->security, sop->order);
}

static inline void lsm_set_ipc(struct kern_ipc_perm *ipc, void *value,
					const struct security_operations *sop)
{
	lsm_set_blob(&ipc->security, value, sop->order);
}

static inline void *lsm_get_msg(const struct msg_msg *msg,
					const struct security_operations *sop)
{
	return lsm_get_blob(msg->security, sop->order);
}

static inline void lsm_set_msg(struct msg_msg *msg, void *value,
					const struct security_operations *sop)
{
	lsm_set_blob(&msg->security, value, sop->order);
}

#ifdef CONFIG_KEYS
static inline void *lsm_get_key(const struct key *key,
					const struct security_operations *sop)
{
	return lsm_get_blob(key->security, sop->order);
}

static inline void lsm_set_key(struct key *key, void *value,
					const struct security_operations *sop)
{
	lsm_set_blob(&key->security, value, sop->order);
}
#endif

static inline void *lsm_get_sock(const struct sock *sock,
					const struct security_operations *sop)
{
	return lsm_get_blob(sock->sk_security, sop->order);
}

static inline void lsm_set_sock(struct sock *sock, void *value,
					const struct security_operations *sop)
{
	lsm_set_blob(&sock->sk_security, value, sop->order);
}

#endif /* ! _LINUX_LSM_H */
