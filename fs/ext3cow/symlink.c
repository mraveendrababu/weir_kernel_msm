/*
 *  linux/fs/ext3cow/symlink.c
 *
 * Only fast symlinks left here - the rest is done by generic code. AV, 1999
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/symlink.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext3cow symlink handling code
 */

#include <linux/namei.h>
#include "ext3cow.h"
#include "xattr.h"

static void * ext3cow_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct ext3cow_inode_info *ei = EXT3COW_I(dentry->d_inode);
	nd_set_link(nd, (char*)ei->i_data);
	return NULL;
}

const struct inode_operations ext3cow_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
	.setattr	= ext3cow_setattr,
#ifdef CONFIG_EXT3COW_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext3cow_listxattr,
	.removexattr	= generic_removexattr,
#endif
};

const struct inode_operations ext3cow_fast_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= ext3cow_follow_link,
	.setattr	= ext3cow_setattr,
#ifdef CONFIG_EXT3COW_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext3cow_listxattr,
	.removexattr	= generic_removexattr,
#endif
};
