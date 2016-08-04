/*
 *  linux/fs/ext3cow/file.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext3cow fs regular file handling primitives
 *
 *  64-bit file support on 64-bit platforms by Jakub Jelinek
 *	(jj@sunsite.ms.mff.cuni.cz)
 */

#include <linux/quotaops.h>
#include "ext3cow.h"
#include "xattr.h"
#include "acl.h"

/*
 * Called when an inode is released. Note that this is different
 * from ext3cow_file_open: open gets called at every open, but release
 * gets called only when /all/ the files are closed.
 */
static int ext3cow_release_file (struct inode * inode, struct file * filp)
{
	if (ext3cow_test_inode_state(inode, EXT3COW_STATE_FLUSH_ON_CLOSE)) {
		filemap_flush(inode->i_mapping);
		ext3cow_clear_inode_state(inode, EXT3COW_STATE_FLUSH_ON_CLOSE);
	}
	/* if we are the last writer on the inode, drop the block reservation */
	if ((filp->f_mode & FMODE_WRITE) &&
			(atomic_read(&inode->i_writecount) == 1))
	{
		mutex_lock(&EXT3COW_I(inode)->truncate_mutex);
		ext3cow_discard_reservation(inode);
		mutex_unlock(&EXT3COW_I(inode)->truncate_mutex);
	}
	if (is_dx(inode) && filp->private_data)
		ext3cow_htree_free_dir_info(filp->private_data);

	return 0;
}

static ssize_t
ext3cow_file_write(struct kiocb *iocb, const struct iovec *iov,
                unsigned long nr_segs, loff_t pos)
{
        struct file *file = iocb->ki_filp;
        struct inode *inode = file->f_path.dentry->d_inode;
	struct inode *dir   = file->f_path.dentry->d_parent->d_inode;
        ssize_t ret = 0;
        int err = 0;
  
	/* This is the place where we create a new version on write -znjp */
	if(EXT3COW_S_EPOCHNUMBER(inode->i_sb) > EXT3COW_I_EPOCHNUMBER(inode)){
	    err = ext3cow_dup_inode(dir, inode);
	    if(err)
		return err;
	}

	ret = generic_file_aio_write(iocb, iov, nr_segs, pos);
	return ret;
}

const struct file_operations ext3cow_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= do_sync_read,
	.write		= do_sync_write,
	.aio_read	= generic_file_aio_read,
	.aio_write	= ext3cow_file_write,
	.unlocked_ioctl	= ext3cow_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ext3cow_compat_ioctl,
#endif
	.mmap		= generic_file_mmap,
	.open		= dquot_file_open,
	.release	= ext3cow_release_file,
	.fsync		= ext3cow_sync_file,
	.splice_read	= generic_file_splice_read,
	.splice_write	= generic_file_splice_write,
};

const struct inode_operations ext3cow_file_inode_operations = {
	.setattr	= ext3cow_setattr,
#ifdef CONFIG_EXT3COW_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext3cow_listxattr,
	.removexattr	= generic_removexattr,
#endif
	.get_acl	= ext3cow_get_acl,
	.fiemap		= ext3cow_fiemap,
};

