/*
 * linux/fs/ext3cow/ioctl.c
 *
 * Copyright (C) 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 */

#include <linux/mount.h>
#include <linux/compat.h>
#include <asm/uaccess.h>
#include "ext3cow.h"

long ext3cow_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = filp->f_dentry->d_inode;
	struct ext3cow_inode_info *ei = EXT3COW_I(inode);
	unsigned int flags;
	unsigned short rsv_window_size;

	ext3cow_debug ("cmd = %u, arg = %lu\n", cmd, arg);

	switch (cmd) {
	/* Some IOCTLs for version */
	case EXT3COW_IOC_TAKESNAPSHOT:
	    return (unsigned int)ext3cow_take_snapshot(inode->i_sb);
	case EXT3COW_IOC_GETEPOCH:
	    return (unsigned int)EXT3COW_S_EPOCHNUMBER(inode->i_sb);
	case EXT3COW_IOC_GETFLAGS:
		ext3cow_get_inode_flags(ei);
		flags = ei->i_flags & EXT3COW_FL_USER_VISIBLE;
		return put_user(flags, (int __user *) arg);
	case EXT3COW_IOC_SETFLAGS: {
		handle_t *handle = NULL;
		int err;
		struct ext3cow_iloc iloc;
		unsigned int oldflags;
		unsigned int jflag;

		if (!inode_owner_or_capable(inode))
			return -EACCES;

		if (get_user(flags, (int __user *) arg))
			return -EFAULT;

		err = mnt_want_write_file(filp);
		if (err)
			return err;

		flags = ext3cow_mask_flags(inode->i_mode, flags);

		mutex_lock(&inode->i_mutex);

		/* Is it quota file? Do not allow user to mess with it */
		err = -EPERM;
		if (IS_NOQUOTA(inode))
			goto flags_out;

		oldflags = ei->i_flags;

		/* The JOURNAL_DATA flag is modifiable only by root */
		jflag = flags & EXT3COW_JOURNAL_DATA_FL;

		/*
		 * The IMMUTABLE and APPEND_ONLY flags can only be changed by
		 * the relevant capability.
		 *
		 * This test looks nicer. Thanks to Pauline Middelink
		 */
		if ((flags ^ oldflags) & (EXT3COW_APPEND_FL | EXT3COW_IMMUTABLE_FL)) {
			if (!capable(CAP_LINUX_IMMUTABLE))
				goto flags_out;
		}

		/*
		 * The JOURNAL_DATA flag can only be changed by
		 * the relevant capability.
		 */
		if ((jflag ^ oldflags) & (EXT3COW_JOURNAL_DATA_FL)) {
			if (!capable(CAP_SYS_RESOURCE))
				goto flags_out;
		}

		handle = ext3cow_journal_start(inode, 1);
		if (IS_ERR(handle)) {
			err = PTR_ERR(handle);
			goto flags_out;
		}
		if (IS_SYNC(inode))
			handle->h_sync = 1;
		err = ext3cow_reserve_inode_write(handle, inode, &iloc);
		if (err)
			goto flags_err;

		flags = flags & EXT3COW_FL_USER_MODIFIABLE;
		flags |= oldflags & ~EXT3COW_FL_USER_MODIFIABLE;
		ei->i_flags = flags;

		ext3cow_set_inode_flags(inode);
		inode->i_ctime = CURRENT_TIME_SEC;

		err = ext3cow_mark_iloc_dirty(handle, inode, &iloc);
flags_err:
		ext3cow_journal_stop(handle);
		if (err)
			goto flags_out;

		if ((jflag ^ oldflags) & (EXT3COW_JOURNAL_DATA_FL))
			err = ext3cow_change_inode_journal_flag(inode, jflag);
flags_out:
		mutex_unlock(&inode->i_mutex);
		mnt_drop_write_file(filp);
		return err;
	}
	case EXT3COW_IOC_GETVERSION:
	case EXT3COW_IOC_GETVERSION_OLD:
		return put_user(inode->i_generation, (int __user *) arg);
	case EXT3COW_IOC_SETVERSION:
	case EXT3COW_IOC_SETVERSION_OLD: {
		handle_t *handle;
		struct ext3cow_iloc iloc;
		__u32 generation;
		int err;

		if (!inode_owner_or_capable(inode))
			return -EPERM;

		err = mnt_want_write_file(filp);
		if (err)
			return err;
		if (get_user(generation, (int __user *) arg)) {
			err = -EFAULT;
			goto setversion_out;
		}

		mutex_lock(&inode->i_mutex);
		handle = ext3cow_journal_start(inode, 1);
		if (IS_ERR(handle)) {
			err = PTR_ERR(handle);
			goto unlock_out;
		}
		err = ext3cow_reserve_inode_write(handle, inode, &iloc);
		if (err == 0) {
			inode->i_ctime = CURRENT_TIME_SEC;
			inode->i_generation = generation;
			err = ext3cow_mark_iloc_dirty(handle, inode, &iloc);
		}
		ext3cow_journal_stop(handle);

unlock_out:
		mutex_unlock(&inode->i_mutex);
setversion_out:
		mnt_drop_write_file(filp);
		return err;
	}
	case EXT3COW_IOC_GETRSVSZ:
		if (test_opt(inode->i_sb, RESERVATION)
			&& S_ISREG(inode->i_mode)
			&& ei->i_block_alloc_info) {
			rsv_window_size = ei->i_block_alloc_info->rsv_window_node.rsv_goal_size;
			return put_user(rsv_window_size, (int __user *)arg);
		}
		return -ENOTTY;
	case EXT3COW_IOC_SETRSVSZ: {
		int err;

		if (!test_opt(inode->i_sb, RESERVATION) ||!S_ISREG(inode->i_mode))
			return -ENOTTY;

		err = mnt_want_write_file(filp);
		if (err)
			return err;

		if (!inode_owner_or_capable(inode)) {
			err = -EACCES;
			goto setrsvsz_out;
		}

		if (get_user(rsv_window_size, (int __user *)arg)) {
			err = -EFAULT;
			goto setrsvsz_out;
		}

		if (rsv_window_size > EXT3COW_MAX_RESERVE_BLOCKS)
			rsv_window_size = EXT3COW_MAX_RESERVE_BLOCKS;

		/*
		 * need to allocate reservation structure for this inode
		 * before set the window size
		 */
		mutex_lock(&ei->truncate_mutex);
		if (!ei->i_block_alloc_info)
			ext3cow_init_block_alloc_info(inode);

		if (ei->i_block_alloc_info){
			struct ext3cow_reserve_window_node *rsv = &ei->i_block_alloc_info->rsv_window_node;
			rsv->rsv_goal_size = rsv_window_size;
		}
		mutex_unlock(&ei->truncate_mutex);
setrsvsz_out:
		mnt_drop_write_file(filp);
		return err;
	}
	case EXT3COW_IOC_GROUP_EXTEND: {
		ext3cow_fsblk_t n_blocks_count;
		struct super_block *sb = inode->i_sb;
		int err, err2;

		if (!capable(CAP_SYS_RESOURCE))
			return -EPERM;

		err = mnt_want_write_file(filp);
		if (err)
			return err;

		if (get_user(n_blocks_count, (__u32 __user *)arg)) {
			err = -EFAULT;
			goto group_extend_out;
		}
		err = ext3cow_group_extend(sb, EXT3COW_SB(sb)->s_es, n_blocks_count);
		journal_lock_updates(EXT3COW_SB(sb)->s_journal);
		err2 = journal_flush(EXT3COW_SB(sb)->s_journal);
		journal_unlock_updates(EXT3COW_SB(sb)->s_journal);
		if (err == 0)
			err = err2;
group_extend_out:
		mnt_drop_write_file(filp);
		return err;
	}
	case EXT3COW_IOC_GROUP_ADD: {
		struct ext3cow_new_group_data input;
		struct super_block *sb = inode->i_sb;
		int err, err2;

		if (!capable(CAP_SYS_RESOURCE))
			return -EPERM;

		err = mnt_want_write_file(filp);
		if (err)
			return err;

		if (copy_from_user(&input, (struct ext3cow_new_group_input __user *)arg,
				sizeof(input))) {
			err = -EFAULT;
			goto group_add_out;
		}

		err = ext3cow_group_add(sb, &input);
		journal_lock_updates(EXT3COW_SB(sb)->s_journal);
		err2 = journal_flush(EXT3COW_SB(sb)->s_journal);
		journal_unlock_updates(EXT3COW_SB(sb)->s_journal);
		if (err == 0)
			err = err2;
group_add_out:
		mnt_drop_write_file(filp);
		return err;
	}
	case FITRIM: {

		struct super_block *sb = inode->i_sb;
		struct fstrim_range range;
		int ret = 0;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (copy_from_user(&range, (struct fstrim_range __user *)arg,
				   sizeof(range)))
			return -EFAULT;

		ret = ext3cow_trim_fs(sb, &range);
		if (ret < 0)
			return ret;

		if (copy_to_user((struct fstrim_range __user *)arg, &range,
				 sizeof(range)))
			return -EFAULT;

		return 0;
	}

	default:
		return -ENOTTY;
	}
}

#ifdef CONFIG_COMPAT
long ext3cow_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	/* These are just misnamed, they actually get/put from/to user an int */
	switch (cmd) {
	case EXT3COW_IOC32_GETFLAGS:
		cmd = EXT3COW_IOC_GETFLAGS;
		break;
	case EXT3COW_IOC32_SETFLAGS:
		cmd = EXT3COW_IOC_SETFLAGS;
		break;
	case EXT3COW_IOC32_GETVERSION:
		cmd = EXT3COW_IOC_GETVERSION;
		break;
	case EXT3COW_IOC32_SETVERSION:
		cmd = EXT3COW_IOC_SETVERSION;
		break;
	case EXT3COW_IOC32_GROUP_EXTEND:
		cmd = EXT3COW_IOC_GROUP_EXTEND;
		break;
	case EXT3COW_IOC32_GETVERSION_OLD:
		cmd = EXT3COW_IOC_GETVERSION_OLD;
		break;
	case EXT3COW_IOC32_SETVERSION_OLD:
		cmd = EXT3COW_IOC_SETVERSION_OLD;
		break;
#ifdef CONFIG_JBD_DEBUG
	case EXT3COW_IOC32_WAIT_FOR_READONLY:
		cmd = EXT3COW_IOC_WAIT_FOR_READONLY;
		break;
#endif
	case EXT3COW_IOC32_GETRSVSZ:
		cmd = EXT3COW_IOC_GETRSVSZ;
		break;
	case EXT3COW_IOC32_SETRSVSZ:
		cmd = EXT3COW_IOC_SETRSVSZ;
		break;
	case EXT3COW_IOC_GROUP_ADD:
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return ext3cow_ioctl(file, cmd, (unsigned long) compat_ptr(arg));
}
#endif
