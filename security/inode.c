/*
 *  inode.c - securityfs
 *
 *  Copyright (C) 2005 Greg Kroah-Hartman <gregkh@suse.de>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License version
 *	2 as published by the Free Software Foundation.
 *
 *  Based on fs/debugfs/inode.c which had the following copyright notice:
 *    Copyright (C) 2004 Greg Kroah-Hartman <greg@kroah.com>
 *    Copyright (C) 2004 IBM Inc.
 */

/* #define DEBUG */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/magic.h>
#ifdef CONFIG_SECURITY
#include <linux/lsm.h>
#endif

static struct vfsmount *mount;
static int mount_count;

static inline int positive(struct dentry *dentry)
{
	return dentry->d_inode && !d_unhashed(dentry);
}

static int fill_super(struct super_block *sb, void *data, int silent)
{
	static struct tree_descr files[] = {{""}};

	return simple_fill_super(sb, SECURITYFS_MAGIC, files);
}

static struct dentry *get_sb(struct file_system_type *fs_type,
		  int flags, const char *dev_name,
		  void *data)
{
	return mount_single(fs_type, flags, data, fill_super);
}

static struct file_system_type fs_type = {
	.owner =	THIS_MODULE,
	.name =		"securityfs",
	.mount =	get_sb,
	.kill_sb =	kill_litter_super,
};

/**
 * securityfs_create_file - create a file in the securityfs filesystem
 *
 * @name: a pointer to a string containing the name of the file to create.
 * @mode: the permission that the file should have
 * @parent: a pointer to the parent dentry for this file.  This should be a
 *          directory dentry if set.  If this parameter is %NULL, then the
 *          file will be created in the root of the securityfs filesystem.
 * @data: a pointer to something that the caller will want to get to later
 *        on.  The inode.i_private pointer will point to this value on
 *        the open() call.
 * @fops: a pointer to a struct file_operations that should be used for
 *        this file.
 *
 * This is the basic "create a file" function for securityfs.  It allows for a
 * wide range of flexibility in creating a file, or a directory (if you
 * want to create a directory, the securityfs_create_dir() function is
 * recommended to be used instead).
 *
 * This function returns a pointer to a dentry if it succeeds.  This
 * pointer must be passed to the securityfs_remove() function when the file is
 * to be removed (no automatic cleanup happens if your module is unloaded,
 * you are responsible here).  If an error occurs, the function will return
 * the erorr value (via ERR_PTR).
 *
 * If securityfs is not enabled in the kernel, the value %-ENODEV is
 * returned.
 */
struct dentry *securityfs_create_file(const char *name, umode_t mode,
				   struct dentry *parent, void *data,
				   const struct file_operations *fops)
{
	struct dentry *dentry;
	int is_dir = S_ISDIR(mode);
	struct inode *dir, *inode;
	int error;

	if (!is_dir) {
		BUG_ON(!fops);
		mode = (mode & S_IALLUGO) | S_IFREG;
	}

	pr_debug("securityfs: creating file '%s'\n",name);

	error = simple_pin_fs(&fs_type, &mount, &mount_count);
	if (error)
		return ERR_PTR(error);

	if (!parent)
		parent = mount->mnt_root;

	dir = parent->d_inode;

	mutex_lock(&dir->i_mutex);
	dentry = lookup_one_len(name, parent, strlen(name));
	if (IS_ERR(dentry))
		goto out;

	if (dentry->d_inode) {
		error = -EEXIST;
		goto out1;
	}

	inode = new_inode(dir->i_sb);
	if (!inode) {
		error = -ENOMEM;
		goto out1;
	}

	inode->i_ino = get_next_ino();
	inode->i_mode = mode;
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	inode->i_private = data;
	if (is_dir) {
		inode->i_op = &simple_dir_inode_operations;
		inode->i_fop = &simple_dir_operations;
		inc_nlink(inode);
		inc_nlink(dir);
	} else {
		inode->i_fop = fops;
	}
	d_instantiate(dentry, inode);
	dget(dentry);
	mutex_unlock(&dir->i_mutex);
	return dentry;

out1:
	dput(dentry);
	dentry = ERR_PTR(error);
out:
	mutex_unlock(&dir->i_mutex);
	simple_release_fs(&mount, &mount_count);
	return dentry;
}
EXPORT_SYMBOL_GPL(securityfs_create_file);

/**
 * securityfs_create_dir - create a directory in the securityfs filesystem
 *
 * @name: a pointer to a string containing the name of the directory to
 *        create.
 * @parent: a pointer to the parent dentry for this file.  This should be a
 *          directory dentry if set.  If this parameter is %NULL, then the
 *          directory will be created in the root of the securityfs filesystem.
 *
 * This function creates a directory in securityfs with the given @name.
 *
 * This function returns a pointer to a dentry if it succeeds.  This
 * pointer must be passed to the securityfs_remove() function when the file is
 * to be removed (no automatic cleanup happens if your module is unloaded,
 * you are responsible here).  If an error occurs, %NULL will be returned.
 *
 * If securityfs is not enabled in the kernel, the value %-ENODEV is
 * returned.  It is not wise to check for this value, but rather, check for
 * %NULL or !%NULL instead as to eliminate the need for #ifdef in the calling
 * code.
 */
struct dentry *securityfs_create_dir(const char *name, struct dentry *parent)
{
	return securityfs_create_file(name,
				      S_IFDIR | S_IRWXU | S_IRUGO | S_IXUGO,
				      parent, NULL, NULL);
}
EXPORT_SYMBOL_GPL(securityfs_create_dir);

/**
 * securityfs_remove - removes a file or directory from the securityfs filesystem
 *
 * @dentry: a pointer to a the dentry of the file or directory to be removed.
 *
 * This function removes a file or directory in securityfs that was previously
 * created with a call to another securityfs function (like
 * securityfs_create_file() or variants thereof.)
 *
 * This function is required to be called in order for the file to be
 * removed. No automatic cleanup of files will happen when a module is
 * removed; you are responsible here.
 */
void securityfs_remove(struct dentry *dentry)
{
	struct dentry *parent;

	if (!dentry || IS_ERR(dentry))
		return;

	parent = dentry->d_parent;
	if (!parent || !parent->d_inode)
		return;

	mutex_lock(&parent->d_inode->i_mutex);
	if (positive(dentry)) {
		if (dentry->d_inode) {
			if (S_ISDIR(dentry->d_inode->i_mode))
				simple_rmdir(parent->d_inode, dentry);
			else
				simple_unlink(parent->d_inode, dentry);
			dput(dentry);
		}
	}
	mutex_unlock(&parent->d_inode->i_mutex);
	simple_release_fs(&mount, &mount_count);
}
EXPORT_SYMBOL_GPL(securityfs_remove);

#ifdef CONFIG_SECURITY
static struct dentry *lsm_dentry;
static ssize_t lsm_read(struct file *filp, char __user *buf, size_t count,
			loff_t *ppos)
{
	struct security_operations *sop;
	char *data;
	int len;

	data = kzalloc(COMPOSER_NAMES_MAX + 1, GFP_KERNEL);
	if (data == NULL)
		return -ENOMEM;

	list_for_each_entry(sop, &lsm_hooks[lsm_name], list[lsm_name]) {
		strcat(data, sop->name);
		strcat(data, ",");
	}
	len = strlen(data);
	if (len > 1)
		data[len-1] = '\n';

	len = simple_read_from_buffer(buf, count, ppos, data, len);
	kfree(data);

	return len;
}

static const struct file_operations lsm_ops = {
	.read = lsm_read,
	.llseek = generic_file_llseek,
};

static struct dentry *present_dentry;
static ssize_t present_read(struct file *filp, char __user *buf, size_t count,
			loff_t *ppos)
{
	struct security_operations *sop = lsm_present;
	char *raw;
	char *data;
	int len;

	if (sop)
		raw = sop->name;
	else
		raw = "(none)";
	len = strlen(raw);

	data = kstrdup(raw, GFP_KERNEL);
	if (data == NULL)
		return -ENOMEM;

	data[len] = '\n';
	len = simple_read_from_buffer(buf, count, ppos, data, len + 1);
	kfree(data);

	return len;
}

static const struct file_operations present_ops = {
	.read = present_read,
	.llseek = generic_file_llseek,
};
#endif /* CONFIG_SECURITY */

static struct kobject *security_kobj;

static int __init securityfs_init(void)
{
	int retval;

	security_kobj = kobject_create_and_add("security", kernel_kobj);
	if (!security_kobj)
		return -EINVAL;

	retval = register_filesystem(&fs_type);
	if (retval) {
		kobject_put(security_kobj);
		return retval;
	}
#ifdef CONFIG_SECURITY
	lsm_dentry = securityfs_create_file("lsm", S_IRUGO, NULL, NULL,
		&lsm_ops);
	present_dentry = securityfs_create_file("present", S_IRUGO, NULL, NULL,
		&present_ops);
#endif /* CONFIG_SECURITY */
	return 0;
}

core_initcall(securityfs_init);
MODULE_LICENSE("GPL");

