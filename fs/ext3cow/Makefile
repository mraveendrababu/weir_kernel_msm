#
# Makefile for the linux ext3cow-filesystem routines.
#

obj-$(CONFIG_EXT3COW_FS) += ext3cow.o

ext3cow-y	:= balloc.o bitmap.o dir.o file.o fsync.o ialloc.o inode.o \
	   ioctl.o namei.o super.o symlink.o hash.o resize.o ext3cow_jbd.o

ext3cow-$(CONFIG_EXT3COW_FS_XATTR)	 += xattr.o xattr_user.o xattr_trusted.o
ext3cow-$(CONFIG_EXT3COW_FS_POSIX_ACL) += acl.o
ext3cow-$(CONFIG_EXT3COW_FS_SECURITY)	 += xattr_security.o
