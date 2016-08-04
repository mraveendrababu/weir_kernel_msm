/*
 *  linux/fs/ext3cow/dir.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/dir.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext3cow directory handling functions
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *
 * Hash Tree Directory indexing (c) 2001  Daniel Phillips
 *
 */

#include "ext3cow.h"

static unsigned char ext3cow_filetype_table[] = {
	DT_UNKNOWN, DT_REG, DT_DIR, DT_CHR, DT_BLK, DT_FIFO, DT_SOCK, DT_LNK
};

static int ext3cow_readdir(struct file *, void *, filldir_t);
static int ext3cow_dx_readdir(struct file * filp,
			   void * dirent, filldir_t filldir);
static int ext3cow_release_dir (struct inode * inode,
				struct file * filp);

const struct file_operations ext3cow_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= ext3cow_readdir,		/* we take BKL. needed?*/
	.unlocked_ioctl	= ext3cow_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ext3cow_compat_ioctl,
#endif
	.fsync		= ext3cow_sync_file,	/* BKL held */
	.release	= ext3cow_release_dir,
};


static unsigned char get_dtype(struct super_block *sb, int filetype)
{
	if (!EXT3COW_HAS_INCOMPAT_FEATURE(sb, EXT3COW_FEATURE_INCOMPAT_FILETYPE) ||
	    (filetype >= EXT3COW_FT_MAX))
		return DT_UNKNOWN;

	return (ext3cow_filetype_table[filetype]);
}

static int ext3cow_readversions(struct file * filp, void * dirent, 
                                filldir_t filldir)
{
  int error = 0;
  unsigned long offset;
  int i, stored;
  struct buffer_head *bh;
  struct ext3cow_dir_entry_2 * de;
  struct super_block * sb;
  int err;
  struct inode *dir = filp->f_dentry->d_inode;
  char *at;
  unsigned long ino;
  int ref_len = filp->f_dentry->d_name.len -1;
  
  sb = dir->i_sb;
  
  stored = 0;
  bh = NULL;
  offset = filp->f_pos & (sb->s_blocksize - 1);
  
  at = strrchr(filp->f_dentry->d_name.name, EXT3COW_FLUX_TOKEN);
  
  while (!error && !stored && filp->f_pos < dir->i_size) {
    unsigned long blk = (filp->f_pos) >> EXT3COW_BLOCK_SIZE_BITS(sb);
    struct buffer_head map_bh;

    bh = NULL;
    map_bh.b_state = 0;
		err = ext3cow_get_blocks_handle(NULL, dir, blk, 1,
					&map_bh, 0);
		if (err > 0) {
			page_cache_sync_readahead(sb->s_bdev->bd_inode->i_mapping,
				&filp->f_ra,
				filp,
				map_bh.b_blocknr >>
					(PAGE_CACHE_SHIFT - dir->i_blkbits),
				1);
			bh = ext3cow_bread(NULL, dir, blk, 0, &err);
		}

		/*
		 * We ignore I/O errors on directories so users have a chance
		 * of recovering data when there's a bad sector
		 */
    if (!bh) {
      ext3cow_error (sb, "ext3cow_versions",
                     "directory #%lu contains a hole at offset %lu",
                     dir->i_ino, (unsigned long)filp->f_pos);
      /* corrupt size?  Maybe no more blocks to read */
                      if (filp->f_pos > dir->i_blocks << 9)
                                break;
      filp->f_pos += sb->s_blocksize - offset;
      continue;
    }
    
  ver_revalidate:
    /* If the dir block has changed since the last call to
     * readdir(2), then we might be pointing to an invalid
     * dirent right now.  Scan from the start of the block
     * to make sure. */
    if (filp->f_version != dir->i_version) {
      for (i = 0; i < sb->s_blocksize && i < offset; ) {
        de = (struct ext3cow_dir_entry_2 *) 
          (bh->b_data + i);
                               /* It's too expensive to do a full
                                * dirent test each time round this
                                * loop, but we do have to test at
                                * least that it is non-zero.  A
                                * failure will be detected in the
                                * dirent test below. */
        if (le16_to_cpu(de->rec_len) <
            EXT3COW_DIR_REC_LEN(1))
          break;
        i += le16_to_cpu(de->rec_len);
      }
      offset = i;
      filp->f_pos = (filp->f_pos & ~(sb->s_blocksize - 1))
        | offset;
      filp->f_version = dir->i_version;
    }
    
    while (!error && filp->f_pos < dir->i_size 
           && offset < sb->s_blocksize) {
      de = (struct ext3cow_dir_entry_2 *) (bh->b_data + offset);
      if (!ext3cow_check_dir_entry ("ext3cow_readversions", dir, de,
                                    bh, offset)) {
                               /* On error, skip the f_pos to the
           next block. */
        filp->f_pos = (filp->f_pos |
                       (sb->s_blocksize - 1)) + 1;
        brelse (bh);
        return stored;
      }
      offset += le16_to_cpu(de->rec_len);
      
      if (le32_to_cpu(de->inode)){
        unsigned long version = filp->f_version;
        unsigned char d_type = DT_UNKNOWN;
        
        /* We might block in the next section
         * if the data destination is
         * currently swapped out.  So, use a
         * version stamp to detect whether or
         * not the directory has been modified
         * during the copy operation.
         */
        if (EXT3COW_HAS_INCOMPAT_FEATURE(sb,
                                         EXT3COW_FEATURE_INCOMPAT_FILETYPE)
            && de->file_type < EXT3COW_FT_MAX)
          d_type =
            ext3cow_filetype_table[de->file_type];
        if (de->name_len == ref_len
            && strncmp(filp->f_dentry->d_name.name, de->name, ref_len)==0) {
          
          struct inode * inde;
          char * name;
          
          name = kmalloc(EXT3COW_NAME_LEN, GFP_KERNEL);
          strncpy(name, de->name, de->name_len);
          inde = ext3cow_iget(dir->i_sb, de->inode);
          
          if (de->death_epoch!=0 && de->birth_epoch!=de->death_epoch) {
            name[de->name_len]='\0';
            sprintf(name,"%s@%d",name, de->death_epoch);
            error = filldir(dirent, name,
                            strlen(name),
                            filp->f_pos,
                            le32_to_cpu(inde->i_ino),
                            d_type);
            stored++;
          }
          
          while (EXT3COW_I(inde)->i_next_inode!=0) {
            name[de->name_len]='\0';
            sprintf(name,"%s@%d",name, EXT3COW_I_EPOCHNUMBER(inde));
            error = filldir(dirent, name,
                            strlen(name),
                            filp->f_pos,
                            le32_to_cpu(inde->i_ino),
                            d_type);
            ino = EXT3COW_I(inde)->i_next_inode;
            iput(inde);
            inde = ext3cow_iget(dir->i_sb, ino);
            stored++;
          }
          
          kfree(name);
          iput(inde);
                    
          if (error)
            break;
          
          if (!stored && 
              EXT3COW_IS_DIRENT_SCOPED(de, EXT3COW_I_EPOCHNUMBER(dir))) {
            error = filldir(dirent, de->name,
                            de->name_len,
                            filp->f_pos,
                            le32_to_cpu(de->inode),
                            d_type);
          }
            
          if (error)
            break;
          if (version != filp->f_version)
            goto ver_revalidate;
          stored ++;
        }
      }
      
      filp->f_pos += le16_to_cpu(de->rec_len);
    }
    offset = 0;
    brelse (bh);
  }
  return 0;
}
        
////
int ext3cow_check_dir_entry (const char * function, struct inode * dir,
			  struct ext3cow_dir_entry_2 * de,
			  struct buffer_head * bh,
			  unsigned long offset)
{
	const char * error_msg = NULL;
	const int rlen = ext3cow_rec_len_from_disk(de->rec_len);
	unsigned int current_epoch = EXT3COW_S_EPOCHNUMBER(dir->i_sb);

	if (unlikely(rlen < EXT3COW_DIR_REC_LEN(1)))
		error_msg = "rec_len is smaller than minimal";
	else if (unlikely(rlen % 4 != 0))
		error_msg = "rec_len % 4 != 0";
	else if (unlikely(rlen < EXT3COW_DIR_REC_LEN(de->name_len)))
		error_msg = "rec_len is too small for name_len";
	else if (unlikely((((char *) de - bh->b_data) + rlen > dir->i_sb->s_blocksize)))
		error_msg = "directory entry across blocks";
	else if (unlikely(le32_to_cpu(de->inode) >
			le32_to_cpu(EXT3COW_SB(dir->i_sb)->s_es->s_inodes_count)))
		error_msg = "inode out of bounds";
	/* Some bounds on versioned entries -znjp*/
	else if (le32_to_cpu(de->death_epoch) != EXT3COW_DIRENT_ALIVE && 
	    le32_to_cpu(de->birth_epoch) > le32_to_cpu(de->death_epoch))
	    error_msg = "entry died before it was born";
	else if (le32_to_cpu(de->birth_epoch) > current_epoch)
	    error_msg = "entry was born in the future";
	else if (le32_to_cpu(de->death_epoch) > current_epoch)
	    error_msg = "entry has already died in the future";

	if (unlikely(error_msg != NULL))
		ext3cow_error (dir->i_sb, function,
			"bad entry in directory #%lu: %s - "
                        "offset=%lu, inode=%lu, rec_len=%d, name_len=%d, "
      "birth_epoch=%d death_epoch=%d",
			dir->i_ino, error_msg, offset,
			(unsigned long) le32_to_cpu(de->inode),
			rlen, de->name_len, de->birth_epoch, de->death_epoch);
	return error_msg == NULL ? 1 : 0;
}

static int ext3cow_readdir(struct file * filp,
			 void * dirent, filldir_t filldir)
{
	int error = 0;
	unsigned long offset;
	int i, stored;
	struct ext3cow_dir_entry_2 *de;
	struct super_block *sb;
	int err;
	struct inode *inode = filp->f_path.dentry->d_inode;
	int ret = 0;
	int dir_has_error = 0;
      
	/* is this a version listing? */
	if (filp->f_dentry->d_name.name[filp->f_dentry->d_name.len-1] ==  
	    EXT3COW_FLUX_TOKEN)
		return ext3cow_readversions(filp, dirent, filldir);

	sb = inode->i_sb;

	if (EXT3COW_HAS_COMPAT_FEATURE(inode->i_sb,
				    EXT3COW_FEATURE_COMPAT_DIR_INDEX) &&
	    ((EXT3COW_I(inode)->i_flags & EXT3COW_INDEX_FL) ||
	     ((inode->i_size >> sb->s_blocksize_bits) == 1))) {
		err = ext3cow_dx_readdir(filp, dirent, filldir);
		if (err != ERR_BAD_DX_DIR) {
			ret = err;
			goto out;
		}
		/*
		 * We don't set the inode dirty flag since it's not
		 * critical that it get flushed back to the disk.
		 */
		EXT3COW_I(filp->f_path.dentry->d_inode)->i_flags &= ~EXT3COW_INDEX_FL;
	}
	stored = 0;
	offset = filp->f_pos & (sb->s_blocksize - 1);

	while (!error && !stored && filp->f_pos < inode->i_size) {
		unsigned long blk = filp->f_pos >> EXT3COW_BLOCK_SIZE_BITS(sb);
		struct buffer_head map_bh;
		struct buffer_head *bh = NULL;

		map_bh.b_state = 0;
		err = ext3cow_get_blocks_handle(NULL, inode, blk, 1, &map_bh, 0);
		if (err > 0) {
			pgoff_t index = map_bh.b_blocknr >>
					(PAGE_CACHE_SHIFT - inode->i_blkbits);
			if (!ra_has_index(&filp->f_ra, index))
				page_cache_sync_readahead(
					sb->s_bdev->bd_inode->i_mapping,
					&filp->f_ra, filp,
					index, 1);
			filp->f_ra.prev_pos = (loff_t)index << PAGE_CACHE_SHIFT;
			bh = ext3cow_bread(NULL, inode, blk, 0, &err);
		}

		/*
		 * We ignore I/O errors on directories so users have a chance
		 * of recovering data when there's a bad sector
		 */
		if (!bh) {
			if (!dir_has_error) {
				ext3cow_error(sb, __func__, "directory #%lu "
					"contains a hole at offset %lld",
					inode->i_ino, filp->f_pos);
				dir_has_error = 1;
			}
			/* corrupt size?  Maybe no more blocks to read */
			if (filp->f_pos > inode->i_blocks << 9)
				break;
			filp->f_pos += sb->s_blocksize - offset;
			continue;
		}

revalidate:
		/* If the dir block has changed since the last call to
		 * readdir(2), then we might be pointing to an invalid
		 * dirent right now.  Scan from the start of the block
		 * to make sure. */
		if (filp->f_version != inode->i_version) {
			for (i = 0; i < sb->s_blocksize && i < offset; ) {
				de = (struct ext3cow_dir_entry_2 *)
					(bh->b_data + i);
				/* It's too expensive to do a full
				 * dirent test each time round this
				 * loop, but we do have to test at
				 * least that it is non-zero.  A
				 * failure will be detected in the
				 * dirent test below. */
				if (ext3cow_rec_len_from_disk(de->rec_len) <
						EXT3COW_DIR_REC_LEN(1))
					break;
				i += ext3cow_rec_len_from_disk(de->rec_len);
			}
			offset = i;
			filp->f_pos = (filp->f_pos & ~(sb->s_blocksize - 1))
				| offset;
			filp->f_version = inode->i_version;
		}

		while (!error && filp->f_pos < inode->i_size
		       && offset < sb->s_blocksize) {
			de = (struct ext3cow_dir_entry_2 *) (bh->b_data + offset);
			if (!ext3cow_check_dir_entry ("ext3cow_readdir", inode, de,
						   bh, offset)) {
				/* On error, skip the f_pos to the
                                   next block. */
				filp->f_pos = (filp->f_pos |
						(sb->s_blocksize - 1)) + 1;
				brelse (bh);
				ret = stored;
				goto out;
			}
			offset += ext3cow_rec_len_from_disk(de->rec_len);
			if (le32_to_cpu(de->inode)  && 
          EXT3COW_IS_DIRENT_SCOPED(de, EXT3COW_I_EPOCHNUMBER(inode))) {
				/* We might block in the next section
				 * if the data destination is
				 * currently swapped out.  So, use a
				 * version stamp to detect whether or
				 * not the directory has been modified
				 * during the copy operation.
				 */
				u64 version = filp->f_version;

				error = filldir(dirent, de->name,
						de->name_len,
						filp->f_pos,
						le32_to_cpu(de->inode),
						get_dtype(sb, de->file_type));
				if (error)
					break;
				if (version != filp->f_version)
					goto revalidate;
				stored ++;
			}
			filp->f_pos += ext3cow_rec_len_from_disk(de->rec_len);
		}
		offset = 0;
		brelse (bh);
	}
out:
	return ret;
}

/*
 * These functions convert from the major/minor hash to an f_pos
 * value.
 *
 * Currently we only use major hash numer.  This is unfortunate, but
 * on 32-bit machines, the same VFS interface is used for lseek and
 * llseek, so if we use the 64 bit offset, then the 32-bit versions of
 * lseek/telldir/seekdir will blow out spectacularly, and from within
 * the ext2 low-level routine, we don't know if we're being called by
 * a 64-bit version of the system call or the 32-bit version of the
 * system call.  Worse yet, NFSv2 only allows for a 32-bit readdir
 * cookie.  Sigh.
 */
#define hash2pos(major, minor)	(major >> 1)
#define pos2maj_hash(pos)	((pos << 1) & 0xffffffff)
#define pos2min_hash(pos)	(0)

/*
 * This structure holds the nodes of the red-black tree used to store
 * the directory entry in hash order.
 */
struct fname {
	__u32		hash;
	__u32		minor_hash;
	struct rb_node	rb_hash;
	struct fname	*next;
	__u32		inode;
	__u8		name_len;
	__u8		file_type;
	char		name[0];
};

/*
 * This functoin implements a non-recursive way of freeing all of the
 * nodes in the red-black tree.
 */
static void free_rb_tree_fname(struct rb_root *root)
{
	struct rb_node	*n = root->rb_node;
	struct rb_node	*parent;
	struct fname	*fname;

	while (n) {
		/* Do the node's children first */
		if (n->rb_left) {
			n = n->rb_left;
			continue;
		}
		if (n->rb_right) {
			n = n->rb_right;
			continue;
		}
		/*
		 * The node has no children; free it, and then zero
		 * out parent's link to it.  Finally go to the
		 * beginning of the loop and try to free the parent
		 * node.
		 */
		parent = rb_parent(n);
		fname = rb_entry(n, struct fname, rb_hash);
		while (fname) {
			struct fname * old = fname;
			fname = fname->next;
			kfree (old);
		}
		if (!parent)
			*root = RB_ROOT;
		else if (parent->rb_left == n)
			parent->rb_left = NULL;
		else if (parent->rb_right == n)
			parent->rb_right = NULL;
		n = parent;
	}
}


static struct dir_private_info *ext3cow_htree_create_dir_info(loff_t pos)
{
	struct dir_private_info *p;

	p = kzalloc(sizeof(struct dir_private_info), GFP_KERNEL);
	if (!p)
		return NULL;
	p->curr_hash = pos2maj_hash(pos);
	p->curr_minor_hash = pos2min_hash(pos);
	return p;
}

void ext3cow_htree_free_dir_info(struct dir_private_info *p)
{
	free_rb_tree_fname(&p->root);
	kfree(p);
}

/*
 * Given a directory entry, enter it into the fname rb tree.
 */
int ext3cow_htree_store_dirent(struct file *dir_file, __u32 hash,
			     __u32 minor_hash,
			     struct ext3cow_dir_entry_2 *dirent)
{
	struct rb_node **p, *parent = NULL;
	struct fname * fname, *new_fn;
	struct dir_private_info *info;
	int len;

	info = (struct dir_private_info *) dir_file->private_data;
	p = &info->root.rb_node;

	/* Create and allocate the fname structure */
	len = sizeof(struct fname) + dirent->name_len + 1;
	new_fn = kzalloc(len, GFP_KERNEL);
	if (!new_fn)
		return -ENOMEM;
	new_fn->hash = hash;
	new_fn->minor_hash = minor_hash;
	new_fn->inode = le32_to_cpu(dirent->inode);
	new_fn->name_len = dirent->name_len;
	new_fn->file_type = dirent->file_type;
	memcpy(new_fn->name, dirent->name, dirent->name_len);
	new_fn->name[dirent->name_len] = 0;

	while (*p) {
		parent = *p;
		fname = rb_entry(parent, struct fname, rb_hash);

		/*
		 * If the hash and minor hash match up, then we put
		 * them on a linked list.  This rarely happens...
		 */
		if ((new_fn->hash == fname->hash) &&
		    (new_fn->minor_hash == fname->minor_hash)) {
			new_fn->next = fname->next;
			fname->next = new_fn;
			return 0;
		}

		if (new_fn->hash < fname->hash)
			p = &(*p)->rb_left;
		else if (new_fn->hash > fname->hash)
			p = &(*p)->rb_right;
		else if (new_fn->minor_hash < fname->minor_hash)
			p = &(*p)->rb_left;
		else /* if (new_fn->minor_hash > fname->minor_hash) */
			p = &(*p)->rb_right;
	}

	rb_link_node(&new_fn->rb_hash, parent, p);
	rb_insert_color(&new_fn->rb_hash, &info->root);
	return 0;
}



/*
 * This is a helper function for ext3cow_dx_readdir.  It calls filldir
 * for all entres on the fname linked list.  (Normally there is only
 * one entry on the linked list, unless there are 62 bit hash collisions.)
 */
static int call_filldir(struct file * filp, void * dirent,
			filldir_t filldir, struct fname *fname)
{
	struct dir_private_info *info = filp->private_data;
	loff_t	curr_pos;
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct super_block * sb;
	int error;

	sb = inode->i_sb;
	//printk(KERN_INFO, "Got %s\n", filp->f_path.dentry->d_name.name);
	if (!fname) {
		printk("call_filldir: called with null fname?!?\n");
		return 0;
	}
	curr_pos = hash2pos(fname->hash, fname->minor_hash);
	while (fname) {
		error = filldir(dirent, fname->name,
				fname->name_len, curr_pos,
				fname->inode,
				get_dtype(sb, fname->file_type));
		if (error) {
			filp->f_pos = curr_pos;
			info->extra_fname = fname;
			return error;
		}
		fname = fname->next;
	}
	return 0;
}

static int ext3cow_dx_readdir(struct file * filp,
			 void * dirent, filldir_t filldir)
{
	struct dir_private_info *info = filp->private_data;
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct fname *fname;
	int	ret;

	if (!info) {
		info = ext3cow_htree_create_dir_info(filp->f_pos);
		if (!info)
			return -ENOMEM;
		filp->private_data = info;
	}

	if (filp->f_pos == EXT3COW_HTREE_EOF)
		return 0;	/* EOF */

	/* Some one has messed with f_pos; reset the world */
	if (info->last_pos != filp->f_pos) {
		free_rb_tree_fname(&info->root);
		info->curr_node = NULL;
		info->extra_fname = NULL;
		info->curr_hash = pos2maj_hash(filp->f_pos);
		info->curr_minor_hash = pos2min_hash(filp->f_pos);
	}

	/*
	 * If there are any leftover names on the hash collision
	 * chain, return them first.
	 */
	if (info->extra_fname) {
		if (call_filldir(filp, dirent, filldir, info->extra_fname))
			goto finished;
		info->extra_fname = NULL;
		goto next_node;
	} else if (!info->curr_node)
		info->curr_node = rb_first(&info->root);

	while (1) {
		/*
		 * Fill the rbtree if we have no more entries,
		 * or the inode has changed since we last read in the
		 * cached entries.
		 */
		if ((!info->curr_node) ||
		    (filp->f_version != inode->i_version)) {
			info->curr_node = NULL;
			free_rb_tree_fname(&info->root);
			filp->f_version = inode->i_version;
			ret = ext3cow_htree_fill_tree(filp, info->curr_hash,
						   info->curr_minor_hash,
						   &info->next_hash);
			if (ret < 0)
				return ret;
			if (ret == 0) {
				filp->f_pos = EXT3COW_HTREE_EOF;
				break;
			}
			info->curr_node = rb_first(&info->root);
		}

		fname = rb_entry(info->curr_node, struct fname, rb_hash);
		info->curr_hash = fname->hash;
		info->curr_minor_hash = fname->minor_hash;
		if (call_filldir(filp, dirent, filldir, fname))
			break;
	next_node:
		info->curr_node = rb_next(info->curr_node);
		if (info->curr_node) {
			fname = rb_entry(info->curr_node, struct fname,
					 rb_hash);
			info->curr_hash = fname->hash;
			info->curr_minor_hash = fname->minor_hash;
		} else {
			if (info->next_hash == ~0) {
				filp->f_pos = EXT3COW_HTREE_EOF;
				break;
			}
			info->curr_hash = info->next_hash;
			info->curr_minor_hash = 0;
		}
	}
finished:
	info->last_pos = filp->f_pos;
	return 0;
}

static int ext3cow_release_dir (struct inode * inode, struct file * filp)
{
       if (filp->private_data)
		ext3cow_htree_free_dir_info(filp->private_data);

	return 0;
}
