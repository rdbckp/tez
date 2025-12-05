<<<<<<< HEAD
// SPDX-License-Identifier: GPL-2.0
=======
>>>>>>> v4.14.187
/*
 * fs/f2fs/segment.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
<<<<<<< HEAD
=======
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
>>>>>>> v4.14.187
 */
#include <linux/fs.h>
#include <linux/f2fs_fs.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/prefetch.h>
#include <linux/kthread.h>
#include <linux/swap.h>
#include <linux/timer.h>
#include <linux/freezer.h>
#include <linux/sched/signal.h>

#include "f2fs.h"
#include "segment.h"
#include "node.h"
#include "gc.h"
#include "trace.h"
#include <trace/events/f2fs.h>

#define __reverse_ffz(x) __reverse_ffs(~(x))

static struct kmem_cache *discard_entry_slab;
static struct kmem_cache *discard_cmd_slab;
static struct kmem_cache *sit_entry_set_slab;
static struct kmem_cache *inmem_entry_slab;

static unsigned long __reverse_ulong(unsigned char *str)
{
	unsigned long tmp = 0;
	int shift = 24, idx = 0;

#if BITS_PER_LONG == 64
	shift = 56;
#endif
	while (shift >= 0) {
		tmp |= (unsigned long)str[idx++] << shift;
		shift -= BITS_PER_BYTE;
	}
	return tmp;
}

/*
 * __reverse_ffs is copied from include/asm-generic/bitops/__ffs.h since
 * MSB and LSB are reversed in a byte by f2fs_set_bit.
 */
static inline unsigned long __reverse_ffs(unsigned long word)
{
	int num = 0;

#if BITS_PER_LONG == 64
	if ((word & 0xffffffff00000000UL) == 0)
		num += 32;
	else
		word >>= 32;
#endif
	if ((word & 0xffff0000) == 0)
		num += 16;
	else
		word >>= 16;

	if ((word & 0xff00) == 0)
		num += 8;
	else
		word >>= 8;

	if ((word & 0xf0) == 0)
		num += 4;
	else
		word >>= 4;

	if ((word & 0xc) == 0)
		num += 2;
	else
		word >>= 2;

	if ((word & 0x2) == 0)
		num += 1;
	return num;
}

<<<<<<< HEAD
static inline void update_max_undiscard_blks(struct f2fs_sb_info *sbi)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;

	if (dcc->undiscard_blks > sbi->sec_stat.max_undiscard_blks)
		sbi->sec_stat.max_undiscard_blks = dcc->undiscard_blks;
}

=======
>>>>>>> v4.14.187
/*
 * __find_rev_next(_zero)_bit is copied from lib/find_next_bit.c because
 * f2fs_set_bit makes MSB and LSB reversed in a byte.
 * @size must be integral times of unsigned long.
 * Example:
 *                             MSB <--> LSB
 *   f2fs_set_bit(0, bitmap) => 1000 0000
 *   f2fs_set_bit(7, bitmap) => 0000 0001
 */
static unsigned long __find_rev_next_bit(const unsigned long *addr,
			unsigned long size, unsigned long offset)
{
	const unsigned long *p = addr + BIT_WORD(offset);
	unsigned long result = size;
	unsigned long tmp;

	if (offset >= size)
		return size;

	size -= (offset & ~(BITS_PER_LONG - 1));
	offset %= BITS_PER_LONG;

	while (1) {
		if (*p == 0)
			goto pass;

		tmp = __reverse_ulong((unsigned char *)p);

		tmp &= ~0UL >> offset;
		if (size < BITS_PER_LONG)
			tmp &= (~0UL << (BITS_PER_LONG - size));
		if (tmp)
			goto found;
pass:
		if (size <= BITS_PER_LONG)
			break;
		size -= BITS_PER_LONG;
		offset = 0;
		p++;
	}
	return result;
found:
	return result - size + __reverse_ffs(tmp);
}

static unsigned long __find_rev_next_zero_bit(const unsigned long *addr,
			unsigned long size, unsigned long offset)
{
	const unsigned long *p = addr + BIT_WORD(offset);
	unsigned long result = size;
	unsigned long tmp;

	if (offset >= size)
		return size;

	size -= (offset & ~(BITS_PER_LONG - 1));
	offset %= BITS_PER_LONG;

	while (1) {
		if (*p == ~0UL)
			goto pass;

		tmp = __reverse_ulong((unsigned char *)p);

		if (offset)
			tmp |= ~0UL << (BITS_PER_LONG - offset);
		if (size < BITS_PER_LONG)
			tmp |= ~0UL >> size;
		if (tmp != ~0UL)
			goto found;
pass:
		if (size <= BITS_PER_LONG)
			break;
		size -= BITS_PER_LONG;
		offset = 0;
		p++;
	}
	return result;
found:
	return result - size + __reverse_ffz(tmp);
}

<<<<<<< HEAD
bool f2fs_need_SSR(struct f2fs_sb_info *sbi)
=======
bool need_SSR(struct f2fs_sb_info *sbi)
>>>>>>> v4.14.187
{
	int node_secs = get_blocktype_secs(sbi, F2FS_DIRTY_NODES);
	int dent_secs = get_blocktype_secs(sbi, F2FS_DIRTY_DENTS);
	int imeta_secs = get_blocktype_secs(sbi, F2FS_DIRTY_IMETA);

<<<<<<< HEAD
	if (f2fs_lfs_mode(sbi))
		return false;
	if (sbi->gc_mode == GC_URGENT)
		return true;
	if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED)))
		return true;

	return free_sections(sbi) <= (node_secs + 2 * dent_secs + imeta_secs +
			SM_I(sbi)->min_ssr_sections + reserved_sections(sbi));
}

void f2fs_register_inmem_page(struct inode *inode, struct page *page)
{
=======
	if (test_opt(sbi, LFS))
		return false;
	if (sbi->gc_thread && sbi->gc_thread->gc_urgent)
		return true;

	return free_sections(sbi) <= (node_secs + 2 * dent_secs + imeta_secs +
						2 * reserved_sections(sbi));
}

void register_inmem_page(struct inode *inode, struct page *page)
{
	struct f2fs_inode_info *fi = F2FS_I(inode);
>>>>>>> v4.14.187
	struct inmem_pages *new;

	f2fs_trace_pid(page);

<<<<<<< HEAD
	f2fs_set_page_private(page, (unsigned long)ATOMIC_WRITTEN_PAGE);
=======
	set_page_private(page, (unsigned long)ATOMIC_WRITTEN_PAGE);
	SetPagePrivate(page);
>>>>>>> v4.14.187

	new = f2fs_kmem_cache_alloc(inmem_entry_slab, GFP_NOFS);

	/* add atomic page indices to the list */
	new->page = page;
	INIT_LIST_HEAD(&new->list);

	/* increase reference count with clean state */
<<<<<<< HEAD
	get_page(page);
	mutex_lock(&F2FS_I(inode)->inmem_lock);
	list_add_tail(&new->list, &F2FS_I(inode)->inmem_pages);
	inc_page_count(F2FS_I_SB(inode), F2FS_INMEM_PAGES);
	if (F2FS_I_SB(inode)->sec_stat.max_inmem_pages < get_pages(F2FS_I_SB(inode), F2FS_INMEM_PAGES))
		F2FS_I_SB(inode)->sec_stat.max_inmem_pages = get_pages(F2FS_I_SB(inode), F2FS_INMEM_PAGES);
	mutex_unlock(&F2FS_I(inode)->inmem_lock);
=======
	mutex_lock(&fi->inmem_lock);
	get_page(page);
	list_add_tail(&new->list, &fi->inmem_pages);
	inc_page_count(F2FS_I_SB(inode), F2FS_INMEM_PAGES);
	mutex_unlock(&fi->inmem_lock);
>>>>>>> v4.14.187

	trace_f2fs_register_inmem_page(page, INMEM);
}

static int __revoke_inmem_pages(struct inode *inode,
<<<<<<< HEAD
				struct list_head *head, bool drop, bool recover,
				bool trylock)
=======
				struct list_head *head, bool drop, bool recover)
>>>>>>> v4.14.187
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct inmem_pages *cur, *tmp;
	int err = 0;

	list_for_each_entry_safe(cur, tmp, head, list) {
		struct page *page = cur->page;

		if (drop)
			trace_f2fs_commit_inmem_page(page, INMEM_DROP);

<<<<<<< HEAD
		if (trylock) {
			/*
			 * to avoid deadlock in between page lock and
			 * inmem_lock.
			 */
			if (!trylock_page(page))
				continue;
		} else {
			lock_page(page);
		}

		f2fs_wait_on_page_writeback(page, DATA, true, true);
=======
		lock_page(page);

		f2fs_wait_on_page_writeback(page, DATA, true);
>>>>>>> v4.14.187

		if (recover) {
			struct dnode_of_data dn;
			struct node_info ni;

			trace_f2fs_commit_inmem_page(page, INMEM_REVOKE);
retry:
			set_new_dnode(&dn, inode, NULL, NULL, 0);
<<<<<<< HEAD
			err = f2fs_get_dnode_of_data(&dn, page->index,
								LOOKUP_NODE);
			if (err) {
				if (err == -ENOMEM) {
					congestion_wait(BLK_RW_ASYNC,
							DEFAULT_IO_TIMEOUT);
=======
			err = get_dnode_of_data(&dn, page->index, LOOKUP_NODE);
			if (err) {
				if (err == -ENOMEM) {
					congestion_wait(BLK_RW_ASYNC, HZ/50);
>>>>>>> v4.14.187
					cond_resched();
					goto retry;
				}
				err = -EAGAIN;
				goto next;
			}
<<<<<<< HEAD

			err = f2fs_get_node_info(sbi, dn.nid, &ni);
			if (err) {
				f2fs_put_dnode(&dn);
				return err;
			}

			if (cur->old_addr == NEW_ADDR) {
				f2fs_invalidate_blocks(sbi, dn.data_blkaddr);
				f2fs_update_data_blkaddr(&dn, NEW_ADDR);
			} else
				f2fs_replace_block(sbi, &dn, dn.data_blkaddr,
=======
			get_node_info(sbi, dn.nid, &ni);
			f2fs_replace_block(sbi, &dn, dn.data_blkaddr,
>>>>>>> v4.14.187
					cur->old_addr, ni.version, true, true);
			f2fs_put_dnode(&dn);
		}
next:
		/* we don't need to invalidate this in the sccessful status */
		if (drop || recover) {
			ClearPageUptodate(page);
			clear_cold_data(page);
		}
<<<<<<< HEAD
		f2fs_clear_page_private(page);
=======
		set_page_private(page, 0);
		ClearPagePrivate(page);
>>>>>>> v4.14.187
		f2fs_put_page(page, 1);

		list_del(&cur->list);
		kmem_cache_free(inmem_entry_slab, cur);
		dec_page_count(F2FS_I_SB(inode), F2FS_INMEM_PAGES);
	}
	return err;
}

<<<<<<< HEAD
void f2fs_drop_inmem_pages_all(struct f2fs_sb_info *sbi, bool gc_failure)
{
	struct list_head *head = &sbi->inode_list[ATOMIC_FILE];
	struct inode *inode;
	struct f2fs_inode_info *fi;
	unsigned int count = sbi->atomic_files;
	unsigned int looped = 0;

	sbi->sec_stat.drop_inmem_all++;
next:
	spin_lock(&sbi->inode_lock[ATOMIC_FILE]);
	if (list_empty(head)) {
		spin_unlock(&sbi->inode_lock[ATOMIC_FILE]);
		return;
	}
	fi = list_first_entry(head, struct f2fs_inode_info, inmem_ilist);
	inode = igrab(&fi->vfs_inode);
	if (inode)
		list_move_tail(&fi->inmem_ilist, head);
	sbi->sec_stat.drop_inmem_files++;
	spin_unlock(&sbi->inode_lock[ATOMIC_FILE]);

	if (inode) {
		if (gc_failure) {
			if (!fi->i_gc_failures[GC_FAILURE_ATOMIC])
				goto skip;
		}
		set_inode_flag(inode, FI_ATOMIC_REVOKE_REQUEST);
		f2fs_drop_inmem_pages(inode);
skip:
		iput(inode);
	}
	congestion_wait(BLK_RW_ASYNC, DEFAULT_IO_TIMEOUT);
	cond_resched();
	if (gc_failure) {
		if (++looped >= count)
			return;
	}
	goto next;
}

void f2fs_drop_inmem_pages(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_inode_info *fi = F2FS_I(inode);

	while (!list_empty(&fi->inmem_pages)) {
		mutex_lock(&fi->inmem_lock);
		__revoke_inmem_pages(inode, &fi->inmem_pages,
						true, false, true);
		mutex_unlock(&fi->inmem_lock);
	}

	fi->i_gc_failures[GC_FAILURE_ATOMIC] = 0;

	spin_lock(&sbi->inode_lock[ATOMIC_FILE]);
	if (!list_empty(&fi->inmem_ilist))
		list_del_init(&fi->inmem_ilist);
	if (f2fs_is_atomic_file(inode)) {
		clear_inode_flag(inode, FI_ATOMIC_FILE);
		sbi->atomic_files--;
	}
	spin_unlock(&sbi->inode_lock[ATOMIC_FILE]);
}

void f2fs_drop_inmem_page(struct inode *inode, struct page *page)
=======
void drop_inmem_pages(struct inode *inode)
{
	struct f2fs_inode_info *fi = F2FS_I(inode);

	mutex_lock(&fi->inmem_lock);
	__revoke_inmem_pages(inode, &fi->inmem_pages, true, false);
	mutex_unlock(&fi->inmem_lock);

	clear_inode_flag(inode, FI_ATOMIC_FILE);
	clear_inode_flag(inode, FI_HOT_DATA);
	stat_dec_atomic_write(inode);
}

void drop_inmem_page(struct inode *inode, struct page *page)
>>>>>>> v4.14.187
{
	struct f2fs_inode_info *fi = F2FS_I(inode);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct list_head *head = &fi->inmem_pages;
	struct inmem_pages *cur = NULL;

	f2fs_bug_on(sbi, !IS_ATOMIC_WRITTEN_PAGE(page));

	mutex_lock(&fi->inmem_lock);
	list_for_each_entry(cur, head, list) {
		if (cur->page == page)
			break;
	}

<<<<<<< HEAD
	f2fs_bug_on(sbi, list_empty(head) || cur->page != page);
=======
	f2fs_bug_on(sbi, !cur || cur->page != page);
>>>>>>> v4.14.187
	list_del(&cur->list);
	mutex_unlock(&fi->inmem_lock);

	dec_page_count(sbi, F2FS_INMEM_PAGES);
	kmem_cache_free(inmem_entry_slab, cur);

	ClearPageUptodate(page);
<<<<<<< HEAD
	f2fs_clear_page_private(page);
=======
	set_page_private(page, 0);
	ClearPagePrivate(page);
>>>>>>> v4.14.187
	f2fs_put_page(page, 0);

	trace_f2fs_commit_inmem_page(page, INMEM_INVALIDATE);
}

<<<<<<< HEAD
static int __f2fs_commit_inmem_pages(struct inode *inode)
=======
static int __commit_inmem_pages(struct inode *inode,
					struct list_head *revoke_list)
>>>>>>> v4.14.187
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_inode_info *fi = F2FS_I(inode);
	struct inmem_pages *cur, *tmp;
	struct f2fs_io_info fio = {
		.sbi = sbi,
<<<<<<< HEAD
		.ino = inode->i_ino,
=======
>>>>>>> v4.14.187
		.type = DATA,
		.op = REQ_OP_WRITE,
		.op_flags = REQ_SYNC | REQ_PRIO,
		.io_type = FS_DATA_IO,
	};
<<<<<<< HEAD
	struct list_head revoke_list;
	bool submit_bio = false;
	int err = 0;

	INIT_LIST_HEAD(&revoke_list);

=======
	pgoff_t last_idx = ULONG_MAX;
	int err = 0;

>>>>>>> v4.14.187
	list_for_each_entry_safe(cur, tmp, &fi->inmem_pages, list) {
		struct page *page = cur->page;

		lock_page(page);
		if (page->mapping == inode->i_mapping) {
			trace_f2fs_commit_inmem_page(page, INMEM);

<<<<<<< HEAD
			f2fs_wait_on_page_writeback(page, DATA, true, true);

			set_page_dirty(page);
			if (clear_page_dirty_for_io(page)) {
				inode_dec_dirty_pages(inode);
				f2fs_remove_dirty_inode(inode);
=======
			set_page_dirty(page);
			f2fs_wait_on_page_writeback(page, DATA, true);
			if (clear_page_dirty_for_io(page)) {
				inode_dec_dirty_pages(inode);
				remove_dirty_inode(inode);
>>>>>>> v4.14.187
			}
retry:
			fio.page = page;
			fio.old_blkaddr = NULL_ADDR;
			fio.encrypted_page = NULL;
			fio.need_lock = LOCK_DONE;
<<<<<<< HEAD
			err = f2fs_do_write_data_page(&fio);
			if (err) {
				if (err == -ENOMEM) {
					congestion_wait(BLK_RW_ASYNC,
							DEFAULT_IO_TIMEOUT);
=======
			err = do_write_data_page(&fio);
			if (err) {
				if (err == -ENOMEM) {
					congestion_wait(BLK_RW_ASYNC, HZ/50);
>>>>>>> v4.14.187
					cond_resched();
					goto retry;
				}
				unlock_page(page);
				break;
			}
			/* record old blkaddr for revoking */
			cur->old_addr = fio.old_blkaddr;
<<<<<<< HEAD
			submit_bio = true;
		}
		unlock_page(page);
		list_move_tail(&cur->list, &revoke_list);
	}

	if (submit_bio)
		f2fs_submit_merged_write_cond(sbi, inode, NULL, 0, DATA);

	if (err) {
=======
			last_idx = page->index;
		}
		unlock_page(page);
		list_move_tail(&cur->list, revoke_list);
	}

	if (last_idx != ULONG_MAX)
		f2fs_submit_merged_write_cond(sbi, inode, 0, last_idx, DATA);

	if (!err)
		__revoke_inmem_pages(inode, revoke_list, false, false);

	return err;
}

int commit_inmem_pages(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_inode_info *fi = F2FS_I(inode);
	struct list_head revoke_list;
	int err;

	INIT_LIST_HEAD(&revoke_list);
	f2fs_balance_fs(sbi, true);
	f2fs_lock_op(sbi);

	set_inode_flag(inode, FI_ATOMIC_COMMIT);

	mutex_lock(&fi->inmem_lock);
	err = __commit_inmem_pages(inode, &revoke_list);
	if (err) {
		int ret;
>>>>>>> v4.14.187
		/*
		 * try to revoke all committed pages, but still we could fail
		 * due to no memory or other reason, if that happened, EAGAIN
		 * will be returned, which means in such case, transaction is
		 * already not integrity, caller should use journal to do the
		 * recovery or rewrite & commit last transaction. For other
		 * error number, revoking was done by filesystem itself.
		 */
<<<<<<< HEAD
		err = __revoke_inmem_pages(inode, &revoke_list,
						false, true, false);

		/* drop all uncommitted pages */
		__revoke_inmem_pages(inode, &fi->inmem_pages,
						true, false, false);
	} else {
		__revoke_inmem_pages(inode, &revoke_list,
						false, false, false);
	}

	return err;
}

int f2fs_commit_inmem_pages(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_inode_info *fi = F2FS_I(inode);
	int err;

	f2fs_balance_fs(sbi, true);

	down_write(&fi->i_gc_rwsem[WRITE]);

	f2fs_lock_op(sbi);
	set_inode_flag(inode, FI_ATOMIC_COMMIT);

	mutex_lock(&fi->inmem_lock);
	err = __f2fs_commit_inmem_pages(inode);
=======
		ret = __revoke_inmem_pages(inode, &revoke_list, false, true);
		if (ret)
			err = ret;

		/* drop all uncommitted pages */
		__revoke_inmem_pages(inode, &fi->inmem_pages, true, false);
	}
>>>>>>> v4.14.187
	mutex_unlock(&fi->inmem_lock);

	clear_inode_flag(inode, FI_ATOMIC_COMMIT);

	f2fs_unlock_op(sbi);
<<<<<<< HEAD
	up_write(&fi->i_gc_rwsem[WRITE]);

=======
>>>>>>> v4.14.187
	return err;
}

/*
 * This function balances dirty node and dentry pages.
 * In addition, it controls garbage collection.
 */
void f2fs_balance_fs(struct f2fs_sb_info *sbi, bool need)
{
<<<<<<< HEAD
	if (time_to_inject(sbi, FAULT_CHECKPOINT)) {
		f2fs_show_injection_info(sbi, FAULT_CHECKPOINT);
		f2fs_stop_checkpoint(sbi, false);
	}

	/* balance_fs_bg is able to be pending */
	if (need && excess_cached_nats(sbi))
		f2fs_balance_fs_bg(sbi, false);

	if (!f2fs_is_checkpoint_ready(sbi))
		return;
=======
#ifdef CONFIG_F2FS_FAULT_INJECTION
	if (time_to_inject(sbi, FAULT_CHECKPOINT)) {
		f2fs_show_injection_info(FAULT_CHECKPOINT);
		f2fs_stop_checkpoint(sbi, false);
	}
#endif

	/* balance_fs_bg is able to be pending */
	if (need && excess_cached_nats(sbi))
		f2fs_balance_fs_bg(sbi);
>>>>>>> v4.14.187

	/*
	 * We should do GC or end up with checkpoint, if there are so many dirty
	 * dir/node pages without enough free segments.
	 */
	if (has_not_enough_free_secs(sbi, 0, 0)) {
<<<<<<< HEAD
		down_write(&sbi->gc_lock);
=======
		mutex_lock(&sbi->gc_mutex);
>>>>>>> v4.14.187
		f2fs_gc(sbi, false, false, NULL_SEGNO);
	}
}

<<<<<<< HEAD
void f2fs_balance_fs_bg(struct f2fs_sb_info *sbi, bool from_bg)
=======
void f2fs_balance_fs_bg(struct f2fs_sb_info *sbi)
>>>>>>> v4.14.187
{
	if (unlikely(is_sbi_flag_set(sbi, SBI_POR_DOING)))
		return;

	/* try to shrink extent cache when there is no enough memory */
<<<<<<< HEAD
	if (!f2fs_available_free_memory(sbi, EXTENT_CACHE))
		f2fs_shrink_extent_tree(sbi, EXTENT_CACHE_SHRINK_NUMBER);

	/* check the # of cached NAT entries */
	if (!f2fs_available_free_memory(sbi, NAT_ENTRIES))
		f2fs_try_to_free_nats(sbi, NAT_ENTRY_PER_BLOCK);

	if (!f2fs_available_free_memory(sbi, FREE_NIDS))
		f2fs_try_to_free_nids(sbi, MAX_FREE_NIDS);
	else
		f2fs_build_free_nids(sbi, false, false);

	if (!is_idle(sbi, REQ_TIME) &&
		(!excess_dirty_nats(sbi) && !excess_dirty_nodes(sbi)))
		return;

	/* checkpoint is the only way to shrink partial cached entries */
	if (!f2fs_available_free_memory(sbi, NAT_ENTRIES) ||
			!f2fs_available_free_memory(sbi, INO_ENTRIES) ||
			excess_prefree_segs(sbi) ||
			excess_dirty_nats(sbi) ||
			excess_dirty_nodes(sbi) ||
			f2fs_time_over(sbi, CP_TIME)) {
		if (test_opt(sbi, DATA_FLUSH) && from_bg) {
			struct blk_plug plug;

			mutex_lock(&sbi->flush_lock);

			blk_start_plug(&plug);
			f2fs_sync_dirty_inodes(sbi, FILE_INODE);
			blk_finish_plug(&plug);

			mutex_unlock(&sbi->flush_lock);
		}
		f2fs_sync_fs(sbi->sb, true);
		stat_inc_bg_cp_count(sbi->stat_info);
		sbi->sec_stat.cp_cnt[STAT_CP_BG]++;
=======
	if (!available_free_memory(sbi, EXTENT_CACHE))
		f2fs_shrink_extent_tree(sbi, EXTENT_CACHE_SHRINK_NUMBER);

	/* check the # of cached NAT entries */
	if (!available_free_memory(sbi, NAT_ENTRIES))
		try_to_free_nats(sbi, NAT_ENTRY_PER_BLOCK);

	if (!available_free_memory(sbi, FREE_NIDS))
		try_to_free_nids(sbi, MAX_FREE_NIDS);
	else
		build_free_nids(sbi, false, false);

	if (!is_idle(sbi) && !excess_dirty_nats(sbi))
		return;

	/* checkpoint is the only way to shrink partial cached entries */
	if (!available_free_memory(sbi, NAT_ENTRIES) ||
			!available_free_memory(sbi, INO_ENTRIES) ||
			excess_prefree_segs(sbi) ||
			excess_dirty_nats(sbi) ||
			f2fs_time_over(sbi, CP_TIME)) {
		if (test_opt(sbi, DATA_FLUSH)) {
			struct blk_plug plug;

			blk_start_plug(&plug);
			sync_dirty_inodes(sbi, FILE_INODE);
			blk_finish_plug(&plug);
		}
		f2fs_sync_fs(sbi->sb, true);
		stat_inc_bg_cp_count(sbi->stat_info);
>>>>>>> v4.14.187
	}
}

static int __submit_flush_wait(struct f2fs_sb_info *sbi,
				struct block_device *bdev)
{
<<<<<<< HEAD
	struct bio *bio;
	int ret;

	bio = f2fs_bio_alloc(sbi, 0, false);
	if (!bio)
		return -ENOMEM;

=======
	struct bio *bio = f2fs_bio_alloc(0);
	int ret;

>>>>>>> v4.14.187
	bio->bi_opf = REQ_OP_WRITE | REQ_SYNC | REQ_PREFLUSH;
	bio_set_dev(bio, bdev);
	ret = submit_bio_wait(bio);
	bio_put(bio);

	trace_f2fs_issue_flush(bdev, test_opt(sbi, NOBARRIER),
				test_opt(sbi, FLUSH_MERGE), ret);
	return ret;
}

<<<<<<< HEAD
static int submit_flush_wait(struct f2fs_sb_info *sbi, nid_t ino)
{
	int ret = 0;
	int i;

	if (!f2fs_is_multi_device(sbi))
		return __submit_flush_wait(sbi, sbi->sb->s_bdev);

	for (i = 0; i < sbi->s_ndevs; i++) {
		if (!f2fs_is_dirty_device(sbi, ino, i, FLUSH_INO))
			continue;
=======
static int submit_flush_wait(struct f2fs_sb_info *sbi)
{
	int ret = __submit_flush_wait(sbi, sbi->sb->s_bdev);
	int i;

	if (!f2fs_is_multi_device(sbi) || ret)
		return ret;

	for (i = 1; i < sbi->s_ndevs; i++) {
>>>>>>> v4.14.187
		ret = __submit_flush_wait(sbi, FDEV(i).bdev);
		if (ret)
			break;
	}
	return ret;
}

static int issue_flush_thread(void *data)
{
	struct f2fs_sb_info *sbi = data;
	struct flush_cmd_control *fcc = SM_I(sbi)->fcc_info;
	wait_queue_head_t *q = &fcc->flush_wait_queue;
repeat:
	if (kthread_should_stop())
		return 0;

	sb_start_intwrite(sbi->sb);

	if (!llist_empty(&fcc->issue_list)) {
		struct flush_cmd *cmd, *next;
		int ret;

		fcc->dispatch_list = llist_del_all(&fcc->issue_list);
		fcc->dispatch_list = llist_reverse_order(fcc->dispatch_list);

<<<<<<< HEAD
		cmd = llist_entry(fcc->dispatch_list, struct flush_cmd, llnode);

		ret = submit_flush_wait(sbi, cmd->ino);
=======
		ret = submit_flush_wait(sbi);
>>>>>>> v4.14.187
		atomic_inc(&fcc->issued_flush);

		llist_for_each_entry_safe(cmd, next,
					  fcc->dispatch_list, llnode) {
			cmd->ret = ret;
			complete(&cmd->wait);
		}
		fcc->dispatch_list = NULL;
	}

	sb_end_intwrite(sbi->sb);

	wait_event_interruptible(*q,
		kthread_should_stop() || !llist_empty(&fcc->issue_list));
	goto repeat;
}

<<<<<<< HEAD
int f2fs_issue_flush(struct f2fs_sb_info *sbi, nid_t ino)
=======
int f2fs_issue_flush(struct f2fs_sb_info *sbi)
>>>>>>> v4.14.187
{
	struct flush_cmd_control *fcc = SM_I(sbi)->fcc_info;
	struct flush_cmd cmd;
	int ret;

	if (test_opt(sbi, NOBARRIER))
		return 0;

	if (!test_opt(sbi, FLUSH_MERGE)) {
<<<<<<< HEAD
		atomic_inc(&fcc->queued_flush);
		ret = submit_flush_wait(sbi, ino);
		atomic_dec(&fcc->queued_flush);
=======
		ret = submit_flush_wait(sbi);
>>>>>>> v4.14.187
		atomic_inc(&fcc->issued_flush);
		return ret;
	}

<<<<<<< HEAD
	if (atomic_inc_return(&fcc->queued_flush) == 1 ||
	    f2fs_is_multi_device(sbi)) {
		ret = submit_flush_wait(sbi, ino);
		atomic_dec(&fcc->queued_flush);
=======
	if (atomic_inc_return(&fcc->issing_flush) == 1) {
		ret = submit_flush_wait(sbi);
		atomic_dec(&fcc->issing_flush);
>>>>>>> v4.14.187

		atomic_inc(&fcc->issued_flush);
		return ret;
	}

<<<<<<< HEAD
	cmd.ino = ino;
=======
>>>>>>> v4.14.187
	init_completion(&cmd.wait);

	llist_add(&cmd.llnode, &fcc->issue_list);

	/* update issue_list before we wake up issue_flush thread */
	smp_mb();

	if (waitqueue_active(&fcc->flush_wait_queue))
		wake_up(&fcc->flush_wait_queue);

	if (fcc->f2fs_issue_flush) {
		wait_for_completion(&cmd.wait);
<<<<<<< HEAD
		atomic_dec(&fcc->queued_flush);
=======
		atomic_dec(&fcc->issing_flush);
>>>>>>> v4.14.187
	} else {
		struct llist_node *list;

		list = llist_del_all(&fcc->issue_list);
		if (!list) {
			wait_for_completion(&cmd.wait);
<<<<<<< HEAD
			atomic_dec(&fcc->queued_flush);
		} else {
			struct flush_cmd *tmp, *next;

			ret = submit_flush_wait(sbi, ino);
=======
			atomic_dec(&fcc->issing_flush);
		} else {
			struct flush_cmd *tmp, *next;

			ret = submit_flush_wait(sbi);
>>>>>>> v4.14.187

			llist_for_each_entry_safe(tmp, next, list, llnode) {
				if (tmp == &cmd) {
					cmd.ret = ret;
<<<<<<< HEAD
					atomic_dec(&fcc->queued_flush);
=======
					atomic_dec(&fcc->issing_flush);
>>>>>>> v4.14.187
					continue;
				}
				tmp->ret = ret;
				complete(&tmp->wait);
			}
		}
	}

	return cmd.ret;
}

<<<<<<< HEAD
int f2fs_create_flush_cmd_control(struct f2fs_sb_info *sbi)
=======
int create_flush_cmd_control(struct f2fs_sb_info *sbi)
>>>>>>> v4.14.187
{
	dev_t dev = sbi->sb->s_bdev->bd_dev;
	struct flush_cmd_control *fcc;
	int err = 0;

	if (SM_I(sbi)->fcc_info) {
		fcc = SM_I(sbi)->fcc_info;
		if (fcc->f2fs_issue_flush)
			return err;
		goto init_thread;
	}

<<<<<<< HEAD
	fcc = f2fs_kzalloc(sbi, sizeof(struct flush_cmd_control), GFP_KERNEL);
	if (!fcc)
		return -ENOMEM;
	atomic_set(&fcc->issued_flush, 0);
	atomic_set(&fcc->queued_flush, 0);
=======
	fcc = kzalloc(sizeof(struct flush_cmd_control), GFP_KERNEL);
	if (!fcc)
		return -ENOMEM;
	atomic_set(&fcc->issued_flush, 0);
	atomic_set(&fcc->issing_flush, 0);
>>>>>>> v4.14.187
	init_waitqueue_head(&fcc->flush_wait_queue);
	init_llist_head(&fcc->issue_list);
	SM_I(sbi)->fcc_info = fcc;
	if (!test_opt(sbi, FLUSH_MERGE))
		return err;

init_thread:
	fcc->f2fs_issue_flush = kthread_run(issue_flush_thread, sbi,
				"f2fs_flush-%u:%u", MAJOR(dev), MINOR(dev));
	if (IS_ERR(fcc->f2fs_issue_flush)) {
		err = PTR_ERR(fcc->f2fs_issue_flush);
<<<<<<< HEAD
		kvfree(fcc);
=======
		kfree(fcc);
>>>>>>> v4.14.187
		SM_I(sbi)->fcc_info = NULL;
		return err;
	}

	return err;
}

<<<<<<< HEAD
void f2fs_destroy_flush_cmd_control(struct f2fs_sb_info *sbi, bool free)
=======
void destroy_flush_cmd_control(struct f2fs_sb_info *sbi, bool free)
>>>>>>> v4.14.187
{
	struct flush_cmd_control *fcc = SM_I(sbi)->fcc_info;

	if (fcc && fcc->f2fs_issue_flush) {
		struct task_struct *flush_thread = fcc->f2fs_issue_flush;

		fcc->f2fs_issue_flush = NULL;
		kthread_stop(flush_thread);
	}
	if (free) {
<<<<<<< HEAD
		kvfree(fcc);
=======
		kfree(fcc);
>>>>>>> v4.14.187
		SM_I(sbi)->fcc_info = NULL;
	}
}

<<<<<<< HEAD
int f2fs_flush_device_cache(struct f2fs_sb_info *sbi)
{
	int ret = 0, i;

	if (!f2fs_is_multi_device(sbi))
		return 0;

	for (i = 1; i < sbi->s_ndevs; i++) {
		if (!f2fs_test_bit(i, (char *)&sbi->dirty_device))
			continue;
		ret = __submit_flush_wait(sbi, FDEV(i).bdev);
		if (ret)
			break;

		spin_lock(&sbi->dev_lock);
		f2fs_clear_bit(i, (char *)&sbi->dirty_device);
		spin_unlock(&sbi->dev_lock);
	}

	return ret;
}

=======
>>>>>>> v4.14.187
static void __locate_dirty_segment(struct f2fs_sb_info *sbi, unsigned int segno,
		enum dirty_type dirty_type)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);

	/* need not be added */
	if (IS_CURSEG(sbi, segno))
		return;

	if (!test_and_set_bit(segno, dirty_i->dirty_segmap[dirty_type]))
		dirty_i->nr_dirty[dirty_type]++;

	if (dirty_type == DIRTY) {
		struct seg_entry *sentry = get_seg_entry(sbi, segno);
		enum dirty_type t = sentry->type;

		if (unlikely(t >= DIRTY)) {
			f2fs_bug_on(sbi, 1);
			return;
		}
		if (!test_and_set_bit(segno, dirty_i->dirty_segmap[t]))
			dirty_i->nr_dirty[t]++;
	}
}

static void __remove_dirty_segment(struct f2fs_sb_info *sbi, unsigned int segno,
		enum dirty_type dirty_type)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);

	if (test_and_clear_bit(segno, dirty_i->dirty_segmap[dirty_type]))
		dirty_i->nr_dirty[dirty_type]--;

	if (dirty_type == DIRTY) {
		struct seg_entry *sentry = get_seg_entry(sbi, segno);
		enum dirty_type t = sentry->type;

		if (test_and_clear_bit(segno, dirty_i->dirty_segmap[t]))
			dirty_i->nr_dirty[t]--;

<<<<<<< HEAD
		if (get_valid_blocks(sbi, segno, true) == 0) {
			clear_bit(GET_SEC_FROM_SEG(sbi, segno),
						dirty_i->victim_secmap);
#ifdef CONFIG_F2FS_CHECK_FS
			clear_bit(segno, SIT_I(sbi)->invalid_segmap);
#endif
		}
=======
		if (get_valid_blocks(sbi, segno, true) == 0)
			clear_bit(GET_SEC_FROM_SEG(sbi, segno),
						dirty_i->victim_secmap);
>>>>>>> v4.14.187
	}
}

/*
 * Should not occur error such as -ENOMEM.
 * Adding dirty entry into seglist is not critical operation.
 * If a given segment is one of current working segments, it won't be added.
 */
static void locate_dirty_segment(struct f2fs_sb_info *sbi, unsigned int segno)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
<<<<<<< HEAD
	unsigned short valid_blocks, ckpt_valid_blocks;
=======
	unsigned short valid_blocks;
>>>>>>> v4.14.187

	if (segno == NULL_SEGNO || IS_CURSEG(sbi, segno))
		return;

	mutex_lock(&dirty_i->seglist_lock);

	valid_blocks = get_valid_blocks(sbi, segno, false);
<<<<<<< HEAD
	ckpt_valid_blocks = get_ckpt_valid_blocks(sbi, segno);

	if (valid_blocks == 0 && (!is_sbi_flag_set(sbi, SBI_CP_DISABLED) ||
				ckpt_valid_blocks == sbi->blocks_per_seg)) {
=======

	if (valid_blocks == 0) {
>>>>>>> v4.14.187
		__locate_dirty_segment(sbi, segno, PRE);
		__remove_dirty_segment(sbi, segno, DIRTY);
	} else if (valid_blocks < sbi->blocks_per_seg) {
		__locate_dirty_segment(sbi, segno, DIRTY);
	} else {
		/* Recovery routine with SSR needs this */
		__remove_dirty_segment(sbi, segno, DIRTY);
	}

	mutex_unlock(&dirty_i->seglist_lock);
}

<<<<<<< HEAD
/* This moves currently empty dirty blocks to prefree. Must hold seglist_lock */
void f2fs_dirty_to_prefree(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	unsigned int segno;

	mutex_lock(&dirty_i->seglist_lock);
	for_each_set_bit(segno, dirty_i->dirty_segmap[DIRTY], MAIN_SEGS(sbi)) {
		if (get_valid_blocks(sbi, segno, false))
			continue;
		if (IS_CURSEG(sbi, segno))
			continue;
		__locate_dirty_segment(sbi, segno, PRE);
		__remove_dirty_segment(sbi, segno, DIRTY);
	}
	mutex_unlock(&dirty_i->seglist_lock);
}

block_t f2fs_get_unusable_blocks(struct f2fs_sb_info *sbi)
{
	int ovp_hole_segs =
		(overprovision_segments(sbi) - reserved_segments(sbi));
	block_t ovp_holes = ovp_hole_segs << sbi->log_blocks_per_seg;
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	block_t holes[2] = {0, 0};	/* DATA and NODE */
	block_t unusable;
	struct seg_entry *se;
	unsigned int segno;

	mutex_lock(&dirty_i->seglist_lock);
	for_each_set_bit(segno, dirty_i->dirty_segmap[DIRTY], MAIN_SEGS(sbi)) {
		se = get_seg_entry(sbi, segno);
		if (IS_NODESEG(se->type))
			holes[NODE] += sbi->blocks_per_seg - se->valid_blocks;
		else
			holes[DATA] += sbi->blocks_per_seg - se->valid_blocks;
	}
	mutex_unlock(&dirty_i->seglist_lock);

	unusable = holes[DATA] > holes[NODE] ? holes[DATA] : holes[NODE];
	if (unusable > ovp_holes)
		return unusable - ovp_holes;
	return 0;
}

int f2fs_disable_cp_again(struct f2fs_sb_info *sbi, block_t unusable)
{
	int ovp_hole_segs =
		(overprovision_segments(sbi) - reserved_segments(sbi));
	if (unusable > F2FS_OPTION(sbi).unusable_cap)
		return -EAGAIN;
	if (is_sbi_flag_set(sbi, SBI_CP_DISABLED_QUICK) &&
		dirty_segments(sbi) > ovp_hole_segs)
		return -EAGAIN;
	return 0;
}

/* This is only used by SBI_CP_DISABLED */
static unsigned int get_free_segment(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	unsigned int segno = 0;

	mutex_lock(&dirty_i->seglist_lock);
	for_each_set_bit(segno, dirty_i->dirty_segmap[DIRTY], MAIN_SEGS(sbi)) {
		if (get_valid_blocks(sbi, segno, false))
			continue;
		if (get_ckpt_valid_blocks(sbi, segno))
			continue;
		mutex_unlock(&dirty_i->seglist_lock);
		return segno;
	}
	mutex_unlock(&dirty_i->seglist_lock);
	return NULL_SEGNO;
}

=======
>>>>>>> v4.14.187
static struct discard_cmd *__create_discard_cmd(struct f2fs_sb_info *sbi,
		struct block_device *bdev, block_t lstart,
		block_t start, block_t len)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct list_head *pend_list;
	struct discard_cmd *dc;

	f2fs_bug_on(sbi, !len);

	pend_list = &dcc->pend_list[plist_idx(len)];

	dc = f2fs_kmem_cache_alloc(discard_cmd_slab, GFP_NOFS);
	INIT_LIST_HEAD(&dc->list);
	dc->bdev = bdev;
	dc->lstart = lstart;
	dc->start = start;
	dc->len = len;
	dc->ref = 0;
	dc->state = D_PREP;
<<<<<<< HEAD
	dc->queued = 0;
	dc->error = 0;
	init_completion(&dc->wait);
	list_add_tail(&dc->list, pend_list);
	spin_lock_init(&dc->lock);
	dc->bio_ref = 0;
	atomic_inc(&dcc->discard_cmd_cnt);
	dcc->undiscard_blks += len;
	update_max_undiscard_blks(sbi);
=======
	dc->error = 0;
	init_completion(&dc->wait);
	list_add_tail(&dc->list, pend_list);
	atomic_inc(&dcc->discard_cmd_cnt);
	dcc->undiscard_blks += len;
>>>>>>> v4.14.187

	return dc;
}

static struct discard_cmd *__attach_discard_cmd(struct f2fs_sb_info *sbi,
				struct block_device *bdev, block_t lstart,
				block_t start, block_t len,
<<<<<<< HEAD
				struct rb_node *parent, struct rb_node **p,
				bool leftmost)
=======
				struct rb_node *parent, struct rb_node **p)
>>>>>>> v4.14.187
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct discard_cmd *dc;

	dc = __create_discard_cmd(sbi, bdev, lstart, start, len);

	rb_link_node(&dc->rb_node, parent, p);
<<<<<<< HEAD
	rb_insert_color_cached(&dc->rb_node, &dcc->root, leftmost);
=======
	rb_insert_color(&dc->rb_node, &dcc->root);
>>>>>>> v4.14.187

	return dc;
}

static void __detach_discard_cmd(struct discard_cmd_control *dcc,
							struct discard_cmd *dc)
{
	if (dc->state == D_DONE)
<<<<<<< HEAD
		atomic_sub(dc->queued, &dcc->queued_discard);

	list_del(&dc->list);
	rb_erase_cached(&dc->rb_node, &dcc->root);
=======
		atomic_dec(&dcc->issing_discard);

	list_del(&dc->list);
	rb_erase(&dc->rb_node, &dcc->root);
>>>>>>> v4.14.187
	dcc->undiscard_blks -= dc->len;

	kmem_cache_free(discard_cmd_slab, dc);

	atomic_dec(&dcc->discard_cmd_cnt);
}

static void __remove_discard_cmd(struct f2fs_sb_info *sbi,
							struct discard_cmd *dc)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
<<<<<<< HEAD
	unsigned long flags;

	trace_f2fs_remove_discard(dc->bdev, dc->start, dc->len);

	spin_lock_irqsave(&dc->lock, flags);
	if (dc->bio_ref) {
		spin_unlock_irqrestore(&dc->lock, flags);
		return;
	}
	spin_unlock_irqrestore(&dc->lock, flags);
=======
>>>>>>> v4.14.187

	f2fs_bug_on(sbi, dc->ref);

	if (dc->error == -EOPNOTSUPP)
		dc->error = 0;

	if (dc->error)
<<<<<<< HEAD
		printk_ratelimited(
			"%sF2FS-fs (%s): Issue discard(%u, %u, %u) failed, ret: %d",
			KERN_INFO, sbi->sb->s_id,
=======
		f2fs_msg(sbi->sb, KERN_INFO,
			"Issue discard(%u, %u, %u) failed, ret: %d",
>>>>>>> v4.14.187
			dc->lstart, dc->start, dc->len, dc->error);
	__detach_discard_cmd(dcc, dc);
}

static void f2fs_submit_discard_endio(struct bio *bio)
{
	struct discard_cmd *dc = (struct discard_cmd *)bio->bi_private;
<<<<<<< HEAD
	unsigned long flags;

	spin_lock_irqsave(&dc->lock, flags);
	if (!dc->error)
		dc->error = blk_status_to_errno(bio->bi_status);
	dc->bio_ref--;
	if (!dc->bio_ref && dc->state == D_SUBMIT) {
		dc->state = D_DONE;
		complete_all(&dc->wait);
	}
	spin_unlock_irqrestore(&dc->lock, flags);
	bio_put(bio);
}

static void __check_sit_bitmap(struct f2fs_sb_info *sbi,
=======

	dc->error = blk_status_to_errno(bio->bi_status);
	dc->state = D_DONE;
	complete_all(&dc->wait);
	bio_put(bio);
}

void __check_sit_bitmap(struct f2fs_sb_info *sbi,
>>>>>>> v4.14.187
				block_t start, block_t end)
{
#ifdef CONFIG_F2FS_CHECK_FS
	struct seg_entry *sentry;
	unsigned int segno;
	block_t blk = start;
	unsigned long offset, size, max_blocks = sbi->blocks_per_seg;
	unsigned long *map;

	while (blk < end) {
		segno = GET_SEGNO(sbi, blk);
		sentry = get_seg_entry(sbi, segno);
		offset = GET_BLKOFF_FROM_SEG0(sbi, blk);

		if (end < START_BLOCK(sbi, segno + 1))
			size = GET_BLKOFF_FROM_SEG0(sbi, end);
		else
			size = max_blocks;
		map = (unsigned long *)(sentry->cur_valid_map);
		offset = __find_rev_next_bit(map, size, offset);
		f2fs_bug_on(sbi, offset != size);
		blk = START_BLOCK(sbi, segno + 1);
	}
#endif
}

<<<<<<< HEAD
/* @fs.sec -- cc451a59f2de8918b30cc7c0bef20871 -- */
static void __init_discard_policy(struct f2fs_sb_info *sbi,
				struct discard_policy *dpolicy,
				int discard_type, unsigned int granularity)
{
	/* common policy */
	dpolicy->type = discard_type;
	dpolicy->sync = true;
	dpolicy->ordered = false;
	dpolicy->granularity = granularity;

	dpolicy->max_requests = DEF_MAX_DISCARD_REQUEST;
	dpolicy->io_aware_gran = MAX_PLIST_NUM - 1;
	dpolicy->timeout = false;

	if (discard_type == DPOLICY_BG) {
		dpolicy->min_interval = DEF_MIN_DISCARD_ISSUE_TIME;
		dpolicy->mid_interval = DEF_MID_DISCARD_ISSUE_TIME;
		dpolicy->max_interval = DEF_MAX_DISCARD_ISSUE_TIME;
		dpolicy->io_aware = true;
		dpolicy->sync = false;
		dpolicy->ordered = true;
		if (utilization(sbi) > DEF_DISCARD_URGENT_UTIL) {
			dpolicy->granularity = 1;
			dpolicy->max_interval = DEF_MIN_DISCARD_ISSUE_TIME;
		}
	} else if (discard_type == DPOLICY_FORCE) {
		dpolicy->min_interval = DEF_MIN_DISCARD_ISSUE_TIME;
		dpolicy->mid_interval = DEF_MID_DISCARD_ISSUE_TIME;
		dpolicy->max_interval = DEF_MAX_DISCARD_ISSUE_TIME;
		dpolicy->io_aware = false;
	} else if (discard_type == DPOLICY_FSTRIM) {
		dpolicy->io_aware = false;
	} else if (discard_type == DPOLICY_UMOUNT) {
		dpolicy->io_aware = false;
		/* we need to issue all to keep CP_TRIMMED_FLAG */
		dpolicy->granularity = 1;
		dpolicy->timeout = true;
	}
}

static void __update_discard_tree_range(struct f2fs_sb_info *sbi,
				struct block_device *bdev, block_t lstart,
				block_t start, block_t len);
/* this function is copied from blkdev_issue_discard from block/blk-lib.c */
static int __submit_discard_cmd(struct f2fs_sb_info *sbi,
						struct discard_policy *dpolicy,
						struct discard_cmd *dc,
						unsigned int *issued)
{
	struct block_device *bdev = dc->bdev;
	struct request_queue *q = bdev_get_queue(bdev);
	unsigned int max_discard_blocks =
			SECTOR_TO_BLOCK(q->limits.max_discard_sectors);
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct list_head *wait_list = (dpolicy->type == DPOLICY_FSTRIM) ?
					&(dcc->fstrim_list) : &(dcc->wait_list);
	int flag = dpolicy->sync ? REQ_SYNC : 0;
	block_t lstart, start, len, total_len;
	int err = 0;

	if (dc->state != D_PREP)
		return 0;

	if (is_sbi_flag_set(sbi, SBI_NEED_FSCK))
		return 0;

	trace_f2fs_issue_discard(bdev, dc->start, dc->len);

	lstart = dc->lstart;
	start = dc->start;
	len = dc->len;
	total_len = len;

	dc->len = 0;

	while (total_len && *issued < dpolicy->max_requests && !err) {
		struct bio *bio = NULL;
		unsigned long flags;
		bool last = true;

		if (len > max_discard_blocks) {
			len = max_discard_blocks;
			last = false;
		}

		(*issued)++;
		if (*issued == dpolicy->max_requests)
			last = true;

		dc->len += len;

		if (time_to_inject(sbi, FAULT_DISCARD)) {
			f2fs_show_injection_info(sbi, FAULT_DISCARD);
			err = -EIO;
			goto submit;
		}
		err = __blkdev_issue_discard(bdev,
					SECTOR_FROM_BLOCK(start),
					SECTOR_FROM_BLOCK(len),
					GFP_NOFS, 0, &bio);
submit:
		if (err) {
			spin_lock_irqsave(&dc->lock, flags);
			if (dc->state == D_PARTIAL)
				dc->state = D_SUBMIT;
			spin_unlock_irqrestore(&dc->lock, flags);

			break;
		}

		f2fs_bug_on(sbi, !bio);

		/*
		 * should keep before submission to avoid D_DONE
		 * right away
		 */
		spin_lock_irqsave(&dc->lock, flags);
		if (last)
			dc->state = D_SUBMIT;
		else
			dc->state = D_PARTIAL;
		dc->bio_ref++;
		spin_unlock_irqrestore(&dc->lock, flags);

		atomic_inc(&dcc->queued_discard);
		dc->queued++;
		list_move_tail(&dc->list, wait_list);

		/* sanity check on discard range */
		__check_sit_bitmap(sbi, lstart, lstart + len);

		bio->bi_private = dc;
		bio->bi_end_io = f2fs_submit_discard_endio;
		bio->bi_opf |= flag;
		submit_bio(bio);

		atomic_inc(&dcc->issued_discard);

		f2fs_update_iostat(sbi, FS_DISCARD, 1);

		lstart += len;
		start += len;
		total_len -= len;
		len = total_len;
	}

	if (!err && len) {
		dcc->undiscard_blks -= len;
		__update_discard_tree_range(sbi, bdev, lstart, start, len);
	}
	return err;
}

static void __insert_discard_tree(struct f2fs_sb_info *sbi,
=======
/* this function is copied from blkdev_issue_discard from block/blk-lib.c */
static void __submit_discard_cmd(struct f2fs_sb_info *sbi,
				struct discard_cmd *dc)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct bio *bio = NULL;

	if (dc->state != D_PREP)
		return;

	trace_f2fs_issue_discard(dc->bdev, dc->start, dc->len);

	dc->error = __blkdev_issue_discard(dc->bdev,
				SECTOR_FROM_BLOCK(dc->start),
				SECTOR_FROM_BLOCK(dc->len),
				GFP_NOFS, 0, &bio);
	if (!dc->error) {
		/* should keep before submission to avoid D_DONE right away */
		dc->state = D_SUBMIT;
		atomic_inc(&dcc->issued_discard);
		atomic_inc(&dcc->issing_discard);
		if (bio) {
			bio->bi_private = dc;
			bio->bi_end_io = f2fs_submit_discard_endio;
			bio->bi_opf |= REQ_SYNC;
			submit_bio(bio);
			list_move_tail(&dc->list, &dcc->wait_list);
			__check_sit_bitmap(sbi, dc->start, dc->start + dc->len);

			f2fs_update_iostat(sbi, FS_DISCARD, 1);
		}
	} else {
		__remove_discard_cmd(sbi, dc);
	}
}

static struct discard_cmd *__insert_discard_tree(struct f2fs_sb_info *sbi,
>>>>>>> v4.14.187
				struct block_device *bdev, block_t lstart,
				block_t start, block_t len,
				struct rb_node **insert_p,
				struct rb_node *insert_parent)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
<<<<<<< HEAD
	struct rb_node **p;
	struct rb_node *parent = NULL;
	bool leftmost = true;
=======
	struct rb_node **p = &dcc->root.rb_node;
	struct rb_node *parent = NULL;
	struct discard_cmd *dc = NULL;
>>>>>>> v4.14.187

	if (insert_p && insert_parent) {
		parent = insert_parent;
		p = insert_p;
		goto do_insert;
	}

<<<<<<< HEAD
	p = f2fs_lookup_rb_tree_for_insert(sbi, &dcc->root, &parent,
							lstart, &leftmost);
do_insert:
	__attach_discard_cmd(sbi, bdev, lstart, start, len, parent,
								p, leftmost);
=======
	p = __lookup_rb_tree_for_insert(sbi, &dcc->root, &parent, lstart);
do_insert:
	dc = __attach_discard_cmd(sbi, bdev, lstart, start, len, parent, p);
	if (!dc)
		return NULL;

	return dc;
>>>>>>> v4.14.187
}

static void __relocate_discard_cmd(struct discard_cmd_control *dcc,
						struct discard_cmd *dc)
{
	list_move_tail(&dc->list, &dcc->pend_list[plist_idx(dc->len)]);
}

static void __punch_discard_cmd(struct f2fs_sb_info *sbi,
				struct discard_cmd *dc, block_t blkaddr)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct discard_info di = dc->di;
	bool modified = false;

	if (dc->state == D_DONE || dc->len == 1) {
		__remove_discard_cmd(sbi, dc);
		return;
	}

	dcc->undiscard_blks -= di.len;

	if (blkaddr > di.lstart) {
		dc->len = blkaddr - dc->lstart;
		dcc->undiscard_blks += dc->len;
<<<<<<< HEAD
		update_max_undiscard_blks(sbi);
=======
>>>>>>> v4.14.187
		__relocate_discard_cmd(dcc, dc);
		modified = true;
	}

	if (blkaddr < di.lstart + di.len - 1) {
		if (modified) {
			__insert_discard_tree(sbi, dc->bdev, blkaddr + 1,
					di.start + blkaddr + 1 - di.lstart,
					di.lstart + di.len - 1 - blkaddr,
					NULL, NULL);
		} else {
			dc->lstart++;
			dc->len--;
			dc->start++;
			dcc->undiscard_blks += dc->len;
<<<<<<< HEAD
			update_max_undiscard_blks(sbi);
=======
>>>>>>> v4.14.187
			__relocate_discard_cmd(dcc, dc);
		}
	}
}

static void __update_discard_tree_range(struct f2fs_sb_info *sbi,
				struct block_device *bdev, block_t lstart,
				block_t start, block_t len)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct discard_cmd *prev_dc = NULL, *next_dc = NULL;
	struct discard_cmd *dc;
	struct discard_info di = {0};
	struct rb_node **insert_p = NULL, *insert_parent = NULL;
<<<<<<< HEAD
	struct request_queue *q = bdev_get_queue(bdev);
	unsigned int max_discard_blocks =
			SECTOR_TO_BLOCK(q->limits.max_discard_sectors);
	block_t end = lstart + len;

	dc = (struct discard_cmd *)f2fs_lookup_rb_tree_ret(&dcc->root,
					NULL, lstart,
					(struct rb_entry **)&prev_dc,
					(struct rb_entry **)&next_dc,
					&insert_p, &insert_parent, true, NULL);
=======
	block_t end = lstart + len;

	mutex_lock(&dcc->cmd_lock);

	dc = (struct discard_cmd *)__lookup_rb_tree_ret(&dcc->root,
					NULL, lstart,
					(struct rb_entry **)&prev_dc,
					(struct rb_entry **)&next_dc,
					&insert_p, &insert_parent, true);
>>>>>>> v4.14.187
	if (dc)
		prev_dc = dc;

	if (!prev_dc) {
		di.lstart = lstart;
		di.len = next_dc ? next_dc->lstart - lstart : len;
		di.len = min(di.len, len);
		di.start = start;
	}

	while (1) {
		struct rb_node *node;
		bool merged = false;
		struct discard_cmd *tdc = NULL;

		if (prev_dc) {
			di.lstart = prev_dc->lstart + prev_dc->len;
			if (di.lstart < lstart)
				di.lstart = lstart;
			if (di.lstart >= end)
				break;

			if (!next_dc || next_dc->lstart > end)
				di.len = end - di.lstart;
			else
				di.len = next_dc->lstart - di.lstart;
			di.start = start + di.lstart - lstart;
		}

		if (!di.len)
			goto next;

		if (prev_dc && prev_dc->state == D_PREP &&
			prev_dc->bdev == bdev &&
<<<<<<< HEAD
			__is_discard_back_mergeable(&di, &prev_dc->di,
							max_discard_blocks)) {
			prev_dc->di.len += di.len;
			dcc->undiscard_blks += di.len;
			update_max_undiscard_blks(sbi);
=======
			__is_discard_back_mergeable(&di, &prev_dc->di)) {
			prev_dc->di.len += di.len;
			dcc->undiscard_blks += di.len;
>>>>>>> v4.14.187
			__relocate_discard_cmd(dcc, prev_dc);
			di = prev_dc->di;
			tdc = prev_dc;
			merged = true;
		}

		if (next_dc && next_dc->state == D_PREP &&
			next_dc->bdev == bdev &&
<<<<<<< HEAD
			__is_discard_front_mergeable(&di, &next_dc->di,
							max_discard_blocks)) {
=======
			__is_discard_front_mergeable(&di, &next_dc->di)) {
>>>>>>> v4.14.187
			next_dc->di.lstart = di.lstart;
			next_dc->di.len += di.len;
			next_dc->di.start = di.start;
			dcc->undiscard_blks += di.len;
<<<<<<< HEAD
			update_max_undiscard_blks(sbi);
=======
>>>>>>> v4.14.187
			__relocate_discard_cmd(dcc, next_dc);
			if (tdc)
				__remove_discard_cmd(sbi, tdc);
			merged = true;
		}

		if (!merged) {
			__insert_discard_tree(sbi, bdev, di.lstart, di.start,
							di.len, NULL, NULL);
		}
 next:
		prev_dc = next_dc;
		if (!prev_dc)
			break;

		node = rb_next(&prev_dc->rb_node);
		next_dc = rb_entry_safe(node, struct discard_cmd, rb_node);
	}
<<<<<<< HEAD
=======

	mutex_unlock(&dcc->cmd_lock);
>>>>>>> v4.14.187
}

static int __queue_discard_cmd(struct f2fs_sb_info *sbi,
		struct block_device *bdev, block_t blkstart, block_t blklen)
{
	block_t lblkstart = blkstart;

<<<<<<< HEAD
	if (!f2fs_bdev_support_discard(bdev))
		return 0;

=======
>>>>>>> v4.14.187
	trace_f2fs_queue_discard(bdev, blkstart, blklen);

	if (f2fs_is_multi_device(sbi)) {
		int devi = f2fs_target_device_index(sbi, blkstart);

		blkstart -= FDEV(devi).start_blk;
	}
<<<<<<< HEAD
	mutex_lock(&SM_I(sbi)->dcc_info->cmd_lock);
	__update_discard_tree_range(sbi, bdev, lblkstart, blkstart, blklen);
	mutex_unlock(&SM_I(sbi)->dcc_info->cmd_lock);
	return 0;
}

static unsigned int __issue_discard_cmd_orderly(struct f2fs_sb_info *sbi,
					struct discard_policy *dpolicy)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct discard_cmd *prev_dc = NULL, *next_dc = NULL;
	struct rb_node **insert_p = NULL, *insert_parent = NULL;
	struct discard_cmd *dc;
	struct blk_plug plug;
	unsigned int pos = dcc->next_pos;
	unsigned int issued = 0;
	bool io_interrupted = false;

	mutex_lock(&dcc->cmd_lock);
	dc = (struct discard_cmd *)f2fs_lookup_rb_tree_ret(&dcc->root,
					NULL, pos,
					(struct rb_entry **)&prev_dc,
					(struct rb_entry **)&next_dc,
					&insert_p, &insert_parent, true, NULL);
	if (!dc)
		dc = next_dc;

	blk_start_plug(&plug);

	while (dc) {
		struct rb_node *node;
		int err = 0;

		if (dc->state != D_PREP)
			goto next;

		if (dpolicy->io_aware && !is_idle(sbi, DISCARD_TIME)) {
			io_interrupted = true;
			break;
		}

		dcc->next_pos = dc->lstart + dc->len;
		err = __submit_discard_cmd(sbi, dpolicy, dc, &issued);

		if (issued >= dpolicy->max_requests)
			break;
next:
		node = rb_next(&dc->rb_node);
		if (err)
			__remove_discard_cmd(sbi, dc);
		dc = rb_entry_safe(node, struct discard_cmd, rb_node);
	}

	blk_finish_plug(&plug);

	if (!dc)
		dcc->next_pos = 0;

=======
	__update_discard_tree_range(sbi, bdev, lblkstart, blkstart, blklen);
	return 0;
}

static int __issue_discard_cmd(struct f2fs_sb_info *sbi, bool issue_cond)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct list_head *pend_list;
	struct discard_cmd *dc, *tmp;
	struct blk_plug plug;
	int iter = 0, issued = 0;
	int i;
	bool io_interrupted = false;

	mutex_lock(&dcc->cmd_lock);
	f2fs_bug_on(sbi,
		!__check_rb_tree_consistence(sbi, &dcc->root));
	blk_start_plug(&plug);
	for (i = MAX_PLIST_NUM - 1;
			i >= 0 && plist_issue(dcc->pend_list_tag[i]); i--) {
		pend_list = &dcc->pend_list[i];
		list_for_each_entry_safe(dc, tmp, pend_list, list) {
			f2fs_bug_on(sbi, dc->state != D_PREP);

			/* Hurry up to finish fstrim */
			if (dcc->pend_list_tag[i] & P_TRIM) {
				__submit_discard_cmd(sbi, dc);
				issued++;

				if (fatal_signal_pending(current))
					break;
				continue;
			}

			if (!issue_cond) {
				__submit_discard_cmd(sbi, dc);
				issued++;
				continue;
			}

			if (is_idle(sbi)) {
				__submit_discard_cmd(sbi, dc);
				issued++;
			} else {
				io_interrupted = true;
			}

			if (++iter >= DISCARD_ISSUE_RATE)
				goto out;
		}
		if (list_empty(pend_list) && dcc->pend_list_tag[i] & P_TRIM)
			dcc->pend_list_tag[i] &= (~P_TRIM);
	}
out:
	blk_finish_plug(&plug);
>>>>>>> v4.14.187
	mutex_unlock(&dcc->cmd_lock);

	if (!issued && io_interrupted)
		issued = -1;

	return issued;
}
<<<<<<< HEAD
static unsigned int __wait_all_discard_cmd(struct f2fs_sb_info *sbi,
					struct discard_policy *dpolicy);

static int __issue_discard_cmd(struct f2fs_sb_info *sbi,
					struct discard_policy *dpolicy)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct list_head *pend_list;
	struct discard_cmd *dc, *tmp;
	struct blk_plug plug;
	int i, issued;
	bool io_interrupted = false;

	if (dpolicy->timeout)
		f2fs_update_time(sbi, UMOUNT_DISCARD_TIMEOUT);

retry:
	issued = 0;
	for (i = MAX_PLIST_NUM - 1; i >= 0; i--) {
		if (dpolicy->timeout &&
				f2fs_time_over(sbi, UMOUNT_DISCARD_TIMEOUT))
			break;

		if (i + 1 < dpolicy->granularity)
			break;

		if (i + 1 < DEFAULT_DISCARD_GRANULARITY && dpolicy->ordered)
			return __issue_discard_cmd_orderly(sbi, dpolicy);

		pend_list = &dcc->pend_list[i];

		mutex_lock(&dcc->cmd_lock);
		if (list_empty(pend_list))
			goto next;
		if (unlikely(dcc->rbtree_check))
			f2fs_bug_on(sbi, !f2fs_check_rb_tree_consistence(sbi,
								&dcc->root));
		blk_start_plug(&plug);
		list_for_each_entry_safe(dc, tmp, pend_list, list) {
			f2fs_bug_on(sbi, dc->state != D_PREP);

			if (dpolicy->timeout &&
				f2fs_time_over(sbi, UMOUNT_DISCARD_TIMEOUT))
				break;
#if 0
			if (dpolicy->io_aware && i < dpolicy->io_aware_gran &&
						!is_idle(sbi, DISCARD_TIME)) {
				io_interrupted = true;
				break;
			}
#endif
			__submit_discard_cmd(sbi, dpolicy, dc, &issued);

			if (issued >= dpolicy->max_requests)
				break;
		}
		blk_finish_plug(&plug);
next:
		mutex_unlock(&dcc->cmd_lock);

		if (issued >= dpolicy->max_requests || io_interrupted)
			break;
	}

	if (dpolicy->type == DPOLICY_UMOUNT && issued) {
		__wait_all_discard_cmd(sbi, dpolicy);
		goto retry;
	}

	if (!issued && io_interrupted)
		issued = -1;

	return issued;
}

static bool __drop_discard_cmd(struct f2fs_sb_info *sbi)
=======

static void __drop_discard_cmd(struct f2fs_sb_info *sbi)
>>>>>>> v4.14.187
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct list_head *pend_list;
	struct discard_cmd *dc, *tmp;
	int i;
<<<<<<< HEAD
	bool dropped = false;
=======
>>>>>>> v4.14.187

	mutex_lock(&dcc->cmd_lock);
	for (i = MAX_PLIST_NUM - 1; i >= 0; i--) {
		pend_list = &dcc->pend_list[i];
		list_for_each_entry_safe(dc, tmp, pend_list, list) {
			f2fs_bug_on(sbi, dc->state != D_PREP);
			__remove_discard_cmd(sbi, dc);
<<<<<<< HEAD
			dropped = true;
		}
	}
	mutex_unlock(&dcc->cmd_lock);

	return dropped;
}

void f2fs_drop_discard_cmd(struct f2fs_sb_info *sbi)
{
	__drop_discard_cmd(sbi);
}

static unsigned int __wait_one_discard_bio(struct f2fs_sb_info *sbi,
							struct discard_cmd *dc)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	unsigned int len = 0;
=======
		}
	}
	mutex_unlock(&dcc->cmd_lock);
}

static void __wait_one_discard_bio(struct f2fs_sb_info *sbi,
							struct discard_cmd *dc)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
>>>>>>> v4.14.187

	wait_for_completion_io(&dc->wait);
	mutex_lock(&dcc->cmd_lock);
	f2fs_bug_on(sbi, dc->state != D_DONE);
	dc->ref--;
<<<<<<< HEAD
	if (!dc->ref) {
		if (!dc->error)
			len = dc->len;
		__remove_discard_cmd(sbi, dc);
	}
	mutex_unlock(&dcc->cmd_lock);

	return len;
}

static unsigned int __wait_discard_cmd_range(struct f2fs_sb_info *sbi,
						struct discard_policy *dpolicy,
						block_t start, block_t end)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct list_head *wait_list = (dpolicy->type == DPOLICY_FSTRIM) ?
					&(dcc->fstrim_list) : &(dcc->wait_list);
	struct discard_cmd *dc, *tmp;
	bool need_wait;
	unsigned int trimmed = 0;
=======
	if (!dc->ref)
		__remove_discard_cmd(sbi, dc);
	mutex_unlock(&dcc->cmd_lock);
}

static void __wait_discard_cmd(struct f2fs_sb_info *sbi, bool wait_cond)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct list_head *wait_list = &(dcc->wait_list);
	struct discard_cmd *dc, *tmp;
	bool need_wait;
>>>>>>> v4.14.187

next:
	need_wait = false;

	mutex_lock(&dcc->cmd_lock);
	list_for_each_entry_safe(dc, tmp, wait_list, list) {
<<<<<<< HEAD
		if (dc->lstart + dc->len <= start || end <= dc->lstart)
			continue;
		if (dc->len < dpolicy->granularity)
			continue;
		if (dc->state == D_DONE && !dc->ref) {
			wait_for_completion_io(&dc->wait);
			if (!dc->error)
				trimmed += dc->len;
=======
		if (!wait_cond || (dc->state == D_DONE && !dc->ref)) {
			wait_for_completion_io(&dc->wait);
>>>>>>> v4.14.187
			__remove_discard_cmd(sbi, dc);
		} else {
			dc->ref++;
			need_wait = true;
			break;
		}
	}
	mutex_unlock(&dcc->cmd_lock);

	if (need_wait) {
<<<<<<< HEAD
		trimmed += __wait_one_discard_bio(sbi, dc);
		goto next;
	}

	return trimmed;
}

static unsigned int __wait_all_discard_cmd(struct f2fs_sb_info *sbi,
						struct discard_policy *dpolicy)
{
	struct discard_policy dp;
	unsigned int discard_blks;

	if (dpolicy)
		return __wait_discard_cmd_range(sbi, dpolicy, 0, UINT_MAX);

	/* wait all */
	__init_discard_policy(sbi, &dp, DPOLICY_FSTRIM, 1);
	discard_blks = __wait_discard_cmd_range(sbi, &dp, 0, UINT_MAX);
	__init_discard_policy(sbi, &dp, DPOLICY_UMOUNT, 1);
	discard_blks += __wait_discard_cmd_range(sbi, &dp, 0, UINT_MAX);

	return discard_blks;
}

/* This should be covered by global mutex, &sit_i->sentry_lock */
static void f2fs_wait_discard_bio(struct f2fs_sb_info *sbi, block_t blkaddr)
=======
		__wait_one_discard_bio(sbi, dc);
		goto next;
	}
}

/* This should be covered by global mutex, &sit_i->sentry_lock */
void f2fs_wait_discard_bio(struct f2fs_sb_info *sbi, block_t blkaddr)
>>>>>>> v4.14.187
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct discard_cmd *dc;
	bool need_wait = false;

	mutex_lock(&dcc->cmd_lock);
<<<<<<< HEAD
	dc = (struct discard_cmd *)f2fs_lookup_rb_tree(&dcc->root,
							NULL, blkaddr);
=======
	dc = (struct discard_cmd *)__lookup_rb_tree(&dcc->root, NULL, blkaddr);
>>>>>>> v4.14.187
	if (dc) {
		if (dc->state == D_PREP) {
			__punch_discard_cmd(sbi, dc, blkaddr);
		} else {
			dc->ref++;
			need_wait = true;
		}
	}
	mutex_unlock(&dcc->cmd_lock);

	if (need_wait)
		__wait_one_discard_bio(sbi, dc);
}

<<<<<<< HEAD
void f2fs_stop_discard_thread(struct f2fs_sb_info *sbi)
=======
void stop_discard_thread(struct f2fs_sb_info *sbi)
>>>>>>> v4.14.187
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;

	if (dcc && dcc->f2fs_issue_discard) {
		struct task_struct *discard_thread = dcc->f2fs_issue_discard;

		dcc->f2fs_issue_discard = NULL;
		kthread_stop(discard_thread);
	}
}

<<<<<<< HEAD
/* This comes from f2fs_put_super */
bool f2fs_issue_discard_timeout(struct f2fs_sb_info *sbi)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct discard_policy dpolicy;
	bool dropped;

	__init_discard_policy(sbi, &dpolicy, DPOLICY_UMOUNT,
					dcc->discard_granularity);
	__issue_discard_cmd(sbi, &dpolicy);
	dropped = __drop_discard_cmd(sbi);

	/* just to make sure there is no pending discard commands */
	__wait_all_discard_cmd(sbi, NULL);

	f2fs_bug_on(sbi, atomic_read(&dcc->discard_cmd_cnt));
	return dropped;
=======
/* This comes from f2fs_put_super and f2fs_trim_fs */
void f2fs_wait_discard_bios(struct f2fs_sb_info *sbi, bool umount)
{
	__issue_discard_cmd(sbi, false);
	__drop_discard_cmd(sbi);
	__wait_discard_cmd(sbi, !umount);
}

static void mark_discard_range_all(struct f2fs_sb_info *sbi)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	int i;

	mutex_lock(&dcc->cmd_lock);
	for (i = 0; i < MAX_PLIST_NUM; i++)
		dcc->pend_list_tag[i] |= P_TRIM;
	mutex_unlock(&dcc->cmd_lock);
>>>>>>> v4.14.187
}

static int issue_discard_thread(void *data)
{
	struct f2fs_sb_info *sbi = data;
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	wait_queue_head_t *q = &dcc->discard_wait_queue;
<<<<<<< HEAD
	struct discard_policy dpolicy;
=======
>>>>>>> v4.14.187
	unsigned int wait_ms = DEF_MIN_DISCARD_ISSUE_TIME;
	int issued;

	set_freezable();

	do {
<<<<<<< HEAD
		__init_discard_policy(sbi, &dpolicy, DPOLICY_BG,
					dcc->discard_granularity);

		wait_event_interruptible_timeout(*q,
				kthread_should_stop() || freezing(current) ||
				!wait_ms ||
				dcc->discard_wake,
				msecs_to_jiffies(wait_ms));

		if (dcc->discard_wake)
			dcc->discard_wake = 0;

		/* clean up pending candidates before going to sleep */
		if (atomic_read(&dcc->queued_discard))
			__wait_all_discard_cmd(sbi, NULL);

		if (try_to_freeze())
			continue;
		if (f2fs_readonly(sbi->sb))
			continue;
		if (kthread_should_stop())
			return 0;
		if (is_sbi_flag_set(sbi, SBI_NEED_FSCK)) {
			wait_ms = dpolicy.max_interval;
			continue;
		}

		if (sbi->gc_mode == GC_URGENT)
			__init_discard_policy(sbi, &dpolicy, DPOLICY_FORCE, 1);

		sb_start_intwrite(sbi->sb);

		issued = __issue_discard_cmd(sbi, &dpolicy);
		if (issued > 0) {
			__wait_all_discard_cmd(sbi, &dpolicy);
			wait_ms = dpolicy.min_interval;
			if (dpolicy.io_aware && is_idle(sbi, DISCARD_TIME))
				wait_ms = 0;
		} else if (issued == -1){
			wait_ms = f2fs_time_to_wait(sbi, DISCARD_TIME);
			if (!wait_ms)
				wait_ms = dpolicy.mid_interval;
		} else {
			wait_ms = dpolicy.max_interval;
=======
		wait_event_interruptible_timeout(*q,
				kthread_should_stop() || freezing(current) ||
				dcc->discard_wake,
				msecs_to_jiffies(wait_ms));
		if (try_to_freeze())
			continue;
		if (kthread_should_stop())
			return 0;

		if (dcc->discard_wake) {
			dcc->discard_wake = 0;
			if (sbi->gc_thread && sbi->gc_thread->gc_urgent)
				mark_discard_range_all(sbi);
		}

		sb_start_intwrite(sbi->sb);

		issued = __issue_discard_cmd(sbi, true);
		if (issued) {
			__wait_discard_cmd(sbi, true);
			wait_ms = DEF_MIN_DISCARD_ISSUE_TIME;
		} else {
			wait_ms = DEF_MAX_DISCARD_ISSUE_TIME;
>>>>>>> v4.14.187
		}

		sb_end_intwrite(sbi->sb);

	} while (!kthread_should_stop());
	return 0;
}

#ifdef CONFIG_BLK_DEV_ZONED
static int __f2fs_issue_discard_zone(struct f2fs_sb_info *sbi,
		struct block_device *bdev, block_t blkstart, block_t blklen)
{
	sector_t sector, nr_sects;
	block_t lblkstart = blkstart;
	int devi = 0;

	if (f2fs_is_multi_device(sbi)) {
		devi = f2fs_target_device_index(sbi, blkstart);
<<<<<<< HEAD
		if (blkstart < FDEV(devi).start_blk ||
		    blkstart > FDEV(devi).end_blk) {
			f2fs_err(sbi, "Invalid block %x", blkstart);
			return -EIO;
		}
		blkstart -= FDEV(devi).start_blk;
	}

	/* For sequential zones, reset the zone write pointer */
	if (f2fs_blkz_is_seq(sbi, devi, blkstart)) {
=======
		blkstart -= FDEV(devi).start_blk;
	}

	/*
	 * We need to know the type of the zone: for conventional zones,
	 * use regular discard if the drive supports it. For sequential
	 * zones, reset the zone write pointer.
	 */
	switch (get_blkz_type(sbi, bdev, blkstart)) {

	case BLK_ZONE_TYPE_CONVENTIONAL:
		if (!blk_queue_discard(bdev_get_queue(bdev)))
			return 0;
		return __queue_discard_cmd(sbi, bdev, lblkstart, blklen);
	case BLK_ZONE_TYPE_SEQWRITE_REQ:
	case BLK_ZONE_TYPE_SEQWRITE_PREF:
>>>>>>> v4.14.187
		sector = SECTOR_FROM_BLOCK(blkstart);
		nr_sects = SECTOR_FROM_BLOCK(blklen);

		if (sector & (bdev_zone_sectors(bdev) - 1) ||
				nr_sects != bdev_zone_sectors(bdev)) {
<<<<<<< HEAD
			f2fs_err(sbi, "(%d) %s: Unaligned zone reset attempted (block %x + %x)",
				 devi, sbi->s_ndevs ? FDEV(devi).path : "",
				 blkstart, blklen);
			return -EIO;
		}
		trace_f2fs_issue_reset_zone(bdev, blkstart);
		return blkdev_reset_zones(bdev, sector, nr_sects, GFP_NOFS);
	}

	/* For conventional zones, use regular discard if supported */
	return __queue_discard_cmd(sbi, bdev, lblkstart, blklen);
=======
			f2fs_msg(sbi->sb, KERN_INFO,
				"(%d) %s: Unaligned discard attempted (block %x + %x)",
				devi, sbi->s_ndevs ? FDEV(devi).path: "",
				blkstart, blklen);
			return -EIO;
		}
		trace_f2fs_issue_reset_zone(bdev, blkstart);
		return blkdev_reset_zones(bdev, sector,
					  nr_sects, GFP_NOFS);
	default:
		/* Unknown zone type: broken device ? */
		return -EIO;
	}
>>>>>>> v4.14.187
}
#endif

static int __issue_discard_async(struct f2fs_sb_info *sbi,
		struct block_device *bdev, block_t blkstart, block_t blklen)
{
#ifdef CONFIG_BLK_DEV_ZONED
<<<<<<< HEAD
	if (f2fs_sb_has_blkzoned(sbi) && bdev_is_zoned(bdev))
=======
	if (f2fs_sb_mounted_blkzoned(sbi->sb) &&
				bdev_zoned_model(bdev) != BLK_ZONED_NONE)
>>>>>>> v4.14.187
		return __f2fs_issue_discard_zone(sbi, bdev, blkstart, blklen);
#endif
	return __queue_discard_cmd(sbi, bdev, blkstart, blklen);
}

static int f2fs_issue_discard(struct f2fs_sb_info *sbi,
				block_t blkstart, block_t blklen)
{
	sector_t start = blkstart, len = 0;
	struct block_device *bdev;
	struct seg_entry *se;
	unsigned int offset;
	block_t i;
	int err = 0;

	bdev = f2fs_target_device(sbi, blkstart, NULL);

	for (i = blkstart; i < blkstart + blklen; i++, len++) {
		if (i != start) {
			struct block_device *bdev2 =
				f2fs_target_device(sbi, i, NULL);

			if (bdev2 != bdev) {
				err = __issue_discard_async(sbi, bdev,
						start, len);
				if (err)
					return err;
				bdev = bdev2;
				start = i;
				len = 0;
			}
		}

		se = get_seg_entry(sbi, GET_SEGNO(sbi, i));
		offset = GET_BLKOFF_FROM_SEG0(sbi, i);

		if (!f2fs_test_and_set_bit(offset, se->discard_map))
			sbi->discard_blks--;
	}

	if (len)
		err = __issue_discard_async(sbi, bdev, start, len);
	return err;
}

static bool add_discard_addrs(struct f2fs_sb_info *sbi, struct cp_control *cpc,
							bool check_only)
{
	int entries = SIT_VBLOCK_MAP_SIZE / sizeof(unsigned long);
	int max_blocks = sbi->blocks_per_seg;
	struct seg_entry *se = get_seg_entry(sbi, cpc->trim_start);
	unsigned long *cur_map = (unsigned long *)se->cur_valid_map;
	unsigned long *ckpt_map = (unsigned long *)se->ckpt_valid_map;
	unsigned long *discard_map = (unsigned long *)se->discard_map;
	unsigned long *dmap = SIT_I(sbi)->tmp_map;
	unsigned int start = 0, end = -1;
	bool force = (cpc->reason & CP_DISCARD);
	struct discard_entry *de = NULL;
	struct list_head *head = &SM_I(sbi)->dcc_info->entry_list;
	int i;

<<<<<<< HEAD
	if (se->valid_blocks == max_blocks || !f2fs_hw_support_discard(sbi))
		return false;

	if (!force) {
		if (!f2fs_realtime_discard_enable(sbi) || !se->valid_blocks ||
=======
	if (se->valid_blocks == max_blocks || !f2fs_discard_en(sbi))
		return false;

	if (!force) {
		if (!test_opt(sbi, DISCARD) || !se->valid_blocks ||
>>>>>>> v4.14.187
			SM_I(sbi)->dcc_info->nr_discards >=
				SM_I(sbi)->dcc_info->max_discards)
			return false;
	}

	/* SIT_VBLOCK_MAP_SIZE should be multiple of sizeof(unsigned long) */
	for (i = 0; i < entries; i++)
		dmap[i] = force ? ~ckpt_map[i] & ~discard_map[i] :
				(cur_map[i] ^ ckpt_map[i]) & ckpt_map[i];

	while (force || SM_I(sbi)->dcc_info->nr_discards <=
				SM_I(sbi)->dcc_info->max_discards) {
		start = __find_rev_next_bit(dmap, max_blocks, end + 1);
		if (start >= max_blocks)
			break;

		end = __find_rev_next_zero_bit(dmap, max_blocks, start + 1);
		if (force && start && end != max_blocks
					&& (end - start) < cpc->trim_minlen)
			continue;

		if (check_only)
			return true;

		if (!de) {
			de = f2fs_kmem_cache_alloc(discard_entry_slab,
								GFP_F2FS_ZERO);
			de->start_blkaddr = START_BLOCK(sbi, cpc->trim_start);
			list_add_tail(&de->list, head);
		}

		for (i = start; i < end; i++)
			__set_bit_le(i, (void *)de->discard_map);

		SM_I(sbi)->dcc_info->nr_discards += end - start;
	}
	return false;
}

<<<<<<< HEAD
static void release_discard_addr(struct discard_entry *entry)
{
	list_del(&entry->list);
	kmem_cache_free(discard_entry_slab, entry);
}

void f2fs_release_discard_addrs(struct f2fs_sb_info *sbi)
=======
void release_discard_addrs(struct f2fs_sb_info *sbi)
>>>>>>> v4.14.187
{
	struct list_head *head = &(SM_I(sbi)->dcc_info->entry_list);
	struct discard_entry *entry, *this;

	/* drop caches */
<<<<<<< HEAD
	list_for_each_entry_safe(entry, this, head, list)
		release_discard_addr(entry);
}

/*
 * Should call f2fs_clear_prefree_segments after checkpoint is done.
=======
	list_for_each_entry_safe(entry, this, head, list) {
		list_del(&entry->list);
		kmem_cache_free(discard_entry_slab, entry);
	}
}

/*
 * Should call clear_prefree_segments after checkpoint is done.
>>>>>>> v4.14.187
 */
static void set_prefree_as_free_segments(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	unsigned int segno;

	mutex_lock(&dirty_i->seglist_lock);
	for_each_set_bit(segno, dirty_i->dirty_segmap[PRE], MAIN_SEGS(sbi))
		__set_test_and_free(sbi, segno);
	mutex_unlock(&dirty_i->seglist_lock);
}

<<<<<<< HEAD
void f2fs_clear_prefree_segments(struct f2fs_sb_info *sbi,
						struct cp_control *cpc)
=======
void clear_prefree_segments(struct f2fs_sb_info *sbi, struct cp_control *cpc)
>>>>>>> v4.14.187
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct list_head *head = &dcc->entry_list;
	struct discard_entry *entry, *this;
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	unsigned long *prefree_map = dirty_i->dirty_segmap[PRE];
	unsigned int start = 0, end = -1;
	unsigned int secno, start_segno;
	bool force = (cpc->reason & CP_DISCARD);
<<<<<<< HEAD
	bool need_align = f2fs_lfs_mode(sbi) && __is_large_section(sbi);
=======
>>>>>>> v4.14.187

	mutex_lock(&dirty_i->seglist_lock);

	while (1) {
		int i;
<<<<<<< HEAD

		if (need_align && end != -1)
			end--;
=======
>>>>>>> v4.14.187
		start = find_next_bit(prefree_map, MAIN_SEGS(sbi), end + 1);
		if (start >= MAIN_SEGS(sbi))
			break;
		end = find_next_zero_bit(prefree_map, MAIN_SEGS(sbi),
								start + 1);

<<<<<<< HEAD
		if (need_align) {
			start = rounddown(start, sbi->segs_per_sec);
			end = roundup(end, sbi->segs_per_sec);
		}

		for (i = start; i < end; i++) {
			if (test_and_clear_bit(i, prefree_map))
				dirty_i->nr_dirty[PRE]--;
		}

		if (!f2fs_realtime_discard_enable(sbi))
=======
		for (i = start; i < end; i++)
			clear_bit(i, prefree_map);

		dirty_i->nr_dirty[PRE] -= end - start;

		if (!test_opt(sbi, DISCARD))
>>>>>>> v4.14.187
			continue;

		if (force && start >= cpc->trim_start &&
					(end - 1) <= cpc->trim_end)
				continue;

<<<<<<< HEAD
		if (!f2fs_lfs_mode(sbi) || !__is_large_section(sbi)) {
=======
		if (!test_opt(sbi, LFS) || sbi->segs_per_sec == 1) {
>>>>>>> v4.14.187
			f2fs_issue_discard(sbi, START_BLOCK(sbi, start),
				(end - start) << sbi->log_blocks_per_seg);
			continue;
		}
next:
		secno = GET_SEC_FROM_SEG(sbi, start);
		start_segno = GET_SEG_FROM_SEC(sbi, secno);
		if (!IS_CURSEC(sbi, secno) &&
			!get_valid_blocks(sbi, start, true))
			f2fs_issue_discard(sbi, START_BLOCK(sbi, start_segno),
				sbi->segs_per_sec << sbi->log_blocks_per_seg);

		start = start_segno + sbi->segs_per_sec;
		if (start < end)
			goto next;
		else
			end = start - 1;
	}
	mutex_unlock(&dirty_i->seglist_lock);

	/* send small discards */
	list_for_each_entry_safe(entry, this, head, list) {
		unsigned int cur_pos = 0, next_pos, len, total_len = 0;
		bool is_valid = test_bit_le(0, entry->discard_map);

find_next:
		if (is_valid) {
			next_pos = find_next_zero_bit_le(entry->discard_map,
					sbi->blocks_per_seg, cur_pos);
			len = next_pos - cur_pos;

<<<<<<< HEAD
			if (f2fs_sb_has_blkzoned(sbi) ||
=======
			if (f2fs_sb_mounted_blkzoned(sbi->sb) ||
>>>>>>> v4.14.187
			    (force && len < cpc->trim_minlen))
				goto skip;

			f2fs_issue_discard(sbi, entry->start_blkaddr + cur_pos,
									len);
<<<<<<< HEAD
=======
			cpc->trimmed += len;
>>>>>>> v4.14.187
			total_len += len;
		} else {
			next_pos = find_next_bit_le(entry->discard_map,
					sbi->blocks_per_seg, cur_pos);
		}
skip:
		cur_pos = next_pos;
		is_valid = !is_valid;

		if (cur_pos < sbi->blocks_per_seg)
			goto find_next;

<<<<<<< HEAD
		release_discard_addr(entry);
		dcc->nr_discards -= total_len;
=======
		list_del(&entry->list);
		dcc->nr_discards -= total_len;
		kmem_cache_free(discard_entry_slab, entry);
>>>>>>> v4.14.187
	}

	wake_up_discard_thread(sbi, false);
}

static int create_discard_cmd_control(struct f2fs_sb_info *sbi)
{
	dev_t dev = sbi->sb->s_bdev->bd_dev;
	struct discard_cmd_control *dcc;
	int err = 0, i;

	if (SM_I(sbi)->dcc_info) {
		dcc = SM_I(sbi)->dcc_info;
		goto init_thread;
	}

<<<<<<< HEAD
	dcc = f2fs_kzalloc(sbi, sizeof(struct discard_cmd_control), GFP_KERNEL);
=======
	dcc = kzalloc(sizeof(struct discard_cmd_control), GFP_KERNEL);
>>>>>>> v4.14.187
	if (!dcc)
		return -ENOMEM;

	dcc->discard_granularity = DEFAULT_DISCARD_GRANULARITY;
	INIT_LIST_HEAD(&dcc->entry_list);
<<<<<<< HEAD
	for (i = 0; i < MAX_PLIST_NUM; i++)
		INIT_LIST_HEAD(&dcc->pend_list[i]);
	INIT_LIST_HEAD(&dcc->wait_list);
	INIT_LIST_HEAD(&dcc->fstrim_list);
	mutex_init(&dcc->cmd_lock);
	atomic_set(&dcc->issued_discard, 0);
	atomic_set(&dcc->queued_discard, 0);
=======
	for (i = 0; i < MAX_PLIST_NUM; i++) {
		INIT_LIST_HEAD(&dcc->pend_list[i]);
		if (i >= dcc->discard_granularity - 1)
			dcc->pend_list_tag[i] |= P_ACTIVE;
	}
	INIT_LIST_HEAD(&dcc->wait_list);
	mutex_init(&dcc->cmd_lock);
	atomic_set(&dcc->issued_discard, 0);
	atomic_set(&dcc->issing_discard, 0);
>>>>>>> v4.14.187
	atomic_set(&dcc->discard_cmd_cnt, 0);
	dcc->nr_discards = 0;
	dcc->max_discards = MAIN_SEGS(sbi) << sbi->log_blocks_per_seg;
	dcc->undiscard_blks = 0;
<<<<<<< HEAD
	dcc->next_pos = 0;
	dcc->root = RB_ROOT_CACHED;
	dcc->rbtree_check = false;
=======
	dcc->root = RB_ROOT;
>>>>>>> v4.14.187

	init_waitqueue_head(&dcc->discard_wait_queue);
	SM_I(sbi)->dcc_info = dcc;
init_thread:
	dcc->f2fs_issue_discard = kthread_run(issue_discard_thread, sbi,
				"f2fs_discard-%u:%u", MAJOR(dev), MINOR(dev));
	if (IS_ERR(dcc->f2fs_issue_discard)) {
		err = PTR_ERR(dcc->f2fs_issue_discard);
<<<<<<< HEAD
		kvfree(dcc);
=======
		kfree(dcc);
>>>>>>> v4.14.187
		SM_I(sbi)->dcc_info = NULL;
		return err;
	}

	return err;
}

static void destroy_discard_cmd_control(struct f2fs_sb_info *sbi)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;

	if (!dcc)
		return;

<<<<<<< HEAD
	f2fs_stop_discard_thread(sbi);

	/*
	 * Recovery can cache discard commands, so in error path of
	 * fill_super(), it needs to give a chance to handle them.
	 */
	if (unlikely(atomic_read(&dcc->discard_cmd_cnt)))
		f2fs_issue_discard_timeout(sbi);

	kvfree(dcc);
=======
	stop_discard_thread(sbi);

	kfree(dcc);
>>>>>>> v4.14.187
	SM_I(sbi)->dcc_info = NULL;
}

static bool __mark_sit_entry_dirty(struct f2fs_sb_info *sbi, unsigned int segno)
{
	struct sit_info *sit_i = SIT_I(sbi);

	if (!__test_and_set_bit(segno, sit_i->dirty_sentries_bitmap)) {
		sit_i->dirty_sentries++;
		return false;
	}

	return true;
}

static void __set_sit_entry_type(struct f2fs_sb_info *sbi, int type,
					unsigned int segno, int modified)
{
	struct seg_entry *se = get_seg_entry(sbi, segno);
	se->type = type;
	if (modified)
		__mark_sit_entry_dirty(sbi, segno);
}

static void update_sit_entry(struct f2fs_sb_info *sbi, block_t blkaddr, int del)
{
	struct seg_entry *se;
	unsigned int segno, offset;
	long int new_vblocks;
	bool exist;
#ifdef CONFIG_F2FS_CHECK_FS
	bool mir_exist;
#endif

	segno = GET_SEGNO(sbi, blkaddr);

	se = get_seg_entry(sbi, segno);
	new_vblocks = se->valid_blocks + del;
	offset = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);

	f2fs_bug_on(sbi, (new_vblocks >> (sizeof(unsigned short) << 3) ||
				(new_vblocks > sbi->blocks_per_seg)));

	se->valid_blocks = new_vblocks;
<<<<<<< HEAD
	se->mtime = get_mtime(sbi, false);
	if (se->mtime > SIT_I(sbi)->max_mtime)
		SIT_I(sbi)->max_mtime = se->mtime;
=======
	se->mtime = get_mtime(sbi);
	SIT_I(sbi)->max_mtime = se->mtime;
>>>>>>> v4.14.187

	/* Update valid block bitmap */
	if (del > 0) {
		exist = f2fs_test_and_set_bit(offset, se->cur_valid_map);
#ifdef CONFIG_F2FS_CHECK_FS
		mir_exist = f2fs_test_and_set_bit(offset,
						se->cur_valid_map_mir);
		if (unlikely(exist != mir_exist)) {
<<<<<<< HEAD
			f2fs_err(sbi, "Inconsistent error when setting bitmap, blk:%u, old bit:%d",
				 blkaddr, exist);
=======
			f2fs_msg(sbi->sb, KERN_ERR, "Inconsistent error "
				"when setting bitmap, blk:%u, old bit:%d",
				blkaddr, exist);
>>>>>>> v4.14.187
			f2fs_bug_on(sbi, 1);
		}
#endif
		if (unlikely(exist)) {
<<<<<<< HEAD
			f2fs_err(sbi, "Bitmap was wrongly set, blk:%u",
				 blkaddr);
=======
			f2fs_msg(sbi->sb, KERN_ERR,
				"Bitmap was wrongly set, blk:%u", blkaddr);
>>>>>>> v4.14.187
			f2fs_bug_on(sbi, 1);
			se->valid_blocks--;
			del = 0;
		}

<<<<<<< HEAD
		if (!f2fs_test_and_set_bit(offset, se->discard_map))
			sbi->discard_blks--;

		/*
		 * SSR should never reuse block which is checkpointed
		 * or newly invalidated.
		 */
		if (!is_sbi_flag_set(sbi, SBI_CP_DISABLED)) {
=======
		if (f2fs_discard_en(sbi) &&
			!f2fs_test_and_set_bit(offset, se->discard_map))
			sbi->discard_blks--;

		/* don't overwrite by SSR to keep node chain */
		if (se->type == CURSEG_WARM_NODE) {
>>>>>>> v4.14.187
			if (!f2fs_test_and_set_bit(offset, se->ckpt_valid_map))
				se->ckpt_valid_blocks++;
		}
	} else {
		exist = f2fs_test_and_clear_bit(offset, se->cur_valid_map);
#ifdef CONFIG_F2FS_CHECK_FS
		mir_exist = f2fs_test_and_clear_bit(offset,
						se->cur_valid_map_mir);
		if (unlikely(exist != mir_exist)) {
<<<<<<< HEAD
			f2fs_err(sbi, "Inconsistent error when clearing bitmap, blk:%u, old bit:%d",
				 blkaddr, exist);
=======
			f2fs_msg(sbi->sb, KERN_ERR, "Inconsistent error "
				"when clearing bitmap, blk:%u, old bit:%d",
				blkaddr, exist);
>>>>>>> v4.14.187
			f2fs_bug_on(sbi, 1);
		}
#endif
		if (unlikely(!exist)) {
<<<<<<< HEAD
			f2fs_err(sbi, "Bitmap was wrongly cleared, blk:%u",
				 blkaddr);
			f2fs_bug_on(sbi, 1);
			se->valid_blocks++;
			del = 0;
		} else if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED))) {
			/*
			 * If checkpoints are off, we must not reuse data that
			 * was used in the previous checkpoint. If it was used
			 * before, we must track that to know how much space we
			 * really have.
			 */
			if (f2fs_test_bit(offset, se->ckpt_valid_map)) {
				spin_lock(&sbi->stat_lock);
				sbi->unusable_block_count++;
				spin_unlock(&sbi->stat_lock);
			}
		}

		if (f2fs_test_and_clear_bit(offset, se->discard_map))
=======
			f2fs_msg(sbi->sb, KERN_ERR,
				"Bitmap was wrongly cleared, blk:%u", blkaddr);
			f2fs_bug_on(sbi, 1);
			se->valid_blocks++;
			del = 0;
		}

		if (f2fs_discard_en(sbi) &&
			f2fs_test_and_clear_bit(offset, se->discard_map))
>>>>>>> v4.14.187
			sbi->discard_blks++;
	}
	if (!f2fs_test_bit(offset, se->ckpt_valid_map))
		se->ckpt_valid_blocks += del;

	__mark_sit_entry_dirty(sbi, segno);

	/* update total number of valid blocks to be written in ckpt area */
	SIT_I(sbi)->written_valid_blocks += del;

<<<<<<< HEAD
	if (__is_large_section(sbi))
		get_sec_entry(sbi, segno)->valid_blocks += del;
}

void f2fs_invalidate_blocks(struct f2fs_sb_info *sbi, block_t addr)
=======
	if (sbi->segs_per_sec > 1)
		get_sec_entry(sbi, segno)->valid_blocks += del;
}

void refresh_sit_entry(struct f2fs_sb_info *sbi, block_t old, block_t new)
{
	update_sit_entry(sbi, new, 1);
	if (GET_SEGNO(sbi, old) != NULL_SEGNO)
		update_sit_entry(sbi, old, -1);

	locate_dirty_segment(sbi, GET_SEGNO(sbi, old));
	locate_dirty_segment(sbi, GET_SEGNO(sbi, new));
}

void invalidate_blocks(struct f2fs_sb_info *sbi, block_t addr)
>>>>>>> v4.14.187
{
	unsigned int segno = GET_SEGNO(sbi, addr);
	struct sit_info *sit_i = SIT_I(sbi);

	f2fs_bug_on(sbi, addr == NULL_ADDR);
<<<<<<< HEAD
	if (addr == NEW_ADDR || addr == COMPRESS_ADDR)
		return;

	invalidate_mapping_pages(META_MAPPING(sbi), addr, addr);

	/* add it into sit main buffer */
	down_write(&sit_i->sentry_lock);
=======
	if (addr == NEW_ADDR)
		return;

	/* add it into sit main buffer */
	mutex_lock(&sit_i->sentry_lock);
>>>>>>> v4.14.187

	update_sit_entry(sbi, addr, -1);

	/* add it into dirty seglist */
	locate_dirty_segment(sbi, segno);

<<<<<<< HEAD
	up_write(&sit_i->sentry_lock);
}

bool f2fs_is_checkpointed_data(struct f2fs_sb_info *sbi, block_t blkaddr)
=======
	mutex_unlock(&sit_i->sentry_lock);
}

bool is_checkpointed_data(struct f2fs_sb_info *sbi, block_t blkaddr)
>>>>>>> v4.14.187
{
	struct sit_info *sit_i = SIT_I(sbi);
	unsigned int segno, offset;
	struct seg_entry *se;
	bool is_cp = false;

<<<<<<< HEAD
	if (!__is_valid_data_blkaddr(blkaddr))
		return true;

	down_read(&sit_i->sentry_lock);
=======
	if (!is_valid_data_blkaddr(sbi, blkaddr))
		return true;

	mutex_lock(&sit_i->sentry_lock);
>>>>>>> v4.14.187

	segno = GET_SEGNO(sbi, blkaddr);
	se = get_seg_entry(sbi, segno);
	offset = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);

	if (f2fs_test_bit(offset, se->ckpt_valid_map))
		is_cp = true;

<<<<<<< HEAD
	up_read(&sit_i->sentry_lock);
=======
	mutex_unlock(&sit_i->sentry_lock);
>>>>>>> v4.14.187

	return is_cp;
}

/*
 * This function should be resided under the curseg_mutex lock
 */
static void __add_sum_entry(struct f2fs_sb_info *sbi, int type,
					struct f2fs_summary *sum)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	void *addr = curseg->sum_blk;
	addr += curseg->next_blkoff * sizeof(struct f2fs_summary);
	memcpy(addr, sum, sizeof(struct f2fs_summary));
}

/*
 * Calculate the number of current summary pages for writing
 */
<<<<<<< HEAD
int f2fs_npages_for_summary_flush(struct f2fs_sb_info *sbi, bool for_ra)
=======
int npages_for_summary_flush(struct f2fs_sb_info *sbi, bool for_ra)
>>>>>>> v4.14.187
{
	int valid_sum_count = 0;
	int i, sum_in_page;

	for (i = CURSEG_HOT_DATA; i <= CURSEG_COLD_DATA; i++) {
		if (sbi->ckpt->alloc_type[i] == SSR)
			valid_sum_count += sbi->blocks_per_seg;
		else {
			if (for_ra)
				valid_sum_count += le16_to_cpu(
					F2FS_CKPT(sbi)->cur_data_blkoff[i]);
			else
				valid_sum_count += curseg_blkoff(sbi, i);
		}
	}

	sum_in_page = (PAGE_SIZE - 2 * SUM_JOURNAL_SIZE -
			SUM_FOOTER_SIZE) / SUMMARY_SIZE;
	if (valid_sum_count <= sum_in_page)
		return 1;
	else if ((valid_sum_count - sum_in_page) <=
		(PAGE_SIZE - SUM_FOOTER_SIZE) / SUMMARY_SIZE)
		return 2;
	return 3;
}

/*
 * Caller should put this summary page
 */
<<<<<<< HEAD
struct page *f2fs_get_sum_page(struct f2fs_sb_info *sbi, unsigned int segno)
{
	return f2fs_get_meta_page_nofail(sbi, GET_SUM_BLOCK(sbi, segno));
}

void f2fs_update_meta_page(struct f2fs_sb_info *sbi,
					void *src, block_t blk_addr)
{
	struct page *page = f2fs_grab_meta_page(sbi, blk_addr);

	memcpy(page_address(page), src, PAGE_SIZE);
=======
struct page *get_sum_page(struct f2fs_sb_info *sbi, unsigned int segno)
{
	return get_meta_page(sbi, GET_SUM_BLOCK(sbi, segno));
}

void update_meta_page(struct f2fs_sb_info *sbi, void *src, block_t blk_addr)
{
	struct page *page = grab_meta_page(sbi, blk_addr);
	void *dst = page_address(page);

	if (src)
		memcpy(dst, src, PAGE_SIZE);
	else
		memset(dst, 0, PAGE_SIZE);
>>>>>>> v4.14.187
	set_page_dirty(page);
	f2fs_put_page(page, 1);
}

static void write_sum_page(struct f2fs_sb_info *sbi,
			struct f2fs_summary_block *sum_blk, block_t blk_addr)
{
<<<<<<< HEAD
	f2fs_update_meta_page(sbi, (void *)sum_blk, blk_addr);
=======
	update_meta_page(sbi, (void *)sum_blk, blk_addr);
>>>>>>> v4.14.187
}

static void write_current_sum_page(struct f2fs_sb_info *sbi,
						int type, block_t blk_addr)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
<<<<<<< HEAD
	struct page *page = f2fs_grab_meta_page(sbi, blk_addr);
=======
	struct page *page = grab_meta_page(sbi, blk_addr);
>>>>>>> v4.14.187
	struct f2fs_summary_block *src = curseg->sum_blk;
	struct f2fs_summary_block *dst;

	dst = (struct f2fs_summary_block *)page_address(page);
<<<<<<< HEAD
	memset(dst, 0, PAGE_SIZE);
=======
>>>>>>> v4.14.187

	mutex_lock(&curseg->curseg_mutex);

	down_read(&curseg->journal_rwsem);
	memcpy(&dst->journal, curseg->journal, SUM_JOURNAL_SIZE);
	up_read(&curseg->journal_rwsem);

	memcpy(dst->entries, src->entries, SUM_ENTRY_SIZE);
	memcpy(&dst->footer, &src->footer, SUM_FOOTER_SIZE);

	mutex_unlock(&curseg->curseg_mutex);

	set_page_dirty(page);
	f2fs_put_page(page, 1);
}

static int is_next_segment_free(struct f2fs_sb_info *sbi, int type)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	unsigned int segno = curseg->segno + 1;
	struct free_segmap_info *free_i = FREE_I(sbi);

	if (segno < MAIN_SEGS(sbi) && segno % sbi->segs_per_sec)
		return !test_bit(segno, free_i->free_segmap);
	return 0;
}

/*
 * Find a new segment from the free segments bitmap to right order
 * This function should be returned with success, otherwise BUG
 */
static void get_new_segment(struct f2fs_sb_info *sbi,
			unsigned int *newseg, bool new_sec, int dir)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int segno, secno, zoneno;
	unsigned int total_zones = MAIN_SECS(sbi) / sbi->secs_per_zone;
	unsigned int hint = GET_SEC_FROM_SEG(sbi, *newseg);
	unsigned int old_zoneno = GET_ZONE_FROM_SEG(sbi, *newseg);
	unsigned int left_start = hint;
	bool init = true;
	int go_left = 0;
	int i;

	spin_lock(&free_i->segmap_lock);

	if (!new_sec && ((*newseg + 1) % sbi->segs_per_sec)) {
		segno = find_next_zero_bit(free_i->free_segmap,
			GET_SEG_FROM_SEC(sbi, hint + 1), *newseg + 1);
		if (segno < GET_SEG_FROM_SEC(sbi, hint + 1))
			goto got_it;
	}
find_other_zone:
	secno = find_next_zero_bit(free_i->free_secmap, MAIN_SECS(sbi), hint);
	if (secno >= MAIN_SECS(sbi)) {
		if (dir == ALLOC_RIGHT) {
			secno = find_next_zero_bit(free_i->free_secmap,
							MAIN_SECS(sbi), 0);
			f2fs_bug_on(sbi, secno >= MAIN_SECS(sbi));
		} else {
			go_left = 1;
			left_start = hint - 1;
		}
	}
	if (go_left == 0)
		goto skip_left;

	while (test_bit(left_start, free_i->free_secmap)) {
		if (left_start > 0) {
			left_start--;
			continue;
		}
		left_start = find_next_zero_bit(free_i->free_secmap,
							MAIN_SECS(sbi), 0);
		f2fs_bug_on(sbi, left_start >= MAIN_SECS(sbi));
		break;
	}
	secno = left_start;
skip_left:
<<<<<<< HEAD
=======
	hint = secno;
>>>>>>> v4.14.187
	segno = GET_SEG_FROM_SEC(sbi, secno);
	zoneno = GET_ZONE_FROM_SEC(sbi, secno);

	/* give up on finding another zone */
	if (!init)
		goto got_it;
	if (sbi->secs_per_zone == 1)
		goto got_it;
	if (zoneno == old_zoneno)
		goto got_it;
	if (dir == ALLOC_LEFT) {
		if (!go_left && zoneno + 1 >= total_zones)
			goto got_it;
		if (go_left && zoneno == 0)
			goto got_it;
	}
	for (i = 0; i < NR_CURSEG_TYPE; i++)
		if (CURSEG_I(sbi, i)->zone == zoneno)
			break;

	if (i < NR_CURSEG_TYPE) {
		/* zone is in user, try another */
		if (go_left)
			hint = zoneno * sbi->secs_per_zone - 1;
		else if (zoneno + 1 >= total_zones)
			hint = 0;
		else
			hint = (zoneno + 1) * sbi->secs_per_zone;
		init = false;
		goto find_other_zone;
	}
got_it:
	/* set it as dirty segment in free segmap */
	f2fs_bug_on(sbi, test_bit(segno, free_i->free_segmap));
	__set_inuse(sbi, segno);
	*newseg = segno;
	spin_unlock(&free_i->segmap_lock);
}

static void reset_curseg(struct f2fs_sb_info *sbi, int type, int modified)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	struct summary_footer *sum_footer;

	curseg->segno = curseg->next_segno;
	curseg->zone = GET_ZONE_FROM_SEG(sbi, curseg->segno);
	curseg->next_blkoff = 0;
	curseg->next_segno = NULL_SEGNO;

	sum_footer = &(curseg->sum_blk->footer);
	memset(sum_footer, 0, sizeof(struct summary_footer));
	if (IS_DATASEG(type))
		SET_SUM_TYPE(sum_footer, SUM_TYPE_DATA);
	if (IS_NODESEG(type))
		SET_SUM_TYPE(sum_footer, SUM_TYPE_NODE);
	__set_sit_entry_type(sbi, type, curseg->segno, modified);
}

static unsigned int __get_next_segno(struct f2fs_sb_info *sbi, int type)
{
	/* if segs_per_sec is large than 1, we need to keep original policy. */
<<<<<<< HEAD
	if (__is_large_section(sbi))
		return CURSEG_I(sbi, type)->segno;

	if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED)))
		return 0;

=======
	if (sbi->segs_per_sec != 1)
		return CURSEG_I(sbi, type)->segno;

>>>>>>> v4.14.187
	if (test_opt(sbi, NOHEAP) &&
		(type == CURSEG_HOT_DATA || IS_NODESEG(type)))
		return 0;

	if (SIT_I(sbi)->last_victim[ALLOC_NEXT])
		return SIT_I(sbi)->last_victim[ALLOC_NEXT];
<<<<<<< HEAD

	/* find segments from 0 to reuse freed segments */
	if (F2FS_OPTION(sbi).alloc_mode == ALLOC_MODE_REUSE)
		return 0;

=======
>>>>>>> v4.14.187
	return CURSEG_I(sbi, type)->segno;
}

/*
 * Allocate a current working segment.
 * This function always allocates a free segment in LFS manner.
 */
static void new_curseg(struct f2fs_sb_info *sbi, int type, bool new_sec)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	unsigned int segno = curseg->segno;
	int dir = ALLOC_LEFT;

	write_sum_page(sbi, curseg->sum_blk,
				GET_SUM_BLOCK(sbi, segno));
	if (type == CURSEG_WARM_DATA || type == CURSEG_COLD_DATA)
		dir = ALLOC_RIGHT;

	if (test_opt(sbi, NOHEAP))
		dir = ALLOC_RIGHT;

	segno = __get_next_segno(sbi, type);
	get_new_segment(sbi, &segno, new_sec, dir);
	curseg->next_segno = segno;
	reset_curseg(sbi, type, 1);
	curseg->alloc_type = LFS;
}

static void __next_free_blkoff(struct f2fs_sb_info *sbi,
			struct curseg_info *seg, block_t start)
{
	struct seg_entry *se = get_seg_entry(sbi, seg->segno);
	int entries = SIT_VBLOCK_MAP_SIZE / sizeof(unsigned long);
	unsigned long *target_map = SIT_I(sbi)->tmp_map;
	unsigned long *ckpt_map = (unsigned long *)se->ckpt_valid_map;
	unsigned long *cur_map = (unsigned long *)se->cur_valid_map;
	int i, pos;

	for (i = 0; i < entries; i++)
		target_map[i] = ckpt_map[i] | cur_map[i];

	pos = __find_rev_next_zero_bit(target_map, sbi->blocks_per_seg, start);

	seg->next_blkoff = pos;
}

/*
 * If a segment is written by LFS manner, next block offset is just obtained
 * by increasing the current block offset. However, if a segment is written by
 * SSR manner, next block offset obtained by calling __next_free_blkoff
 */
static void __refresh_next_blkoff(struct f2fs_sb_info *sbi,
				struct curseg_info *seg)
{
	if (seg->alloc_type == SSR)
		__next_free_blkoff(sbi, seg, seg->next_blkoff + 1);
	else
		seg->next_blkoff++;
}

/*
 * This function always allocates a used segment(from dirty seglist) by SSR
 * manner, so it should recover the existing segment information of valid blocks
 */
static void change_curseg(struct f2fs_sb_info *sbi, int type)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	unsigned int new_segno = curseg->next_segno;
	struct f2fs_summary_block *sum_node;
	struct page *sum_page;

	write_sum_page(sbi, curseg->sum_blk,
				GET_SUM_BLOCK(sbi, curseg->segno));
	__set_test_and_inuse(sbi, new_segno);

	mutex_lock(&dirty_i->seglist_lock);
	__remove_dirty_segment(sbi, new_segno, PRE);
	__remove_dirty_segment(sbi, new_segno, DIRTY);
	mutex_unlock(&dirty_i->seglist_lock);

	reset_curseg(sbi, type, 1);
	curseg->alloc_type = SSR;
	__next_free_blkoff(sbi, curseg, 0);

<<<<<<< HEAD
	sum_page = f2fs_get_sum_page(sbi, new_segno);
	f2fs_bug_on(sbi, IS_ERR(sum_page));

	/* W/A - prevent panic while shutdown */
	if (unlikely(ignore_fs_panic && IS_ERR(sum_page))) {
		//pr_err("%s: Ignore panic err=%ld\n", __func__, PTR_ERR(sum_page));
		return;
	}

=======
	sum_page = get_sum_page(sbi, new_segno);
>>>>>>> v4.14.187
	sum_node = (struct f2fs_summary_block *)page_address(sum_page);
	memcpy(curseg->sum_blk, sum_node, SUM_ENTRY_SIZE);
	f2fs_put_page(sum_page, 1);
}

static int get_ssr_segment(struct f2fs_sb_info *sbi, int type)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	const struct victim_selection *v_ops = DIRTY_I(sbi)->v_ops;
	unsigned segno = NULL_SEGNO;
	int i, cnt;
	bool reversed = false;

<<<<<<< HEAD
	/* f2fs_need_SSR() already forces to do this */
=======
	/* need_SSR() already forces to do this */
>>>>>>> v4.14.187
	if (v_ops->get_victim(sbi, &segno, BG_GC, type, SSR)) {
		curseg->next_segno = segno;
		return 1;
	}

	/* For node segments, let's do SSR more intensively */
	if (IS_NODESEG(type)) {
		if (type >= CURSEG_WARM_NODE) {
			reversed = true;
			i = CURSEG_COLD_NODE;
		} else {
			i = CURSEG_HOT_NODE;
		}
		cnt = NR_CURSEG_NODE_TYPE;
	} else {
		if (type >= CURSEG_WARM_DATA) {
			reversed = true;
			i = CURSEG_COLD_DATA;
		} else {
			i = CURSEG_HOT_DATA;
		}
		cnt = NR_CURSEG_DATA_TYPE;
	}

	for (; cnt-- > 0; reversed ? i-- : i++) {
		if (i == type)
			continue;
		if (v_ops->get_victim(sbi, &segno, BG_GC, i, SSR)) {
			curseg->next_segno = segno;
			return 1;
		}
	}
<<<<<<< HEAD

	/* find valid_blocks=0 in dirty list */
	if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED))) {
		segno = get_free_segment(sbi);
		if (segno != NULL_SEGNO) {
			curseg->next_segno = segno;
			return 1;
		}
	}
=======
>>>>>>> v4.14.187
	return 0;
}

/*
 * flush out current segment and replace it with new segment
 * This function should be returned with success, otherwise BUG
 */
static void allocate_segment_by_default(struct f2fs_sb_info *sbi,
						int type, bool force)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);

	if (force)
		new_curseg(sbi, type, true);
	else if (!is_set_ckpt_flags(sbi, CP_CRC_RECOVERY_FLAG) &&
					type == CURSEG_WARM_NODE)
		new_curseg(sbi, type, false);
<<<<<<< HEAD
	else if (curseg->alloc_type == LFS && is_next_segment_free(sbi, type) &&
			likely(!is_sbi_flag_set(sbi, SBI_CP_DISABLED)))
		new_curseg(sbi, type, false);
	else if (f2fs_need_SSR(sbi) && get_ssr_segment(sbi, type))
=======
	else if (curseg->alloc_type == LFS && is_next_segment_free(sbi, type))
		new_curseg(sbi, type, false);
	else if (need_SSR(sbi) && get_ssr_segment(sbi, type))
>>>>>>> v4.14.187
		change_curseg(sbi, type);
	else
		new_curseg(sbi, type, false);

	stat_inc_seg_type(sbi, curseg);
<<<<<<< HEAD
	sbi->sec_stat.alloc_seg_type[curseg->alloc_type]++;
}

void allocate_segment_for_resize(struct f2fs_sb_info *sbi, int type,
					unsigned int start, unsigned int end)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	unsigned int segno;

	down_read(&SM_I(sbi)->curseg_lock);
	mutex_lock(&curseg->curseg_mutex);
	down_write(&SIT_I(sbi)->sentry_lock);

	segno = CURSEG_I(sbi, type)->segno;
	if (segno < start || segno > end)
		goto unlock;

	if (f2fs_need_SSR(sbi) && get_ssr_segment(sbi, type))
		change_curseg(sbi, type);
	else
		new_curseg(sbi, type, true);

	stat_inc_seg_type(sbi, curseg);

	locate_dirty_segment(sbi, segno);
unlock:
	up_write(&SIT_I(sbi)->sentry_lock);

	if (segno != curseg->segno)
		f2fs_notice(sbi, "For resize: curseg of type %d: %u ==> %u",
			    type, segno, curseg->segno);

	mutex_unlock(&curseg->curseg_mutex);
	up_read(&SM_I(sbi)->curseg_lock);
}

void f2fs_allocate_new_segments(struct f2fs_sb_info *sbi, int type)
=======
}

void allocate_new_segments(struct f2fs_sb_info *sbi)
>>>>>>> v4.14.187
{
	struct curseg_info *curseg;
	unsigned int old_segno;
	int i;

<<<<<<< HEAD
	down_write(&SIT_I(sbi)->sentry_lock);

	for (i = CURSEG_HOT_DATA; i <= CURSEG_COLD_DATA; i++) {
		if (type != NO_CHECK_TYPE && i != type)
			continue;

		curseg = CURSEG_I(sbi, i);
		if (type == NO_CHECK_TYPE || curseg->next_blkoff ||
				get_valid_blocks(sbi, curseg->segno, false) ||
				get_ckpt_valid_blocks(sbi, curseg->segno)) {
			old_segno = curseg->segno;
			SIT_I(sbi)->s_ops->allocate_segment(sbi, i, true);
			locate_dirty_segment(sbi, old_segno);
		}
	}

	up_write(&SIT_I(sbi)->sentry_lock);
=======
	for (i = CURSEG_HOT_DATA; i <= CURSEG_COLD_DATA; i++) {
		curseg = CURSEG_I(sbi, i);
		old_segno = curseg->segno;
		SIT_I(sbi)->s_ops->allocate_segment(sbi, i, true);
		locate_dirty_segment(sbi, old_segno);
	}
>>>>>>> v4.14.187
}

static const struct segment_allocation default_salloc_ops = {
	.allocate_segment = allocate_segment_by_default,
};

<<<<<<< HEAD
bool f2fs_exist_trim_candidates(struct f2fs_sb_info *sbi,
						struct cp_control *cpc)
=======
bool exist_trim_candidates(struct f2fs_sb_info *sbi, struct cp_control *cpc)
>>>>>>> v4.14.187
{
	__u64 trim_start = cpc->trim_start;
	bool has_candidate = false;

<<<<<<< HEAD
	down_write(&SIT_I(sbi)->sentry_lock);
=======
	mutex_lock(&SIT_I(sbi)->sentry_lock);
>>>>>>> v4.14.187
	for (; cpc->trim_start <= cpc->trim_end; cpc->trim_start++) {
		if (add_discard_addrs(sbi, cpc, true)) {
			has_candidate = true;
			break;
		}
	}
<<<<<<< HEAD
	up_write(&SIT_I(sbi)->sentry_lock);
=======
	mutex_unlock(&SIT_I(sbi)->sentry_lock);
>>>>>>> v4.14.187

	cpc->trim_start = trim_start;
	return has_candidate;
}

<<<<<<< HEAD
static unsigned int __issue_discard_cmd_range(struct f2fs_sb_info *sbi,
					struct discard_policy *dpolicy,
					unsigned int start, unsigned int end)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct discard_cmd *prev_dc = NULL, *next_dc = NULL;
	struct rb_node **insert_p = NULL, *insert_parent = NULL;
	struct discard_cmd *dc;
	struct blk_plug plug;
	int issued;
	unsigned int trimmed = 0;

next:
	issued = 0;

	mutex_lock(&dcc->cmd_lock);
	if (unlikely(dcc->rbtree_check))
		f2fs_bug_on(sbi, !f2fs_check_rb_tree_consistence(sbi,
								&dcc->root));

	dc = (struct discard_cmd *)f2fs_lookup_rb_tree_ret(&dcc->root,
					NULL, start,
					(struct rb_entry **)&prev_dc,
					(struct rb_entry **)&next_dc,
					&insert_p, &insert_parent, true, NULL);
	if (!dc)
		dc = next_dc;

	blk_start_plug(&plug);

	while (dc && dc->lstart <= end) {
		struct rb_node *node;
		int err = 0;

		if (dc->len < dpolicy->granularity)
			goto skip;

		if (dc->state != D_PREP) {
			list_move_tail(&dc->list, &dcc->fstrim_list);
			goto skip;
		}

		err = __submit_discard_cmd(sbi, dpolicy, dc, &issued);

		if (issued >= dpolicy->max_requests) {
			start = dc->lstart + dc->len;

			if (err)
				__remove_discard_cmd(sbi, dc);

			blk_finish_plug(&plug);
			mutex_unlock(&dcc->cmd_lock);
			trimmed += __wait_all_discard_cmd(sbi, NULL);
			congestion_wait(BLK_RW_ASYNC, DEFAULT_IO_TIMEOUT);
			goto next;
		}
skip:
		node = rb_next(&dc->rb_node);
		if (err)
			__remove_discard_cmd(sbi, dc);
		dc = rb_entry_safe(node, struct discard_cmd, rb_node);

		if (fatal_signal_pending(current))
			break;
	}

	blk_finish_plug(&plug);
	mutex_unlock(&dcc->cmd_lock);

	return trimmed;
}

=======
>>>>>>> v4.14.187
int f2fs_trim_fs(struct f2fs_sb_info *sbi, struct fstrim_range *range)
{
	__u64 start = F2FS_BYTES_TO_BLK(range->start);
	__u64 end = start + F2FS_BYTES_TO_BLK(range->len) - 1;
	unsigned int start_segno, end_segno;
<<<<<<< HEAD
	block_t start_block, end_block;
	struct cp_control cpc;
	struct discard_policy dpolicy;
	unsigned long long trimmed = 0;
	int err = 0;
	bool need_align = f2fs_lfs_mode(sbi) && __is_large_section(sbi);
=======
	struct cp_control cpc;
	int err = 0;
>>>>>>> v4.14.187

	if (start >= MAX_BLKADDR(sbi) || range->len < sbi->blocksize)
		return -EINVAL;

<<<<<<< HEAD
	if (end < MAIN_BLKADDR(sbi))
		goto out;

	if (is_sbi_flag_set(sbi, SBI_NEED_FSCK)) {
		f2fs_warn(sbi, "Found FS corruption, run fsck to fix.");
		return -EFSCORRUPTED;
=======
	cpc.trimmed = 0;
	if (end <= MAIN_BLKADDR(sbi))
		goto out;

	if (is_sbi_flag_set(sbi, SBI_NEED_FSCK)) {
		f2fs_msg(sbi->sb, KERN_WARNING,
			"Found FS corruption, run fsck to fix.");
		err = -EFSCORRUPTED;
		goto out;
>>>>>>> v4.14.187
	}

	/* start/end segment number in main_area */
	start_segno = (start <= MAIN_BLKADDR(sbi)) ? 0 : GET_SEGNO(sbi, start);
	end_segno = (end >= MAX_BLKADDR(sbi)) ? MAIN_SEGS(sbi) - 1 :
						GET_SEGNO(sbi, end);
<<<<<<< HEAD
	if (need_align) {
		start_segno = rounddown(start_segno, sbi->segs_per_sec);
		end_segno = roundup(end_segno + 1, sbi->segs_per_sec) - 1;
	}

	cpc.reason = CP_DISCARD;
	cpc.trim_minlen = max_t(__u64, 1, F2FS_BYTES_TO_BLK(range->minlen));
	cpc.trim_start = start_segno;
	cpc.trim_end = end_segno;

	if (sbi->discard_blks == 0)
		goto out;

	down_write(&sbi->gc_lock);
	err = f2fs_write_checkpoint(sbi, &cpc);
	up_write(&sbi->gc_lock);
	if (err)
		goto out;

	/*
	 * We filed discard candidates, but actually we don't need to wait for
	 * all of them, since they'll be issued in idle time along with runtime
	 * discard option. User configuration looks like using runtime discard
	 * or periodic fstrim instead of it.
	 */
	if (f2fs_realtime_discard_enable(sbi))
		goto out;

	start_block = START_BLOCK(sbi, start_segno);
	end_block = START_BLOCK(sbi, end_segno + 1);

	__init_discard_policy(sbi, &dpolicy, DPOLICY_FSTRIM, cpc.trim_minlen);
	trimmed = __issue_discard_cmd_range(sbi, &dpolicy,
					start_block, end_block);

	trimmed += __wait_discard_cmd_range(sbi, &dpolicy,
					start_block, end_block);
out:
	if (!err)
		range->len = F2FS_BLK_TO_BYTES(trimmed);
=======
	cpc.reason = CP_DISCARD;
	cpc.trim_minlen = max_t(__u64, 1, F2FS_BYTES_TO_BLK(range->minlen));

	/* do checkpoint to issue discard commands safely */
	for (; start_segno <= end_segno; start_segno = cpc.trim_end + 1) {
		cpc.trim_start = start_segno;

		if (sbi->discard_blks == 0)
			break;
		else if (sbi->discard_blks < BATCHED_TRIM_BLOCKS(sbi))
			cpc.trim_end = end_segno;
		else
			cpc.trim_end = min_t(unsigned int,
				rounddown(start_segno +
				BATCHED_TRIM_SEGMENTS(sbi),
				sbi->segs_per_sec) - 1, end_segno);

		mutex_lock(&sbi->gc_mutex);
		err = write_checkpoint(sbi, &cpc);
		mutex_unlock(&sbi->gc_mutex);
		if (err)
			break;

		schedule();
	}
	/* It's time to issue all the filed discards */
	mark_discard_range_all(sbi);
	f2fs_wait_discard_bios(sbi, false);
out:
	range->len = F2FS_BLK_TO_BYTES(cpc.trimmed);
>>>>>>> v4.14.187
	return err;
}

static bool __has_curseg_space(struct f2fs_sb_info *sbi, int type)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	if (curseg->next_blkoff < sbi->blocks_per_seg)
		return true;
	return false;
}

<<<<<<< HEAD
int f2fs_rw_hint_to_seg_type(enum rw_hint hint)
{
	switch (hint) {
	case WRITE_LIFE_SHORT:
		return CURSEG_HOT_DATA;
	case WRITE_LIFE_EXTREME:
		return CURSEG_COLD_DATA;
	default:
		return CURSEG_WARM_DATA;
	}
}

/* This returns write hints for each segment type. This hints will be
 * passed down to block layer. There are mapping tables which depend on
 * the mount option 'whint_mode'.
 *
 * 1) whint_mode=off. F2FS only passes down WRITE_LIFE_NOT_SET.
 *
 * 2) whint_mode=user-based. F2FS tries to pass down hints given by users.
 *
 * User                  F2FS                     Block
 * ----                  ----                     -----
 *                       META                     WRITE_LIFE_NOT_SET
 *                       HOT_NODE                 "
 *                       WARM_NODE                "
 *                       COLD_NODE                "
 * ioctl(COLD)           COLD_DATA                WRITE_LIFE_EXTREME
 * extension list        "                        "
 *
 * -- buffered io
 * WRITE_LIFE_EXTREME    COLD_DATA                WRITE_LIFE_EXTREME
 * WRITE_LIFE_SHORT      HOT_DATA                 WRITE_LIFE_SHORT
 * WRITE_LIFE_NOT_SET    WARM_DATA                WRITE_LIFE_NOT_SET
 * WRITE_LIFE_NONE       "                        "
 * WRITE_LIFE_MEDIUM     "                        "
 * WRITE_LIFE_LONG       "                        "
 *
 * -- direct io
 * WRITE_LIFE_EXTREME    COLD_DATA                WRITE_LIFE_EXTREME
 * WRITE_LIFE_SHORT      HOT_DATA                 WRITE_LIFE_SHORT
 * WRITE_LIFE_NOT_SET    WARM_DATA                WRITE_LIFE_NOT_SET
 * WRITE_LIFE_NONE       "                        WRITE_LIFE_NONE
 * WRITE_LIFE_MEDIUM     "                        WRITE_LIFE_MEDIUM
 * WRITE_LIFE_LONG       "                        WRITE_LIFE_LONG
 *
 * 3) whint_mode=fs-based. F2FS passes down hints with its policy.
 *
 * User                  F2FS                     Block
 * ----                  ----                     -----
 *                       META                     WRITE_LIFE_MEDIUM;
 *                       HOT_NODE                 WRITE_LIFE_NOT_SET
 *                       WARM_NODE                "
 *                       COLD_NODE                WRITE_LIFE_NONE
 * ioctl(COLD)           COLD_DATA                WRITE_LIFE_EXTREME
 * extension list        "                        "
 *
 * -- buffered io
 * WRITE_LIFE_EXTREME    COLD_DATA                WRITE_LIFE_EXTREME
 * WRITE_LIFE_SHORT      HOT_DATA                 WRITE_LIFE_SHORT
 * WRITE_LIFE_NOT_SET    WARM_DATA                WRITE_LIFE_LONG
 * WRITE_LIFE_NONE       "                        "
 * WRITE_LIFE_MEDIUM     "                        "
 * WRITE_LIFE_LONG       "                        "
 *
 * -- direct io
 * WRITE_LIFE_EXTREME    COLD_DATA                WRITE_LIFE_EXTREME
 * WRITE_LIFE_SHORT      HOT_DATA                 WRITE_LIFE_SHORT
 * WRITE_LIFE_NOT_SET    WARM_DATA                WRITE_LIFE_NOT_SET
 * WRITE_LIFE_NONE       "                        WRITE_LIFE_NONE
 * WRITE_LIFE_MEDIUM     "                        WRITE_LIFE_MEDIUM
 * WRITE_LIFE_LONG       "                        WRITE_LIFE_LONG
 */

enum rw_hint f2fs_io_type_to_rw_hint(struct f2fs_sb_info *sbi,
				enum page_type type, enum temp_type temp)
{
	if (F2FS_OPTION(sbi).whint_mode == WHINT_MODE_USER) {
		if (type == DATA) {
			if (temp == WARM)
				return WRITE_LIFE_NOT_SET;
			else if (temp == HOT)
				return WRITE_LIFE_SHORT;
			else if (temp == COLD)
				return WRITE_LIFE_EXTREME;
		} else {
			return WRITE_LIFE_NOT_SET;
		}
	} else if (F2FS_OPTION(sbi).whint_mode == WHINT_MODE_FS) {
		if (type == DATA) {
			if (temp == WARM)
				return WRITE_LIFE_LONG;
			else if (temp == HOT)
				return WRITE_LIFE_SHORT;
			else if (temp == COLD)
				return WRITE_LIFE_EXTREME;
		} else if (type == NODE) {
			if (temp == WARM || temp == HOT)
				return WRITE_LIFE_NOT_SET;
			else if (temp == COLD)
				return WRITE_LIFE_NONE;
		} else if (type == META) {
			return WRITE_LIFE_MEDIUM;
		}
	}
	return WRITE_LIFE_NOT_SET;
}

=======
>>>>>>> v4.14.187
static int __get_segment_type_2(struct f2fs_io_info *fio)
{
	if (fio->type == DATA)
		return CURSEG_HOT_DATA;
	else
		return CURSEG_HOT_NODE;
}

static int __get_segment_type_4(struct f2fs_io_info *fio)
{
	if (fio->type == DATA) {
		struct inode *inode = fio->page->mapping->host;

		if (S_ISDIR(inode->i_mode))
			return CURSEG_HOT_DATA;
		else
			return CURSEG_COLD_DATA;
	} else {
		if (IS_DNODE(fio->page) && is_cold_node(fio->page))
			return CURSEG_WARM_NODE;
		else
			return CURSEG_COLD_NODE;
	}
}

static int __get_segment_type_6(struct f2fs_io_info *fio)
{
	if (fio->type == DATA) {
		struct inode *inode = fio->page->mapping->host;

<<<<<<< HEAD
		if (is_cold_data(fio->page) || file_is_cold(inode) ||
				f2fs_compressed_file(inode))
			return CURSEG_COLD_DATA;
		if (file_is_hot(inode) ||
				is_inode_flag_set(inode, FI_HOT_DATA) ||
				f2fs_is_atomic_file(inode) ||
				f2fs_is_volatile_file(inode))
			return CURSEG_HOT_DATA;
		return f2fs_rw_hint_to_seg_type(inode->i_write_hint);
=======
		if (is_cold_data(fio->page) || file_is_cold(inode))
			return CURSEG_COLD_DATA;
		if (is_inode_flag_set(inode, FI_HOT_DATA))
			return CURSEG_HOT_DATA;
		return CURSEG_WARM_DATA;
>>>>>>> v4.14.187
	} else {
		if (IS_DNODE(fio->page))
			return is_cold_node(fio->page) ? CURSEG_WARM_NODE :
						CURSEG_HOT_NODE;
		return CURSEG_COLD_NODE;
	}
}

static int __get_segment_type(struct f2fs_io_info *fio)
{
	int type = 0;

<<<<<<< HEAD
	switch (F2FS_OPTION(fio->sbi).active_logs) {
=======
	switch (fio->sbi->active_logs) {
>>>>>>> v4.14.187
	case 2:
		type = __get_segment_type_2(fio);
		break;
	case 4:
		type = __get_segment_type_4(fio);
		break;
	case 6:
		type = __get_segment_type_6(fio);
		break;
	default:
		f2fs_bug_on(fio->sbi, true);
	}

	if (IS_HOT(type))
		fio->temp = HOT;
	else if (IS_WARM(type))
		fio->temp = WARM;
	else
		fio->temp = COLD;
	return type;
}

<<<<<<< HEAD
void f2fs_allocate_data_block(struct f2fs_sb_info *sbi, struct page *page,
=======
void allocate_data_block(struct f2fs_sb_info *sbi, struct page *page,
>>>>>>> v4.14.187
		block_t old_blkaddr, block_t *new_blkaddr,
		struct f2fs_summary *sum, int type,
		struct f2fs_io_info *fio, bool add_list)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct curseg_info *curseg = CURSEG_I(sbi, type);
<<<<<<< HEAD
	bool put_pin_sem = false;

	if (type == CURSEG_COLD_DATA) {
		/* GC during CURSEG_COLD_DATA_PINNED allocation */
		if (down_read_trylock(&sbi->pin_sem)) {
			put_pin_sem = true;
		} else {
			type = CURSEG_WARM_DATA;
			curseg = CURSEG_I(sbi, type);
		}
	} else if (type == CURSEG_COLD_DATA_PINNED) {
		type = CURSEG_COLD_DATA;
	}

	/*
	 * We need to wait for node_write to avoid block allocation during
	 * checkpoint. This can only happen to quota writes which can cause
	 * the below discard race condition.
	 */
	if (IS_DATASEG(type))
		down_write(&sbi->node_write);

	down_read(&SM_I(sbi)->curseg_lock);

	mutex_lock(&curseg->curseg_mutex);
	down_write(&sit_i->sentry_lock);
=======

	mutex_lock(&curseg->curseg_mutex);
	mutex_lock(&sit_i->sentry_lock);
>>>>>>> v4.14.187

	*new_blkaddr = NEXT_FREE_BLKADDR(sbi, curseg);

	f2fs_wait_discard_bio(sbi, *new_blkaddr);

	/*
	 * __add_sum_entry should be resided under the curseg_mutex
	 * because, this function updates a summary entry in the
	 * current summary block.
	 */
	__add_sum_entry(sbi, type, sum);

	__refresh_next_blkoff(sbi, curseg);

	stat_inc_block_count(sbi, curseg);
<<<<<<< HEAD
	sbi->sec_stat.alloc_blk_count[curseg->alloc_type]++;
	/*
	 * SIT information should be updated before segment allocation,
	 * since SSR needs latest valid block information.
	 */
	update_sit_entry(sbi, *new_blkaddr, 1);
	if (GET_SEGNO(sbi, old_blkaddr) != NULL_SEGNO)
		update_sit_entry(sbi, old_blkaddr, -1);

	if (!__has_curseg_space(sbi, type))
		sit_i->s_ops->allocate_segment(sbi, type, false);

	/*
	 * segment dirty status should be updated after segment allocation,
	 * so we just need to update status only one time after previous
	 * segment being closed.
	 */
	locate_dirty_segment(sbi, GET_SEGNO(sbi, old_blkaddr));
	locate_dirty_segment(sbi, GET_SEGNO(sbi, *new_blkaddr));

	up_write(&sit_i->sentry_lock);
=======

	if (!__has_curseg_space(sbi, type))
		sit_i->s_ops->allocate_segment(sbi, type, false);
	/*
	 * SIT information should be updated after segment allocation,
	 * since we need to keep dirty segments precisely under SSR.
	 */
	refresh_sit_entry(sbi, old_blkaddr, *new_blkaddr);

	mutex_unlock(&sit_i->sentry_lock);
>>>>>>> v4.14.187

	if (page && IS_NODESEG(type)) {
		fill_node_footer_blkaddr(page, NEXT_FREE_BLKADDR(sbi, curseg));

		f2fs_inode_chksum_set(sbi, page);
	}

<<<<<<< HEAD
	if (F2FS_IO_ALIGNED(sbi))
		fio->retry = false;

=======
>>>>>>> v4.14.187
	if (add_list) {
		struct f2fs_bio_info *io;

		INIT_LIST_HEAD(&fio->list);
		fio->in_list = true;
		io = sbi->write_io[fio->type] + fio->temp;
		spin_lock(&io->io_lock);
		list_add_tail(&fio->list, &io->io_list);
		spin_unlock(&io->io_lock);
	}

	mutex_unlock(&curseg->curseg_mutex);
<<<<<<< HEAD

	up_read(&SM_I(sbi)->curseg_lock);

	if (IS_DATASEG(type))
		up_write(&sbi->node_write);

	if (put_pin_sem)
		up_read(&sbi->pin_sem);
}

static void update_device_state(struct f2fs_io_info *fio)
{
	struct f2fs_sb_info *sbi = fio->sbi;
	unsigned int devidx;

	if (!f2fs_is_multi_device(sbi))
		return;

	devidx = f2fs_target_device_index(sbi, fio->new_blkaddr);

	/* update device state for fsync */
	f2fs_set_dirty_device(sbi, fio->ino, devidx, FLUSH_INO);

	/* update device state for checkpoint */
	if (!f2fs_test_bit(devidx, (char *)&sbi->dirty_device)) {
		spin_lock(&sbi->dev_lock);
		f2fs_set_bit(devidx, (char *)&sbi->dirty_device);
		spin_unlock(&sbi->dev_lock);
	}
=======
>>>>>>> v4.14.187
}

static void do_write_page(struct f2fs_summary *sum, struct f2fs_io_info *fio)
{
	int type = __get_segment_type(fio);
<<<<<<< HEAD
	bool keep_order = (f2fs_lfs_mode(fio->sbi) && type == CURSEG_COLD_DATA);

	if (keep_order)
		down_read(&fio->sbi->io_order_lock);
reallocate:
	f2fs_allocate_data_block(fio->sbi, fio->page, fio->old_blkaddr,
			&fio->new_blkaddr, sum, type, fio, true);
	if (GET_SEGNO(fio->sbi, fio->old_blkaddr) != NULL_SEGNO)
		invalidate_mapping_pages(META_MAPPING(fio->sbi),
					fio->old_blkaddr, fio->old_blkaddr);

	/* writeout dirty page into bdev */
	f2fs_submit_page_write(fio);
	if (fio->retry) {
		fio->old_blkaddr = fio->new_blkaddr;
		goto reallocate;
	}

	update_device_state(fio);

	if (keep_order)
		up_read(&fio->sbi->io_order_lock);
}

void f2fs_do_write_meta_page(struct f2fs_sb_info *sbi, struct page *page,
=======
	int err;

reallocate:
	allocate_data_block(fio->sbi, fio->page, fio->old_blkaddr,
			&fio->new_blkaddr, sum, type, fio, true);

	/* writeout dirty page into bdev */
	err = f2fs_submit_page_write(fio);
	if (err == -EAGAIN) {
		fio->old_blkaddr = fio->new_blkaddr;
		goto reallocate;
	}
}

void write_meta_page(struct f2fs_sb_info *sbi, struct page *page,
>>>>>>> v4.14.187
					enum iostat_type io_type)
{
	struct f2fs_io_info fio = {
		.sbi = sbi,
		.type = META,
<<<<<<< HEAD
		.temp = HOT,
=======
>>>>>>> v4.14.187
		.op = REQ_OP_WRITE,
		.op_flags = REQ_SYNC | REQ_META | REQ_PRIO,
		.old_blkaddr = page->index,
		.new_blkaddr = page->index,
		.page = page,
		.encrypted_page = NULL,
		.in_list = false,
	};

<<<<<<< HEAD
	f2fs_cond_set_fua(&fio);

=======
>>>>>>> v4.14.187
	if (unlikely(page->index >= MAIN_BLKADDR(sbi)))
		fio.op_flags &= ~REQ_META;

	set_page_writeback(page);
<<<<<<< HEAD
	ClearPageError(page);
	f2fs_submit_page_write(&fio);

	stat_inc_meta_count(sbi, page->index);
	f2fs_update_iostat(sbi, io_type, F2FS_BLKSIZE);
}

void f2fs_do_write_node_page(unsigned int nid, struct f2fs_io_info *fio)
=======
	f2fs_submit_page_write(&fio);

	f2fs_update_iostat(sbi, io_type, F2FS_BLKSIZE);
}

void write_node_page(unsigned int nid, struct f2fs_io_info *fio)
>>>>>>> v4.14.187
{
	struct f2fs_summary sum;

	set_summary(&sum, nid, 0, 0);
	do_write_page(&sum, fio);

	f2fs_update_iostat(fio->sbi, fio->io_type, F2FS_BLKSIZE);
}

<<<<<<< HEAD
void f2fs_outplace_write_data(struct dnode_of_data *dn,
					struct f2fs_io_info *fio)
{
	struct f2fs_sb_info *sbi = fio->sbi;
	struct f2fs_summary sum;

	f2fs_bug_on(sbi, dn->data_blkaddr == NULL_ADDR);
	set_summary(&sum, dn->nid, dn->ofs_in_node, fio->version);
=======
void write_data_page(struct dnode_of_data *dn, struct f2fs_io_info *fio)
{
	struct f2fs_sb_info *sbi = fio->sbi;
	struct f2fs_summary sum;
	struct node_info ni;

	f2fs_bug_on(sbi, dn->data_blkaddr == NULL_ADDR);
	get_node_info(sbi, dn->nid, &ni);
	set_summary(&sum, dn->nid, dn->ofs_in_node, ni.version);
>>>>>>> v4.14.187
	do_write_page(&sum, fio);
	f2fs_update_data_blkaddr(dn, fio->new_blkaddr);

	f2fs_update_iostat(sbi, fio->io_type, F2FS_BLKSIZE);
}

<<<<<<< HEAD
int f2fs_inplace_write_data(struct f2fs_io_info *fio)
{
	int err;
	struct f2fs_sb_info *sbi = fio->sbi;
	unsigned int segno;

	fio->new_blkaddr = fio->old_blkaddr;
	/* i/o temperature is needed for passing down write hints */
	__get_segment_type(fio);

	segno = GET_SEGNO(sbi, fio->new_blkaddr);

	if (!IS_DATASEG(get_seg_entry(sbi, segno)->type)) {
		set_sbi_flag(sbi, SBI_NEED_FSCK);
		f2fs_warn(sbi, "%s: incorrect segment(%u) type, run fsck to fix.",
			  __func__, segno);
		return -EFSCORRUPTED;
	}

	stat_inc_inplace_blocks(fio->sbi);
	atomic64_inc(&(sbi->sec_stat.inplace_count));

	if (fio->bio && !(SM_I(sbi)->ipu_policy & (1 << F2FS_IPU_NOCACHE)))
		err = f2fs_merge_page_bio(fio);
	else
		err = f2fs_submit_page_bio(fio);
	if (!err) {
		update_device_state(fio);
		f2fs_update_iostat(fio->sbi, fio->io_type, F2FS_BLKSIZE);
	}
=======
int rewrite_data_page(struct f2fs_io_info *fio)
{
	int err;

	fio->new_blkaddr = fio->old_blkaddr;
	stat_inc_inplace_blocks(fio->sbi);

	err = f2fs_submit_page_bio(fio);

	f2fs_update_iostat(fio->sbi, fio->io_type, F2FS_BLKSIZE);
>>>>>>> v4.14.187

	return err;
}

<<<<<<< HEAD
static inline int __f2fs_get_curseg(struct f2fs_sb_info *sbi,
						unsigned int segno)
{
	int i;

	for (i = CURSEG_HOT_DATA; i < NO_CHECK_TYPE; i++) {
		if (CURSEG_I(sbi, i)->segno == segno)
			break;
	}
	return i;
}

void f2fs_do_replace_block(struct f2fs_sb_info *sbi, struct f2fs_summary *sum,
=======
void __f2fs_replace_block(struct f2fs_sb_info *sbi, struct f2fs_summary *sum,
>>>>>>> v4.14.187
				block_t old_blkaddr, block_t new_blkaddr,
				bool recover_curseg, bool recover_newaddr)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct curseg_info *curseg;
	unsigned int segno, old_cursegno;
	struct seg_entry *se;
	int type;
	unsigned short old_blkoff;

	segno = GET_SEGNO(sbi, new_blkaddr);
	se = get_seg_entry(sbi, segno);
	type = se->type;

<<<<<<< HEAD
	down_write(&SM_I(sbi)->curseg_lock);

=======
>>>>>>> v4.14.187
	if (!recover_curseg) {
		/* for recovery flow */
		if (se->valid_blocks == 0 && !IS_CURSEG(sbi, segno)) {
			if (old_blkaddr == NULL_ADDR)
				type = CURSEG_COLD_DATA;
			else
				type = CURSEG_WARM_DATA;
		}
	} else {
<<<<<<< HEAD
		if (IS_CURSEG(sbi, segno)) {
			/* se->type is volatile as SSR allocation */
			type = __f2fs_get_curseg(sbi, segno);
			f2fs_bug_on(sbi, type == NO_CHECK_TYPE);
		} else {
			type = CURSEG_WARM_DATA;
		}
	}

	f2fs_bug_on(sbi, !IS_DATASEG(type));
	curseg = CURSEG_I(sbi, type);

	mutex_lock(&curseg->curseg_mutex);
	down_write(&sit_i->sentry_lock);
=======
		if (!IS_CURSEG(sbi, segno))
			type = CURSEG_WARM_DATA;
	}

	curseg = CURSEG_I(sbi, type);

	mutex_lock(&curseg->curseg_mutex);
	mutex_lock(&sit_i->sentry_lock);
>>>>>>> v4.14.187

	old_cursegno = curseg->segno;
	old_blkoff = curseg->next_blkoff;

	/* change the current segment */
	if (segno != curseg->segno) {
		curseg->next_segno = segno;
		change_curseg(sbi, type);
	}

	curseg->next_blkoff = GET_BLKOFF_FROM_SEG0(sbi, new_blkaddr);
	__add_sum_entry(sbi, type, sum);

	if (!recover_curseg || recover_newaddr)
		update_sit_entry(sbi, new_blkaddr, 1);
<<<<<<< HEAD
	if (GET_SEGNO(sbi, old_blkaddr) != NULL_SEGNO) {
		invalidate_mapping_pages(META_MAPPING(sbi),
					old_blkaddr, old_blkaddr);
		update_sit_entry(sbi, old_blkaddr, -1);
	}
=======
	if (GET_SEGNO(sbi, old_blkaddr) != NULL_SEGNO)
		update_sit_entry(sbi, old_blkaddr, -1);
>>>>>>> v4.14.187

	locate_dirty_segment(sbi, GET_SEGNO(sbi, old_blkaddr));
	locate_dirty_segment(sbi, GET_SEGNO(sbi, new_blkaddr));

	locate_dirty_segment(sbi, old_cursegno);

	if (recover_curseg) {
		if (old_cursegno != curseg->segno) {
			curseg->next_segno = old_cursegno;
			change_curseg(sbi, type);
		}
		curseg->next_blkoff = old_blkoff;
	}

<<<<<<< HEAD
	up_write(&sit_i->sentry_lock);
	mutex_unlock(&curseg->curseg_mutex);
	up_write(&SM_I(sbi)->curseg_lock);
=======
	mutex_unlock(&sit_i->sentry_lock);
	mutex_unlock(&curseg->curseg_mutex);
>>>>>>> v4.14.187
}

void f2fs_replace_block(struct f2fs_sb_info *sbi, struct dnode_of_data *dn,
				block_t old_addr, block_t new_addr,
				unsigned char version, bool recover_curseg,
				bool recover_newaddr)
{
	struct f2fs_summary sum;

	set_summary(&sum, dn->nid, dn->ofs_in_node, version);

<<<<<<< HEAD
	f2fs_do_replace_block(sbi, &sum, old_addr, new_addr,
=======
	__f2fs_replace_block(sbi, &sum, old_addr, new_addr,
>>>>>>> v4.14.187
					recover_curseg, recover_newaddr);

	f2fs_update_data_blkaddr(dn, new_addr);
}

void f2fs_wait_on_page_writeback(struct page *page,
<<<<<<< HEAD
				enum page_type type, bool ordered, bool locked)
=======
				enum page_type type, bool ordered)
>>>>>>> v4.14.187
{
	if (PageWriteback(page)) {
		struct f2fs_sb_info *sbi = F2FS_P_SB(page);

<<<<<<< HEAD
		/* submit cached LFS IO */
		f2fs_submit_merged_write_cond(sbi, NULL, page, 0, type);
		/* sbumit cached IPU IO */
		f2fs_submit_merged_ipu_write(sbi, NULL, page);
		if (ordered) {
			wait_on_page_writeback(page);
			f2fs_bug_on(sbi, locked && PageWriteback(page));
		} else {
			wait_for_stable_page(page);
		}
	}
}

void f2fs_wait_on_block_writeback(struct inode *inode, block_t blkaddr)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct page *cpage;

	if (!f2fs_post_read_required(inode))
		return;

	if (!__is_valid_data_blkaddr(blkaddr))
=======
		f2fs_submit_merged_write_cond(sbi, page->mapping->host,
						0, page->index, type);
		if (ordered)
			wait_on_page_writeback(page);
		else
			wait_for_stable_page(page);
	}
}

void f2fs_wait_on_block_writeback(struct f2fs_sb_info *sbi, block_t blkaddr)
{
	struct page *cpage;

	if (!is_valid_data_blkaddr(sbi, blkaddr))
>>>>>>> v4.14.187
		return;

	cpage = find_lock_page(META_MAPPING(sbi), blkaddr);
	if (cpage) {
<<<<<<< HEAD
		f2fs_wait_on_page_writeback(cpage, DATA, true, true);
=======
		f2fs_wait_on_page_writeback(cpage, DATA, true);
>>>>>>> v4.14.187
		f2fs_put_page(cpage, 1);
	}
}

<<<<<<< HEAD
void f2fs_wait_on_block_writeback_range(struct inode *inode, block_t blkaddr,
								block_t len)
{
	block_t i;

	for (i = 0; i < len; i++)
		f2fs_wait_on_block_writeback(inode, blkaddr + i);
}

=======
>>>>>>> v4.14.187
static int read_compacted_summaries(struct f2fs_sb_info *sbi)
{
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	struct curseg_info *seg_i;
	unsigned char *kaddr;
	struct page *page;
	block_t start;
	int i, j, offset;

	start = start_sum_block(sbi);

<<<<<<< HEAD
	page = f2fs_get_meta_page(sbi, start++);
	if (IS_ERR(page))
		return PTR_ERR(page);
=======
	page = get_meta_page(sbi, start++);
>>>>>>> v4.14.187
	kaddr = (unsigned char *)page_address(page);

	/* Step 1: restore nat cache */
	seg_i = CURSEG_I(sbi, CURSEG_HOT_DATA);
	memcpy(seg_i->journal, kaddr, SUM_JOURNAL_SIZE);

	/* Step 2: restore sit cache */
	seg_i = CURSEG_I(sbi, CURSEG_COLD_DATA);
	memcpy(seg_i->journal, kaddr + SUM_JOURNAL_SIZE, SUM_JOURNAL_SIZE);
	offset = 2 * SUM_JOURNAL_SIZE;

	/* Step 3: restore summary entries */
	for (i = CURSEG_HOT_DATA; i <= CURSEG_COLD_DATA; i++) {
		unsigned short blk_off;
		unsigned int segno;

		seg_i = CURSEG_I(sbi, i);
		segno = le32_to_cpu(ckpt->cur_data_segno[i]);
		blk_off = le16_to_cpu(ckpt->cur_data_blkoff[i]);
		seg_i->next_segno = segno;
		reset_curseg(sbi, i, 0);
		seg_i->alloc_type = ckpt->alloc_type[i];
		seg_i->next_blkoff = blk_off;

		if (seg_i->alloc_type == SSR)
			blk_off = sbi->blocks_per_seg;

		for (j = 0; j < blk_off; j++) {
			struct f2fs_summary *s;
			s = (struct f2fs_summary *)(kaddr + offset);
			seg_i->sum_blk->entries[j] = *s;
			offset += SUMMARY_SIZE;
			if (offset + SUMMARY_SIZE <= PAGE_SIZE -
						SUM_FOOTER_SIZE)
				continue;

			f2fs_put_page(page, 1);
			page = NULL;

<<<<<<< HEAD
			page = f2fs_get_meta_page(sbi, start++);
			if (IS_ERR(page))
				return PTR_ERR(page);
=======
			page = get_meta_page(sbi, start++);
>>>>>>> v4.14.187
			kaddr = (unsigned char *)page_address(page);
			offset = 0;
		}
	}
	f2fs_put_page(page, 1);
	return 0;
}

static int read_normal_summaries(struct f2fs_sb_info *sbi, int type)
{
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	struct f2fs_summary_block *sum;
	struct curseg_info *curseg;
	struct page *new;
	unsigned short blk_off;
	unsigned int segno = 0;
	block_t blk_addr = 0;
<<<<<<< HEAD
	int err = 0;
=======
>>>>>>> v4.14.187

	/* get segment number and block addr */
	if (IS_DATASEG(type)) {
		segno = le32_to_cpu(ckpt->cur_data_segno[type]);
		blk_off = le16_to_cpu(ckpt->cur_data_blkoff[type -
							CURSEG_HOT_DATA]);
		if (__exist_node_summaries(sbi))
			blk_addr = sum_blk_addr(sbi, NR_CURSEG_TYPE, type);
		else
			blk_addr = sum_blk_addr(sbi, NR_CURSEG_DATA_TYPE, type);
	} else {
		segno = le32_to_cpu(ckpt->cur_node_segno[type -
							CURSEG_HOT_NODE]);
		blk_off = le16_to_cpu(ckpt->cur_node_blkoff[type -
							CURSEG_HOT_NODE]);
		if (__exist_node_summaries(sbi))
			blk_addr = sum_blk_addr(sbi, NR_CURSEG_NODE_TYPE,
							type - CURSEG_HOT_NODE);
		else
			blk_addr = GET_SUM_BLOCK(sbi, segno);
	}

<<<<<<< HEAD
	new = f2fs_get_meta_page(sbi, blk_addr);
	if (IS_ERR(new))
		return PTR_ERR(new);
=======
	new = get_meta_page(sbi, blk_addr);
>>>>>>> v4.14.187
	sum = (struct f2fs_summary_block *)page_address(new);

	if (IS_NODESEG(type)) {
		if (__exist_node_summaries(sbi)) {
			struct f2fs_summary *ns = &sum->entries[0];
			int i;
			for (i = 0; i < sbi->blocks_per_seg; i++, ns++) {
				ns->version = 0;
				ns->ofs_in_node = 0;
			}
		} else {
<<<<<<< HEAD
			err = f2fs_restore_node_summary(sbi, segno, sum);
			if (err)
				goto out;
=======
			int err;

			err = restore_node_summary(sbi, segno, sum);
			if (err) {
				f2fs_put_page(new, 1);
				return err;
			}
>>>>>>> v4.14.187
		}
	}

	/* set uncompleted segment to curseg */
	curseg = CURSEG_I(sbi, type);
	mutex_lock(&curseg->curseg_mutex);

	/* update journal info */
	down_write(&curseg->journal_rwsem);
	memcpy(curseg->journal, &sum->journal, SUM_JOURNAL_SIZE);
	up_write(&curseg->journal_rwsem);

	memcpy(curseg->sum_blk->entries, sum->entries, SUM_ENTRY_SIZE);
	memcpy(&curseg->sum_blk->footer, &sum->footer, SUM_FOOTER_SIZE);
	curseg->next_segno = segno;
	reset_curseg(sbi, type, 0);
	curseg->alloc_type = ckpt->alloc_type[type];
	curseg->next_blkoff = blk_off;
	mutex_unlock(&curseg->curseg_mutex);
<<<<<<< HEAD
out:
	f2fs_put_page(new, 1);
	return err;
=======
	f2fs_put_page(new, 1);
	return 0;
>>>>>>> v4.14.187
}

static int restore_curseg_summaries(struct f2fs_sb_info *sbi)
{
	struct f2fs_journal *sit_j = CURSEG_I(sbi, CURSEG_COLD_DATA)->journal;
	struct f2fs_journal *nat_j = CURSEG_I(sbi, CURSEG_HOT_DATA)->journal;
	int type = CURSEG_HOT_DATA;
	int err;

	if (is_set_ckpt_flags(sbi, CP_COMPACT_SUM_FLAG)) {
<<<<<<< HEAD
		int npages = f2fs_npages_for_summary_flush(sbi, true);

		if (npages >= 2)
			f2fs_ra_meta_pages(sbi, start_sum_block(sbi), npages,
							META_CP, true);

		/* restore for compacted data summary */
		err = read_compacted_summaries(sbi);
		if (err)
			return err;
=======
		int npages = npages_for_summary_flush(sbi, true);

		if (npages >= 2)
			ra_meta_pages(sbi, start_sum_block(sbi), npages,
							META_CP, true);

		/* restore for compacted data summary */
		if (read_compacted_summaries(sbi))
			return -EINVAL;
>>>>>>> v4.14.187
		type = CURSEG_HOT_NODE;
	}

	if (__exist_node_summaries(sbi))
<<<<<<< HEAD
		f2fs_ra_meta_pages(sbi, sum_blk_addr(sbi, NR_CURSEG_TYPE, type),
=======
		ra_meta_pages(sbi, sum_blk_addr(sbi, NR_CURSEG_TYPE, type),
>>>>>>> v4.14.187
					NR_CURSEG_TYPE - type, META_CP, true);

	for (; type <= CURSEG_COLD_NODE; type++) {
		err = read_normal_summaries(sbi, type);
		if (err)
			return err;
	}

	/* sanity check for summary blocks */
	if (nats_in_cursum(nat_j) > NAT_JOURNAL_ENTRIES ||
<<<<<<< HEAD
			sits_in_cursum(sit_j) > SIT_JOURNAL_ENTRIES) {
		f2fs_err(sbi, "invalid journal entries nats %u sits %u\n",
			 nats_in_cursum(nat_j), sits_in_cursum(sit_j));
		return -EINVAL;
	}
=======
			sits_in_cursum(sit_j) > SIT_JOURNAL_ENTRIES)
		return -EINVAL;
>>>>>>> v4.14.187

	return 0;
}

static void write_compacted_summaries(struct f2fs_sb_info *sbi, block_t blkaddr)
{
	struct page *page;
	unsigned char *kaddr;
	struct f2fs_summary *summary;
	struct curseg_info *seg_i;
	int written_size = 0;
	int i, j;

<<<<<<< HEAD
	page = f2fs_grab_meta_page(sbi, blkaddr++);
	kaddr = (unsigned char *)page_address(page);
	memset(kaddr, 0, PAGE_SIZE);
=======
	page = grab_meta_page(sbi, blkaddr++);
	kaddr = (unsigned char *)page_address(page);
>>>>>>> v4.14.187

	/* Step 1: write nat cache */
	seg_i = CURSEG_I(sbi, CURSEG_HOT_DATA);
	memcpy(kaddr, seg_i->journal, SUM_JOURNAL_SIZE);
	written_size += SUM_JOURNAL_SIZE;

	/* Step 2: write sit cache */
	seg_i = CURSEG_I(sbi, CURSEG_COLD_DATA);
	memcpy(kaddr + written_size, seg_i->journal, SUM_JOURNAL_SIZE);
	written_size += SUM_JOURNAL_SIZE;

	/* Step 3: write summary entries */
	for (i = CURSEG_HOT_DATA; i <= CURSEG_COLD_DATA; i++) {
		unsigned short blkoff;
		seg_i = CURSEG_I(sbi, i);
		if (sbi->ckpt->alloc_type[i] == SSR)
			blkoff = sbi->blocks_per_seg;
		else
			blkoff = curseg_blkoff(sbi, i);

		for (j = 0; j < blkoff; j++) {
			if (!page) {
<<<<<<< HEAD
				page = f2fs_grab_meta_page(sbi, blkaddr++);
				kaddr = (unsigned char *)page_address(page);
				memset(kaddr, 0, PAGE_SIZE);
=======
				page = grab_meta_page(sbi, blkaddr++);
				kaddr = (unsigned char *)page_address(page);
>>>>>>> v4.14.187
				written_size = 0;
			}
			summary = (struct f2fs_summary *)(kaddr + written_size);
			*summary = seg_i->sum_blk->entries[j];
			written_size += SUMMARY_SIZE;

			if (written_size + SUMMARY_SIZE <= PAGE_SIZE -
							SUM_FOOTER_SIZE)
				continue;

			set_page_dirty(page);
			f2fs_put_page(page, 1);
			page = NULL;
		}
	}
	if (page) {
		set_page_dirty(page);
		f2fs_put_page(page, 1);
	}
}

static void write_normal_summaries(struct f2fs_sb_info *sbi,
					block_t blkaddr, int type)
{
	int i, end;
	if (IS_DATASEG(type))
		end = type + NR_CURSEG_DATA_TYPE;
	else
		end = type + NR_CURSEG_NODE_TYPE;

	for (i = type; i < end; i++)
		write_current_sum_page(sbi, i, blkaddr + (i - type));
}

<<<<<<< HEAD
void f2fs_write_data_summaries(struct f2fs_sb_info *sbi, block_t start_blk)
=======
void write_data_summaries(struct f2fs_sb_info *sbi, block_t start_blk)
>>>>>>> v4.14.187
{
	if (is_set_ckpt_flags(sbi, CP_COMPACT_SUM_FLAG))
		write_compacted_summaries(sbi, start_blk);
	else
		write_normal_summaries(sbi, start_blk, CURSEG_HOT_DATA);
}

<<<<<<< HEAD
void f2fs_write_node_summaries(struct f2fs_sb_info *sbi, block_t start_blk)
=======
void write_node_summaries(struct f2fs_sb_info *sbi, block_t start_blk)
>>>>>>> v4.14.187
{
	write_normal_summaries(sbi, start_blk, CURSEG_HOT_NODE);
}

<<<<<<< HEAD
int f2fs_lookup_journal_in_cursum(struct f2fs_journal *journal, int type,
=======
int lookup_journal_in_cursum(struct f2fs_journal *journal, int type,
>>>>>>> v4.14.187
					unsigned int val, int alloc)
{
	int i;

	if (type == NAT_JOURNAL) {
		for (i = 0; i < nats_in_cursum(journal); i++) {
			if (le32_to_cpu(nid_in_journal(journal, i)) == val)
				return i;
		}
		if (alloc && __has_cursum_space(journal, 1, NAT_JOURNAL))
			return update_nats_in_cursum(journal, 1);
	} else if (type == SIT_JOURNAL) {
		for (i = 0; i < sits_in_cursum(journal); i++)
			if (le32_to_cpu(segno_in_journal(journal, i)) == val)
				return i;
		if (alloc && __has_cursum_space(journal, 1, SIT_JOURNAL))
			return update_sits_in_cursum(journal, 1);
	}
	return -1;
}

static struct page *get_current_sit_page(struct f2fs_sb_info *sbi,
					unsigned int segno)
{
<<<<<<< HEAD
	return f2fs_get_meta_page_nofail(sbi, current_sit_addr(sbi, segno));
=======
	return get_meta_page(sbi, current_sit_addr(sbi, segno));
>>>>>>> v4.14.187
}

static struct page *get_next_sit_page(struct f2fs_sb_info *sbi,
					unsigned int start)
{
	struct sit_info *sit_i = SIT_I(sbi);
<<<<<<< HEAD
	struct page *page;
	pgoff_t src_off, dst_off;
=======
	struct page *src_page, *dst_page;
	pgoff_t src_off, dst_off;
	void *src_addr, *dst_addr;
>>>>>>> v4.14.187

	src_off = current_sit_addr(sbi, start);
	dst_off = next_sit_addr(sbi, src_off);

<<<<<<< HEAD
	page = f2fs_grab_meta_page(sbi, dst_off);
	seg_info_to_sit_page(sbi, page, start);

	set_page_dirty(page);
	set_to_next_sit(sit_i, start);

	return page;
=======
	/* get current sit block page without lock */
	src_page = get_meta_page(sbi, src_off);
	dst_page = grab_meta_page(sbi, dst_off);
	f2fs_bug_on(sbi, PageDirty(src_page));

	src_addr = page_address(src_page);
	dst_addr = page_address(dst_page);
	memcpy(dst_addr, src_addr, PAGE_SIZE);

	set_page_dirty(dst_page);
	f2fs_put_page(src_page, 1);

	set_to_next_sit(sit_i, start);

	return dst_page;
>>>>>>> v4.14.187
}

static struct sit_entry_set *grab_sit_entry_set(void)
{
	struct sit_entry_set *ses =
			f2fs_kmem_cache_alloc(sit_entry_set_slab, GFP_NOFS);

	ses->entry_cnt = 0;
	INIT_LIST_HEAD(&ses->set_list);
	return ses;
}

static void release_sit_entry_set(struct sit_entry_set *ses)
{
	list_del(&ses->set_list);
	kmem_cache_free(sit_entry_set_slab, ses);
}

static void adjust_sit_entry_set(struct sit_entry_set *ses,
						struct list_head *head)
{
	struct sit_entry_set *next = ses;

	if (list_is_last(&ses->set_list, head))
		return;

	list_for_each_entry_continue(next, head, set_list)
		if (ses->entry_cnt <= next->entry_cnt)
			break;

	list_move_tail(&ses->set_list, &next->set_list);
}

static void add_sit_entry(unsigned int segno, struct list_head *head)
{
	struct sit_entry_set *ses;
	unsigned int start_segno = START_SEGNO(segno);

	list_for_each_entry(ses, head, set_list) {
		if (ses->start_segno == start_segno) {
			ses->entry_cnt++;
			adjust_sit_entry_set(ses, head);
			return;
		}
	}

	ses = grab_sit_entry_set();

	ses->start_segno = start_segno;
	ses->entry_cnt++;
	list_add(&ses->set_list, head);
}

static void add_sits_in_set(struct f2fs_sb_info *sbi)
{
	struct f2fs_sm_info *sm_info = SM_I(sbi);
	struct list_head *set_list = &sm_info->sit_entry_set;
	unsigned long *bitmap = SIT_I(sbi)->dirty_sentries_bitmap;
	unsigned int segno;

	for_each_set_bit(segno, bitmap, MAIN_SEGS(sbi))
		add_sit_entry(segno, set_list);
}

static void remove_sits_in_journal(struct f2fs_sb_info *sbi)
{
	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_COLD_DATA);
	struct f2fs_journal *journal = curseg->journal;
	int i;

	down_write(&curseg->journal_rwsem);
	for (i = 0; i < sits_in_cursum(journal); i++) {
		unsigned int segno;
		bool dirtied;

		segno = le32_to_cpu(segno_in_journal(journal, i));
		dirtied = __mark_sit_entry_dirty(sbi, segno);

		if (!dirtied)
			add_sit_entry(segno, &SM_I(sbi)->sit_entry_set);
	}
	update_sits_in_cursum(journal, -i);
	up_write(&curseg->journal_rwsem);
}

/*
 * CP calls this function, which flushes SIT entries including sit_journal,
 * and moves prefree segs to free segs.
 */
<<<<<<< HEAD
void f2fs_flush_sit_entries(struct f2fs_sb_info *sbi, struct cp_control *cpc)
=======
void flush_sit_entries(struct f2fs_sb_info *sbi, struct cp_control *cpc)
>>>>>>> v4.14.187
{
	struct sit_info *sit_i = SIT_I(sbi);
	unsigned long *bitmap = sit_i->dirty_sentries_bitmap;
	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_COLD_DATA);
	struct f2fs_journal *journal = curseg->journal;
	struct sit_entry_set *ses, *tmp;
	struct list_head *head = &SM_I(sbi)->sit_entry_set;
<<<<<<< HEAD
	bool to_journal = !is_sbi_flag_set(sbi, SBI_IS_RESIZEFS);
	struct seg_entry *se;

	down_write(&sit_i->sentry_lock);
=======
	bool to_journal = true;
	struct seg_entry *se;

	mutex_lock(&sit_i->sentry_lock);
>>>>>>> v4.14.187

	if (!sit_i->dirty_sentries)
		goto out;

	/*
	 * add and account sit entries of dirty bitmap in sit entry
	 * set temporarily
	 */
	add_sits_in_set(sbi);

	/*
	 * if there are no enough space in journal to store dirty sit
	 * entries, remove all entries from journal and add and account
	 * them in sit entry set.
	 */
<<<<<<< HEAD
	if (!__has_cursum_space(journal, sit_i->dirty_sentries, SIT_JOURNAL) ||
								!to_journal)
=======
	if (!__has_cursum_space(journal, sit_i->dirty_sentries, SIT_JOURNAL))
>>>>>>> v4.14.187
		remove_sits_in_journal(sbi);

	/*
	 * there are two steps to flush sit entries:
	 * #1, flush sit entries to journal in current cold data summary block.
	 * #2, flush sit entries to sit page.
	 */
	list_for_each_entry_safe(ses, tmp, head, set_list) {
		struct page *page = NULL;
		struct f2fs_sit_block *raw_sit = NULL;
		unsigned int start_segno = ses->start_segno;
		unsigned int end = min(start_segno + SIT_ENTRY_PER_BLOCK,
						(unsigned long)MAIN_SEGS(sbi));
		unsigned int segno = start_segno;
<<<<<<< HEAD
		int err = 0;
=======
>>>>>>> v4.14.187

		if (to_journal &&
			!__has_cursum_space(journal, ses->entry_cnt, SIT_JOURNAL))
			to_journal = false;

		if (to_journal) {
			down_write(&curseg->journal_rwsem);
		} else {
			page = get_next_sit_page(sbi, start_segno);
			raw_sit = page_address(page);
		}

		/* flush dirty sit entries in region of current sit set */
		for_each_set_bit_from(segno, bitmap, end) {
			int offset, sit_offset;

			se = get_seg_entry(sbi, segno);
<<<<<<< HEAD
#ifdef CONFIG_F2FS_CHECK_FS
			if (memcmp(se->cur_valid_map, se->cur_valid_map_mir,
						SIT_VBLOCK_MAP_SIZE))
				f2fs_bug_on(sbi, 1);
#endif
=======
>>>>>>> v4.14.187

			/* add discard candidates */
			if (!(cpc->reason & CP_DISCARD)) {
				cpc->trim_start = segno;
				add_discard_addrs(sbi, cpc, false);
			}

			if (to_journal) {
<<<<<<< HEAD
				offset = f2fs_lookup_journal_in_cursum(journal,
=======
				offset = lookup_journal_in_cursum(journal,
>>>>>>> v4.14.187
							SIT_JOURNAL, segno, 1);
				f2fs_bug_on(sbi, offset < 0);
				segno_in_journal(journal, offset) =
							cpu_to_le32(segno);
				seg_info_to_raw_sit(se,
					&sit_in_journal(journal, offset));
<<<<<<< HEAD
				err = check_block_count(sbi, segno,
					&sit_in_journal(journal, offset));
=======
>>>>>>> v4.14.187
			} else {
				sit_offset = SIT_ENTRY_OFFSET(sit_i, segno);
				seg_info_to_raw_sit(se,
						&raw_sit->entries[sit_offset]);
<<<<<<< HEAD
				err = check_block_count(sbi, segno,
						&raw_sit->entries[sit_offset]);
			}
			f2fs_bug_on(sbi, err);
=======
			}

>>>>>>> v4.14.187
			__clear_bit(segno, bitmap);
			sit_i->dirty_sentries--;
			ses->entry_cnt--;
		}

		if (to_journal)
			up_write(&curseg->journal_rwsem);
		else
			f2fs_put_page(page, 1);

		f2fs_bug_on(sbi, ses->entry_cnt);
		release_sit_entry_set(ses);
	}

	f2fs_bug_on(sbi, !list_empty(head));
	f2fs_bug_on(sbi, sit_i->dirty_sentries);
out:
	if (cpc->reason & CP_DISCARD) {
		__u64 trim_start = cpc->trim_start;

		for (; cpc->trim_start <= cpc->trim_end; cpc->trim_start++)
			add_discard_addrs(sbi, cpc, false);

		cpc->trim_start = trim_start;
	}
<<<<<<< HEAD
	up_write(&sit_i->sentry_lock);
=======
	mutex_unlock(&sit_i->sentry_lock);
>>>>>>> v4.14.187

	set_prefree_as_free_segments(sbi);
}

static int build_sit_info(struct f2fs_sb_info *sbi)
{
	struct f2fs_super_block *raw_super = F2FS_RAW_SUPER(sbi);
	struct sit_info *sit_i;
	unsigned int sit_segs, start;
<<<<<<< HEAD
	char *src_bitmap, *bitmap;
	unsigned int bitmap_size, main_bitmap_size, sit_bitmap_size;

	/* allocate memory for SIT information */
	sit_i = f2fs_kzalloc(sbi, sizeof(struct sit_info), GFP_KERNEL);
=======
	char *src_bitmap;
	unsigned int bitmap_size;

	/* allocate memory for SIT information */
	sit_i = kzalloc(sizeof(struct sit_info), GFP_KERNEL);
>>>>>>> v4.14.187
	if (!sit_i)
		return -ENOMEM;

	SM_I(sbi)->sit_info = sit_i;

<<<<<<< HEAD
	sit_i->sentries =
		f2fs_kvzalloc(sbi, array_size(sizeof(struct seg_entry),
					      MAIN_SEGS(sbi)),
			      GFP_KERNEL);
	if (!sit_i->sentries)
		return -ENOMEM;

	main_bitmap_size = f2fs_bitmap_size(MAIN_SEGS(sbi));
	sit_i->dirty_sentries_bitmap = f2fs_kvzalloc(sbi, main_bitmap_size,
								GFP_KERNEL);
	if (!sit_i->dirty_sentries_bitmap)
		return -ENOMEM;

#ifdef CONFIG_F2FS_CHECK_FS
	bitmap_size = MAIN_SEGS(sbi) * SIT_VBLOCK_MAP_SIZE * 4;
#else
	bitmap_size = MAIN_SEGS(sbi) * SIT_VBLOCK_MAP_SIZE * 3;
#endif
	sit_i->bitmap = f2fs_kvzalloc(sbi, bitmap_size, GFP_KERNEL);
	if (!sit_i->bitmap)
		return -ENOMEM;

	bitmap = sit_i->bitmap;

	for (start = 0; start < MAIN_SEGS(sbi); start++) {
		sit_i->sentries[start].cur_valid_map = bitmap;
		bitmap += SIT_VBLOCK_MAP_SIZE;

		sit_i->sentries[start].ckpt_valid_map = bitmap;
		bitmap += SIT_VBLOCK_MAP_SIZE;

#ifdef CONFIG_F2FS_CHECK_FS
		sit_i->sentries[start].cur_valid_map_mir = bitmap;
		bitmap += SIT_VBLOCK_MAP_SIZE;
#endif

		sit_i->sentries[start].discard_map = bitmap;
		bitmap += SIT_VBLOCK_MAP_SIZE;
	}

	sit_i->tmp_map = f2fs_kzalloc(sbi, SIT_VBLOCK_MAP_SIZE, GFP_KERNEL);
	if (!sit_i->tmp_map)
		return -ENOMEM;

	if (__is_large_section(sbi)) {
		sit_i->sec_entries =
			f2fs_kvzalloc(sbi, array_size(sizeof(struct sec_entry),
						      MAIN_SECS(sbi)),
				      GFP_KERNEL);
=======
	sit_i->sentries = kvzalloc(MAIN_SEGS(sbi) *
					sizeof(struct seg_entry), GFP_KERNEL);
	if (!sit_i->sentries)
		return -ENOMEM;

	bitmap_size = f2fs_bitmap_size(MAIN_SEGS(sbi));
	sit_i->dirty_sentries_bitmap = kvzalloc(bitmap_size, GFP_KERNEL);
	if (!sit_i->dirty_sentries_bitmap)
		return -ENOMEM;

	for (start = 0; start < MAIN_SEGS(sbi); start++) {
		sit_i->sentries[start].cur_valid_map
			= kzalloc(SIT_VBLOCK_MAP_SIZE, GFP_KERNEL);
		sit_i->sentries[start].ckpt_valid_map
			= kzalloc(SIT_VBLOCK_MAP_SIZE, GFP_KERNEL);
		if (!sit_i->sentries[start].cur_valid_map ||
				!sit_i->sentries[start].ckpt_valid_map)
			return -ENOMEM;

#ifdef CONFIG_F2FS_CHECK_FS
		sit_i->sentries[start].cur_valid_map_mir
			= kzalloc(SIT_VBLOCK_MAP_SIZE, GFP_KERNEL);
		if (!sit_i->sentries[start].cur_valid_map_mir)
			return -ENOMEM;
#endif

		if (f2fs_discard_en(sbi)) {
			sit_i->sentries[start].discard_map
				= kzalloc(SIT_VBLOCK_MAP_SIZE, GFP_KERNEL);
			if (!sit_i->sentries[start].discard_map)
				return -ENOMEM;
		}
	}

	sit_i->tmp_map = kzalloc(SIT_VBLOCK_MAP_SIZE, GFP_KERNEL);
	if (!sit_i->tmp_map)
		return -ENOMEM;

	if (sbi->segs_per_sec > 1) {
		sit_i->sec_entries = kvzalloc(MAIN_SECS(sbi) *
					sizeof(struct sec_entry), GFP_KERNEL);
>>>>>>> v4.14.187
		if (!sit_i->sec_entries)
			return -ENOMEM;
	}

	/* get information related with SIT */
	sit_segs = le32_to_cpu(raw_super->segment_count_sit) >> 1;

	/* setup SIT bitmap from ckeckpoint pack */
<<<<<<< HEAD
	sit_bitmap_size = __bitmap_size(sbi, SIT_BITMAP);
	src_bitmap = __bitmap_ptr(sbi, SIT_BITMAP);

	sit_i->sit_bitmap = kmemdup(src_bitmap, sit_bitmap_size, GFP_KERNEL);
=======
	bitmap_size = __bitmap_size(sbi, SIT_BITMAP);
	src_bitmap = __bitmap_ptr(sbi, SIT_BITMAP);

	sit_i->sit_bitmap = kmemdup(src_bitmap, bitmap_size, GFP_KERNEL);
>>>>>>> v4.14.187
	if (!sit_i->sit_bitmap)
		return -ENOMEM;

#ifdef CONFIG_F2FS_CHECK_FS
<<<<<<< HEAD
	sit_i->sit_bitmap_mir = kmemdup(src_bitmap,
					sit_bitmap_size, GFP_KERNEL);
	if (!sit_i->sit_bitmap_mir)
		return -ENOMEM;

	sit_i->invalid_segmap = f2fs_kvzalloc(sbi,
					main_bitmap_size, GFP_KERNEL);
	if (!sit_i->invalid_segmap)
		return -ENOMEM;
=======
	sit_i->sit_bitmap_mir = kmemdup(src_bitmap, bitmap_size, GFP_KERNEL);
	if (!sit_i->sit_bitmap_mir)
		return -ENOMEM;
>>>>>>> v4.14.187
#endif

	/* init SIT information */
	sit_i->s_ops = &default_salloc_ops;

	sit_i->sit_base_addr = le32_to_cpu(raw_super->sit_blkaddr);
	sit_i->sit_blocks = sit_segs << sbi->log_blocks_per_seg;
	sit_i->written_valid_blocks = 0;
<<<<<<< HEAD
	sit_i->bitmap_size = sit_bitmap_size;
	sit_i->dirty_sentries = 0;
	sit_i->sents_per_block = SIT_ENTRY_PER_BLOCK;
	sit_i->elapsed_time = le64_to_cpu(sbi->ckpt->elapsed_time);
	sit_i->mounted_time = ktime_get_boottime_seconds();
	init_rwsem(&sit_i->sentry_lock);
=======
	sit_i->bitmap_size = bitmap_size;
	sit_i->dirty_sentries = 0;
	sit_i->sents_per_block = SIT_ENTRY_PER_BLOCK;
	sit_i->elapsed_time = le64_to_cpu(sbi->ckpt->elapsed_time);
	sit_i->mounted_time = ktime_get_real_seconds();
	mutex_init(&sit_i->sentry_lock);
>>>>>>> v4.14.187
	return 0;
}

static int build_free_segmap(struct f2fs_sb_info *sbi)
{
	struct free_segmap_info *free_i;
	unsigned int bitmap_size, sec_bitmap_size;

	/* allocate memory for free segmap information */
<<<<<<< HEAD
	free_i = f2fs_kzalloc(sbi, sizeof(struct free_segmap_info), GFP_KERNEL);
=======
	free_i = kzalloc(sizeof(struct free_segmap_info), GFP_KERNEL);
>>>>>>> v4.14.187
	if (!free_i)
		return -ENOMEM;

	SM_I(sbi)->free_info = free_i;

	bitmap_size = f2fs_bitmap_size(MAIN_SEGS(sbi));
<<<<<<< HEAD
	free_i->free_segmap = f2fs_kvmalloc(sbi, bitmap_size, GFP_KERNEL);
=======
	free_i->free_segmap = kvmalloc(bitmap_size, GFP_KERNEL);
>>>>>>> v4.14.187
	if (!free_i->free_segmap)
		return -ENOMEM;

	sec_bitmap_size = f2fs_bitmap_size(MAIN_SECS(sbi));
<<<<<<< HEAD
	free_i->free_secmap = f2fs_kvmalloc(sbi, sec_bitmap_size, GFP_KERNEL);
=======
	free_i->free_secmap = kvmalloc(sec_bitmap_size, GFP_KERNEL);
>>>>>>> v4.14.187
	if (!free_i->free_secmap)
		return -ENOMEM;

	/* set all segments as dirty temporarily */
	memset(free_i->free_segmap, 0xff, bitmap_size);
	memset(free_i->free_secmap, 0xff, sec_bitmap_size);

	/* init free segmap information */
	free_i->start_segno = GET_SEGNO_FROM_SEG0(sbi, MAIN_BLKADDR(sbi));
	free_i->free_segments = 0;
	free_i->free_sections = 0;
	spin_lock_init(&free_i->segmap_lock);
	return 0;
}

static int build_curseg(struct f2fs_sb_info *sbi)
{
	struct curseg_info *array;
	int i;

<<<<<<< HEAD
	array = f2fs_kzalloc(sbi, array_size(NR_CURSEG_TYPE, sizeof(*array)),
			     GFP_KERNEL);
=======
	array = kcalloc(NR_CURSEG_TYPE, sizeof(*array), GFP_KERNEL);
>>>>>>> v4.14.187
	if (!array)
		return -ENOMEM;

	SM_I(sbi)->curseg_array = array;

	for (i = 0; i < NR_CURSEG_TYPE; i++) {
		mutex_init(&array[i].curseg_mutex);
<<<<<<< HEAD
		array[i].sum_blk = f2fs_kzalloc(sbi, PAGE_SIZE, GFP_KERNEL);
		if (!array[i].sum_blk)
			return -ENOMEM;
		init_rwsem(&array[i].journal_rwsem);
		array[i].journal = f2fs_kzalloc(sbi,
				sizeof(struct f2fs_journal), GFP_KERNEL);
=======
		array[i].sum_blk = kzalloc(PAGE_SIZE, GFP_KERNEL);
		if (!array[i].sum_blk)
			return -ENOMEM;
		init_rwsem(&array[i].journal_rwsem);
		array[i].journal = kzalloc(sizeof(struct f2fs_journal),
							GFP_KERNEL);
>>>>>>> v4.14.187
		if (!array[i].journal)
			return -ENOMEM;
		array[i].segno = NULL_SEGNO;
		array[i].next_blkoff = 0;
	}
	return restore_curseg_summaries(sbi);
}

static int build_sit_entries(struct f2fs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_COLD_DATA);
	struct f2fs_journal *journal = curseg->journal;
	struct seg_entry *se;
	struct f2fs_sit_entry sit;
	int sit_blk_cnt = SIT_BLK_CNT(sbi);
	unsigned int i, start, end;
	unsigned int readed, start_blk = 0;
	int err = 0;
	block_t total_node_blocks = 0;

	do {
<<<<<<< HEAD
		readed = f2fs_ra_meta_pages(sbi, start_blk, BIO_MAX_PAGES,
=======
		readed = ra_meta_pages(sbi, start_blk, BIO_MAX_PAGES,
>>>>>>> v4.14.187
							META_SIT, true);

		start = start_blk * sit_i->sents_per_block;
		end = (start_blk + readed) * sit_i->sents_per_block;

		for (; start < end && start < MAIN_SEGS(sbi); start++) {
			struct f2fs_sit_block *sit_blk;
			struct page *page;

			se = &sit_i->sentries[start];
			page = get_current_sit_page(sbi, start);
<<<<<<< HEAD
			if (IS_ERR(page))
				return PTR_ERR(page);
=======
>>>>>>> v4.14.187
			sit_blk = (struct f2fs_sit_block *)page_address(page);
			sit = sit_blk->entries[SIT_ENTRY_OFFSET(sit_i, start)];
			f2fs_put_page(page, 1);

			err = check_block_count(sbi, start, &sit);
<<<<<<< HEAD
			if (err) {
				print_block_data(sbi->sb, current_sit_addr(sbi, start),
						 page_address(page), 0,  F2FS_BLKSIZE);
				return err;
			}
=======
			if (err)
				return err;
>>>>>>> v4.14.187
			seg_info_from_raw_sit(se, &sit);
			if (IS_NODESEG(se->type))
				total_node_blocks += se->valid_blocks;

			/* build discard map only one time */
<<<<<<< HEAD
			if (is_set_ckpt_flags(sbi, CP_TRIMMED_FLAG)) {
				memset(se->discard_map, 0xff,
					SIT_VBLOCK_MAP_SIZE);
			} else {
				memcpy(se->discard_map,
					se->cur_valid_map,
					SIT_VBLOCK_MAP_SIZE);
				sbi->discard_blks +=
					sbi->blocks_per_seg -
					se->valid_blocks;
			}

			if (__is_large_section(sbi))
=======
			if (f2fs_discard_en(sbi)) {
				if (is_set_ckpt_flags(sbi, CP_TRIMMED_FLAG)) {
					memset(se->discard_map, 0xff,
						SIT_VBLOCK_MAP_SIZE);
				} else {
					memcpy(se->discard_map,
						se->cur_valid_map,
						SIT_VBLOCK_MAP_SIZE);
					sbi->discard_blks +=
						sbi->blocks_per_seg -
						se->valid_blocks;
				}
			}

			if (sbi->segs_per_sec > 1)
>>>>>>> v4.14.187
				get_sec_entry(sbi, start)->valid_blocks +=
							se->valid_blocks;
		}
		start_blk += readed;
	} while (start_blk < sit_blk_cnt);

	down_read(&curseg->journal_rwsem);
	for (i = 0; i < sits_in_cursum(journal); i++) {
		unsigned int old_valid_blocks;

		start = le32_to_cpu(segno_in_journal(journal, i));
		if (start >= MAIN_SEGS(sbi)) {
<<<<<<< HEAD
			f2fs_err(sbi, "Wrong journal entry on segno %u",
				 start);
=======
			f2fs_msg(sbi->sb, KERN_ERR,
					"Wrong journal entry on segno %u",
					start);
			set_sbi_flag(sbi, SBI_NEED_FSCK);
>>>>>>> v4.14.187
			err = -EFSCORRUPTED;
			break;
		}

		se = &sit_i->sentries[start];
		sit = sit_in_journal(journal, i);

		old_valid_blocks = se->valid_blocks;
		if (IS_NODESEG(se->type))
			total_node_blocks -= old_valid_blocks;

		err = check_block_count(sbi, start, &sit);
<<<<<<< HEAD
		if (err) {
			print_block_data(sbi->sb, 0, (void *)&sit, 0,
					 sizeof(struct f2fs_sit_entry));
			break;
		}
=======
		if (err)
			break;
>>>>>>> v4.14.187
		seg_info_from_raw_sit(se, &sit);
		if (IS_NODESEG(se->type))
			total_node_blocks += se->valid_blocks;

<<<<<<< HEAD
		if (is_set_ckpt_flags(sbi, CP_TRIMMED_FLAG)) {
			memset(se->discard_map, 0xff, SIT_VBLOCK_MAP_SIZE);
		} else {
			memcpy(se->discard_map, se->cur_valid_map,
						SIT_VBLOCK_MAP_SIZE);
			sbi->discard_blks += old_valid_blocks;
			sbi->discard_blks -= se->valid_blocks;
		}

		if (__is_large_section(sbi)) {
			get_sec_entry(sbi, start)->valid_blocks +=
							se->valid_blocks;
			get_sec_entry(sbi, start)->valid_blocks -=
							old_valid_blocks;
		}
=======
		if (f2fs_discard_en(sbi)) {
			if (is_set_ckpt_flags(sbi, CP_TRIMMED_FLAG)) {
				memset(se->discard_map, 0xff,
							SIT_VBLOCK_MAP_SIZE);
			} else {
				memcpy(se->discard_map, se->cur_valid_map,
							SIT_VBLOCK_MAP_SIZE);
				sbi->discard_blks += old_valid_blocks -
							se->valid_blocks;
			}
		}

		if (sbi->segs_per_sec > 1)
			get_sec_entry(sbi, start)->valid_blocks +=
				se->valid_blocks - old_valid_blocks;
>>>>>>> v4.14.187
	}
	up_read(&curseg->journal_rwsem);

	if (!err && total_node_blocks != valid_node_count(sbi)) {
<<<<<<< HEAD
		f2fs_err(sbi, "SIT is corrupted node# %u vs %u",
			 total_node_blocks, valid_node_count(sbi));
=======
		f2fs_msg(sbi->sb, KERN_ERR,
			"SIT is corrupted node# %u vs %u",
			total_node_blocks, valid_node_count(sbi));
		set_sbi_flag(sbi, SBI_NEED_FSCK);
>>>>>>> v4.14.187
		err = -EFSCORRUPTED;
	}

	return err;
}

static void init_free_segmap(struct f2fs_sb_info *sbi)
{
	unsigned int start;
	int type;

	for (start = 0; start < MAIN_SEGS(sbi); start++) {
		struct seg_entry *sentry = get_seg_entry(sbi, start);
		if (!sentry->valid_blocks)
			__set_free(sbi, start);
		else
			SIT_I(sbi)->written_valid_blocks +=
						sentry->valid_blocks;
	}

	/* set use the current segments */
	for (type = CURSEG_HOT_DATA; type <= CURSEG_COLD_NODE; type++) {
		struct curseg_info *curseg_t = CURSEG_I(sbi, type);
		__set_test_and_inuse(sbi, curseg_t->segno);
	}
}

static void init_dirty_segmap(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int segno = 0, offset = 0;
	unsigned short valid_blocks;

	while (1) {
		/* find dirty segment based on free segmap */
		segno = find_next_inuse(free_i, MAIN_SEGS(sbi), offset);
		if (segno >= MAIN_SEGS(sbi))
			break;
		offset = segno + 1;
		valid_blocks = get_valid_blocks(sbi, segno, false);
		if (valid_blocks == sbi->blocks_per_seg || !valid_blocks)
			continue;
		if (valid_blocks > sbi->blocks_per_seg) {
			f2fs_bug_on(sbi, 1);
			continue;
		}
		mutex_lock(&dirty_i->seglist_lock);
		__locate_dirty_segment(sbi, segno, DIRTY);
		mutex_unlock(&dirty_i->seglist_lock);
	}
}

static int init_victim_secmap(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	unsigned int bitmap_size = f2fs_bitmap_size(MAIN_SECS(sbi));

<<<<<<< HEAD
	dirty_i->victim_secmap = f2fs_kvzalloc(sbi, bitmap_size, GFP_KERNEL);
	if (!dirty_i->victim_secmap)
		return -ENOMEM;

	/* W/A for FG_GC failure due to Atomic Write File and Pinned File */
	dirty_i->blacklist_victim_secmap = f2fs_kvzalloc(sbi, bitmap_size,
								GFP_KERNEL);
	if (!dirty_i->blacklist_victim_secmap)
		return -ENOMEM;

=======
	dirty_i->victim_secmap = kvzalloc(bitmap_size, GFP_KERNEL);
	if (!dirty_i->victim_secmap)
		return -ENOMEM;
>>>>>>> v4.14.187
	return 0;
}

static int build_dirty_segmap(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i;
	unsigned int bitmap_size, i;

	/* allocate memory for dirty segments list information */
<<<<<<< HEAD
	dirty_i = f2fs_kzalloc(sbi, sizeof(struct dirty_seglist_info),
								GFP_KERNEL);
=======
	dirty_i = kzalloc(sizeof(struct dirty_seglist_info), GFP_KERNEL);
>>>>>>> v4.14.187
	if (!dirty_i)
		return -ENOMEM;

	SM_I(sbi)->dirty_info = dirty_i;
	mutex_init(&dirty_i->seglist_lock);

	bitmap_size = f2fs_bitmap_size(MAIN_SEGS(sbi));

	for (i = 0; i < NR_DIRTY_TYPE; i++) {
<<<<<<< HEAD
		dirty_i->dirty_segmap[i] = f2fs_kvzalloc(sbi, bitmap_size,
								GFP_KERNEL);
=======
		dirty_i->dirty_segmap[i] = kvzalloc(bitmap_size, GFP_KERNEL);
>>>>>>> v4.14.187
		if (!dirty_i->dirty_segmap[i])
			return -ENOMEM;
	}

	init_dirty_segmap(sbi);
	return init_victim_secmap(sbi);
}

static int sanity_check_curseg(struct f2fs_sb_info *sbi)
{
	int i;

	/*
	 * In LFS/SSR curseg, .next_blkoff should point to an unused blkaddr;
	 * In LFS curseg, all blkaddr after .next_blkoff should be unused.
	 */
	for (i = 0; i < NO_CHECK_TYPE; i++) {
		struct curseg_info *curseg = CURSEG_I(sbi, i);
		struct seg_entry *se = get_seg_entry(sbi, curseg->segno);
		unsigned int blkofs = curseg->next_blkoff;

		if (f2fs_test_bit(blkofs, se->cur_valid_map))
			goto out;

		if (curseg->alloc_type == SSR)
			continue;

		for (blkofs += 1; blkofs < sbi->blocks_per_seg; blkofs++) {
			if (!f2fs_test_bit(blkofs, se->cur_valid_map))
				continue;
out:
<<<<<<< HEAD
			f2fs_err(sbi,
				 "Current segment's next free block offset is inconsistent with bitmap, logtype:%u, segno:%u, type:%u, next_blkoff:%u, blkofs:%u",
				 i, curseg->segno, curseg->alloc_type,
				 curseg->next_blkoff, blkofs);
=======
			f2fs_msg(sbi->sb, KERN_ERR,
				"Current segment's next free block offset is "
				"inconsistent with bitmap, logtype:%u, "
				"segno:%u, type:%u, next_blkoff:%u, blkofs:%u",
				i, curseg->segno, curseg->alloc_type,
				curseg->next_blkoff, blkofs);
>>>>>>> v4.14.187
			return -EFSCORRUPTED;
		}
	}
	return 0;
}

/*
 * Update min, max modified time for cost-benefit GC algorithm
 */
static void init_min_max_mtime(struct f2fs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
	unsigned int segno;

<<<<<<< HEAD
	down_write(&sit_i->sentry_lock);

	sit_i->min_mtime = ULLONG_MAX;
=======
	mutex_lock(&sit_i->sentry_lock);

	sit_i->min_mtime = LLONG_MAX;
>>>>>>> v4.14.187

	for (segno = 0; segno < MAIN_SEGS(sbi); segno += sbi->segs_per_sec) {
		unsigned int i;
		unsigned long long mtime = 0;

		for (i = 0; i < sbi->segs_per_sec; i++)
			mtime += get_seg_entry(sbi, segno + i)->mtime;

		mtime = div_u64(mtime, sbi->segs_per_sec);

		if (sit_i->min_mtime > mtime)
			sit_i->min_mtime = mtime;
	}
<<<<<<< HEAD
	sit_i->max_mtime = get_mtime(sbi, false);
	up_write(&sit_i->sentry_lock);
}

int f2fs_build_segment_manager(struct f2fs_sb_info *sbi)
=======
	sit_i->max_mtime = get_mtime(sbi);
	mutex_unlock(&sit_i->sentry_lock);
}

int build_segment_manager(struct f2fs_sb_info *sbi)
>>>>>>> v4.14.187
{
	struct f2fs_super_block *raw_super = F2FS_RAW_SUPER(sbi);
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	struct f2fs_sm_info *sm_info;
	int err;

<<<<<<< HEAD
	sm_info = f2fs_kzalloc(sbi, sizeof(struct f2fs_sm_info), GFP_KERNEL);
=======
	sm_info = kzalloc(sizeof(struct f2fs_sm_info), GFP_KERNEL);
>>>>>>> v4.14.187
	if (!sm_info)
		return -ENOMEM;

	/* init sm info */
	sbi->sm_info = sm_info;
	sm_info->seg0_blkaddr = le32_to_cpu(raw_super->segment0_blkaddr);
	sm_info->main_blkaddr = le32_to_cpu(raw_super->main_blkaddr);
	sm_info->segment_count = le32_to_cpu(raw_super->segment_count);
	sm_info->reserved_segments = le32_to_cpu(ckpt->rsvd_segment_count);
	sm_info->ovp_segments = le32_to_cpu(ckpt->overprov_segment_count);
	sm_info->main_segments = le32_to_cpu(raw_super->segment_count_main);
	sm_info->ssa_blkaddr = le32_to_cpu(raw_super->ssa_blkaddr);
	sm_info->rec_prefree_segments = sm_info->main_segments *
					DEF_RECLAIM_PREFREE_SEGMENTS / 100;
	if (sm_info->rec_prefree_segments > DEF_MAX_RECLAIM_PREFREE_SEGMENTS)
		sm_info->rec_prefree_segments = DEF_MAX_RECLAIM_PREFREE_SEGMENTS;

<<<<<<< HEAD
	if (!f2fs_lfs_mode(sbi))
		sm_info->ipu_policy = 1 << F2FS_IPU_FSYNC;
	sm_info->min_ipu_util = DEF_MIN_IPU_UTIL;
	sm_info->min_fsync_blocks = DEF_MIN_FSYNC_BLOCKS;
	sm_info->min_seq_blocks = sbi->blocks_per_seg * sbi->segs_per_sec;
	sm_info->min_hot_blocks = DEF_MIN_HOT_BLOCKS;
	sm_info->min_ssr_sections = reserved_sections(sbi);

	INIT_LIST_HEAD(&sm_info->sit_entry_set);

	init_rwsem(&sm_info->curseg_lock);

	if (!f2fs_readonly(sbi->sb)) {
		err = f2fs_create_flush_cmd_control(sbi);
=======
	if (!test_opt(sbi, LFS))
		sm_info->ipu_policy = 1 << F2FS_IPU_FSYNC;
	sm_info->min_ipu_util = DEF_MIN_IPU_UTIL;
	sm_info->min_fsync_blocks = DEF_MIN_FSYNC_BLOCKS;
	sm_info->min_hot_blocks = DEF_MIN_HOT_BLOCKS;

	sm_info->trim_sections = DEF_BATCHED_TRIM_SECTIONS;

	INIT_LIST_HEAD(&sm_info->sit_entry_set);

	if (!f2fs_readonly(sbi->sb)) {
		err = create_flush_cmd_control(sbi);
>>>>>>> v4.14.187
		if (err)
			return err;
	}

	err = create_discard_cmd_control(sbi);
	if (err)
		return err;

	err = build_sit_info(sbi);
	if (err)
		return err;
	err = build_free_segmap(sbi);
	if (err)
		return err;
	err = build_curseg(sbi);
	if (err)
		return err;

	/* reinit free segmap based on SIT */
	err = build_sit_entries(sbi);
	if (err)
		return err;

	init_free_segmap(sbi);
	err = build_dirty_segmap(sbi);
	if (err)
		return err;

	err = sanity_check_curseg(sbi);
	if (err)
		return err;

	init_min_max_mtime(sbi);
	return 0;
}

static void discard_dirty_segmap(struct f2fs_sb_info *sbi,
		enum dirty_type dirty_type)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);

	mutex_lock(&dirty_i->seglist_lock);
	kvfree(dirty_i->dirty_segmap[dirty_type]);
	dirty_i->nr_dirty[dirty_type] = 0;
	mutex_unlock(&dirty_i->seglist_lock);
}

static void destroy_victim_secmap(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	kvfree(dirty_i->victim_secmap);
<<<<<<< HEAD

	/* W/A for FG_GC failure due to Atomic Write File and Pinned File */
	kvfree(dirty_i->blacklist_victim_secmap);
=======
>>>>>>> v4.14.187
}

static void destroy_dirty_segmap(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	int i;

	if (!dirty_i)
		return;

	/* discard pre-free/dirty segments list */
	for (i = 0; i < NR_DIRTY_TYPE; i++)
		discard_dirty_segmap(sbi, i);

	destroy_victim_secmap(sbi);
	SM_I(sbi)->dirty_info = NULL;
<<<<<<< HEAD
	kvfree(dirty_i);
=======
	kfree(dirty_i);
>>>>>>> v4.14.187
}

static void destroy_curseg(struct f2fs_sb_info *sbi)
{
	struct curseg_info *array = SM_I(sbi)->curseg_array;
	int i;

	if (!array)
		return;
	SM_I(sbi)->curseg_array = NULL;
	for (i = 0; i < NR_CURSEG_TYPE; i++) {
<<<<<<< HEAD
		kvfree(array[i].sum_blk);
		kvfree(array[i].journal);
	}
	kvfree(array);
=======
		kfree(array[i].sum_blk);
		kfree(array[i].journal);
	}
	kfree(array);
>>>>>>> v4.14.187
}

static void destroy_free_segmap(struct f2fs_sb_info *sbi)
{
	struct free_segmap_info *free_i = SM_I(sbi)->free_info;
	if (!free_i)
		return;
	SM_I(sbi)->free_info = NULL;
	kvfree(free_i->free_segmap);
	kvfree(free_i->free_secmap);
<<<<<<< HEAD
	kvfree(free_i);
=======
	kfree(free_i);
>>>>>>> v4.14.187
}

static void destroy_sit_info(struct f2fs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
<<<<<<< HEAD
=======
	unsigned int start;
>>>>>>> v4.14.187

	if (!sit_i)
		return;

<<<<<<< HEAD
	if (sit_i->sentries)
		kvfree(sit_i->bitmap);
	kvfree(sit_i->tmp_map);
=======
	if (sit_i->sentries) {
		for (start = 0; start < MAIN_SEGS(sbi); start++) {
			kfree(sit_i->sentries[start].cur_valid_map);
#ifdef CONFIG_F2FS_CHECK_FS
			kfree(sit_i->sentries[start].cur_valid_map_mir);
#endif
			kfree(sit_i->sentries[start].ckpt_valid_map);
			kfree(sit_i->sentries[start].discard_map);
		}
	}
	kfree(sit_i->tmp_map);
>>>>>>> v4.14.187

	kvfree(sit_i->sentries);
	kvfree(sit_i->sec_entries);
	kvfree(sit_i->dirty_sentries_bitmap);

	SM_I(sbi)->sit_info = NULL;
<<<<<<< HEAD
	kvfree(sit_i->sit_bitmap);
#ifdef CONFIG_F2FS_CHECK_FS
	kvfree(sit_i->sit_bitmap_mir);
	kvfree(sit_i->invalid_segmap);
#endif
	kvfree(sit_i);
}

void f2fs_destroy_segment_manager(struct f2fs_sb_info *sbi)
=======
	kfree(sit_i->sit_bitmap);
#ifdef CONFIG_F2FS_CHECK_FS
	kfree(sit_i->sit_bitmap_mir);
#endif
	kfree(sit_i);
}

void destroy_segment_manager(struct f2fs_sb_info *sbi)
>>>>>>> v4.14.187
{
	struct f2fs_sm_info *sm_info = SM_I(sbi);

	if (!sm_info)
		return;
<<<<<<< HEAD
	f2fs_destroy_flush_cmd_control(sbi, true);
=======
	destroy_flush_cmd_control(sbi, true);
>>>>>>> v4.14.187
	destroy_discard_cmd_control(sbi);
	destroy_dirty_segmap(sbi);
	destroy_curseg(sbi);
	destroy_free_segmap(sbi);
	destroy_sit_info(sbi);
	sbi->sm_info = NULL;
<<<<<<< HEAD
	kvfree(sm_info);
}

int __init f2fs_create_segment_manager_caches(void)
{
	discard_entry_slab = f2fs_kmem_cache_create("f2fs_discard_entry",
=======
	kfree(sm_info);
}

int __init create_segment_manager_caches(void)
{
	discard_entry_slab = f2fs_kmem_cache_create("discard_entry",
>>>>>>> v4.14.187
			sizeof(struct discard_entry));
	if (!discard_entry_slab)
		goto fail;

<<<<<<< HEAD
	discard_cmd_slab = f2fs_kmem_cache_create("f2fs_discard_cmd",
=======
	discard_cmd_slab = f2fs_kmem_cache_create("discard_cmd",
>>>>>>> v4.14.187
			sizeof(struct discard_cmd));
	if (!discard_cmd_slab)
		goto destroy_discard_entry;

<<<<<<< HEAD
	sit_entry_set_slab = f2fs_kmem_cache_create("f2fs_sit_entry_set",
=======
	sit_entry_set_slab = f2fs_kmem_cache_create("sit_entry_set",
>>>>>>> v4.14.187
			sizeof(struct sit_entry_set));
	if (!sit_entry_set_slab)
		goto destroy_discard_cmd;

<<<<<<< HEAD
	inmem_entry_slab = f2fs_kmem_cache_create("f2fs_inmem_page_entry",
=======
	inmem_entry_slab = f2fs_kmem_cache_create("inmem_page_entry",
>>>>>>> v4.14.187
			sizeof(struct inmem_pages));
	if (!inmem_entry_slab)
		goto destroy_sit_entry_set;
	return 0;

destroy_sit_entry_set:
	kmem_cache_destroy(sit_entry_set_slab);
destroy_discard_cmd:
	kmem_cache_destroy(discard_cmd_slab);
destroy_discard_entry:
	kmem_cache_destroy(discard_entry_slab);
fail:
	return -ENOMEM;
}

<<<<<<< HEAD
void f2fs_destroy_segment_manager_caches(void)
=======
void destroy_segment_manager_caches(void)
>>>>>>> v4.14.187
{
	kmem_cache_destroy(sit_entry_set_slab);
	kmem_cache_destroy(discard_cmd_slab);
	kmem_cache_destroy(discard_entry_slab);
	kmem_cache_destroy(inmem_entry_slab);
}
