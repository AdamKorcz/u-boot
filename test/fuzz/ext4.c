/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 Ada Logics Ltd.
 *
 * Fuzz test for ext4 filesystem parser — exercises superblock parsing,
 * block group descriptors, inode reading, directory iteration, extent
 * tree traversal, indirect block addressing, and partition table parsing.
 */

#include <blk.h>
#include <command.h>
#include <ext4fs.h>
#include <malloc.h>
#include <os.h>
#include <part.h>
#include <setjmp.h>
#include <test/fuzz.h>
#include "../../fs/ext4/ext4_journal.h"

extern jmp_buf fuzz_exit_jmp;

extern int jrnl_blk_idx;
extern struct journal_log *journal_ptr[];
extern struct dirty_blocks *dirty_block_ptr[];

/* Reset all ext4 global state so each fuzz iteration starts clean.
 * This handles both normal cleanup and recovery after longjmp
 * (where stack-frame cleanup was skipped).
 */
static void ext4fs_fuzz_reset(void)
{
	struct ext_filesystem *fs = get_fs();
	int i;

	/* Do not call ext4fs_free_node — it dereferences ext4fs_root
	 * which may be corrupt after longjmp.
	 */
	ext4fs_file = NULL;

	if (ext4fs_root != NULL) {
		free(ext4fs_root);
		ext4fs_root = NULL;
	}

	ext4fs_reinit_global();

	if (g_parent_inode != NULL) {
		free(g_parent_inode);
		g_parent_inode = NULL;
	}

	/* Free ext_filesystem allocations left from the write path */
	if (fs->sb) {
		free(fs->sb);
		fs->sb = NULL;
	}
	if (fs->gdtable) {
		free(fs->gdtable);
		fs->gdtable = NULL;
	}
	if (fs->blk_bmaps) {
		for (i = 0; i < fs->no_blkgrp; i++)
			free(fs->blk_bmaps[i]);
		free(fs->blk_bmaps);
		fs->blk_bmaps = NULL;
	}
	if (fs->inode_bmaps) {
		for (i = 0; i < fs->no_blkgrp; i++)
			free(fs->inode_bmaps[i]);
		free(fs->inode_bmaps);
		fs->inode_bmaps = NULL;
	}
	memset(fs, 0, sizeof(*fs));

	/* Reset journal state */
	ext4fs_free_revoke_blks();

	for (i = 0; i < MAX_JOURNAL_ENTRIES; i++) {
		if (journal_ptr[i]) {
			free(journal_ptr[i]->buf);
			free(journal_ptr[i]);
			journal_ptr[i] = NULL;
		}
		if (dirty_block_ptr[i]) {
			free(dirty_block_ptr[i]->buf);
			free(dirty_block_ptr[i]);
			dirty_block_ptr[i] = NULL;
		}
	}
	gindex = 0;
	gd_index = 0;
	jrnl_blk_idx = 1;
}

#define FUZZ_DISK_PATH "/tmp/fuzz_ext4.img"

static int fuzz_ext4(const uint8_t *data, size_t size)
{
	static uint8_t buf[131072];
	struct blk_desc *desc;
	int fd;

	/* Reset all ext4/journal state from any previous iteration,
	 * including state leaked by longjmp recovery.
	 */
	ext4fs_fuzz_reset();

	if (size < 2048)
		return 0;
	if (size > sizeof(buf))
		size = sizeof(buf);

	memcpy(buf, data, size);

	fd = os_open(FUZZ_DISK_PATH, OS_O_WRONLY | OS_O_CREAT | OS_O_TRUNC);
	if (fd < 0)
		return 0;
	os_write(fd, buf, size);
	os_close(fd);

	/* host bind auto-unbinds any existing device with the same label,
	 * so no explicit cleanup is needed even after longjmp.
	 */
	run_command("host bind 0 " FUZZ_DISK_PATH, 0);

	/* setjmp so that os_exit() (called by panic/hang) returns here
	 * instead of killing the fuzzer process.  The next iteration's
	 * ext4fs_fuzz_reset() handles cleanup of any leaked state.
	 */
	if (setjmp(fuzz_exit_jmp))
		return 0;

	desc = blk_get_dev("host", 0);
	if (desc)
		part_init(desc);

	run_command("ls host 0 /", 0);
	run_command("ls host 0:1 /", 0);
	run_command("ls host 0:0 /", 0);
	run_command("size host 0:0 /a", 0);
	run_command("load host 0:0 $loadaddr /a", 0);
	run_command("save host 0:0 $loadaddr /b 100", 0);

	run_command("host unbind 0", 0);

	return 0;
}
FUZZ_TEST(fuzz_ext4, 0);
