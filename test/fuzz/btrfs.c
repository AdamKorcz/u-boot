/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 Ada Logics Ltd.
 *
 * Fuzz test for BTRFS filesystem parser.
 */

#include <command.h>
#include <os.h>
#include <test/fuzz.h>

#define FUZZ_DISK_PATH "/tmp/fuzz_btrfs.img"

static int fuzz_btrfs(const uint8_t *data, size_t size)
{
	int fd;

	if (size < 512)
		return 0;

	fd = os_open(FUZZ_DISK_PATH, OS_O_WRONLY | OS_O_CREAT | OS_O_TRUNC);
	if (fd < 0)
		return 0;
	os_write(fd, data, size);
	os_close(fd);

	run_command("host bind 0 " FUZZ_DISK_PATH, 0);
	run_command("ls host 0:0 /", 0);
	run_command("host unbind 0", 0);

	return 0;
}
FUZZ_TEST(fuzz_btrfs, 0);
