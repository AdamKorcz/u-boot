/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 Ada Logics Ltd.
 *
 * Fuzz test for image_decomp() - multi-format decompressor.
 */

#include <image.h>
#include <malloc.h>
#include <test/fuzz.h>

#define DECOMP_BUF_SIZE (1 * 1024 * 1024)  /* 1 MB output limit */

static void *decomp_buf;

static int fuzz_image_decomp(const uint8_t *data, size_t size)
{
	ulong load_end;
	int comp;

	if (size < 2)
		return 0;

	/* First byte selects compression type */
	comp = (data[0] % (IH_COMP_COUNT - 1)) + 1;
	data++;
	size--;

	if (!decomp_buf) {
		decomp_buf = malloc(DECOMP_BUF_SIZE);
		if (!decomp_buf)
			return 0;
	}

	image_decomp(comp, 0, 0, IH_TYPE_KERNEL,
		     decomp_buf, (void *)data, size,
		     DECOMP_BUF_SIZE, &load_end);

	return 0;
}
FUZZ_TEST(fuzz_image_decomp, 0);
