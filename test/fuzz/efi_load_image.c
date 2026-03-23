/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 Ada Logics Ltd.
 *
 * Fuzz test for efi_load_image() - feeds random data as a PE image buffer
 * into the EFI image loader.
 */

#include <efi_loader.h>
#include <test/fuzz.h>

static int fuzz_efi_load_image(const uint8_t *data, size_t size)
{
	efi_handle_t image_handle = NULL;

	if (size == 0)
		return 0;

	/* Initialize EFI subsystem on first call */
	if (efi_obj_list_initialized != EFI_SUCCESS)
		efi_init_obj_list();

	/* Call efi_load_image with fuzz data as a PE image buffer */
	EFI_CALL(efi_load_image(false, efi_root, NULL,
				(void *)data, size, &image_handle));

	/* Clean up loaded image to prevent memory accumulation */
	if (image_handle)
		EFI_CALL(efi_unload_image(image_handle));

	return 0;
}
FUZZ_TEST(fuzz_efi_load_image, 0);
