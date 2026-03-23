/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 Ada Logics Ltd.
 *
 * Fuzz test for ELF image loader — exercises load_elf_image_phdr() and
 * load_elf_image_shdr() with mutated ELF binaries.
 *
 * Destination addresses inside program/section headers are redirected into
 * a safe heap buffer so the loader's memcpy/memset calls do not scribble
 * over random host memory.  Source offsets and sizes are clamped to the
 * fuzz input so reads stay in bounds.  The ELF class is forced to 64-bit
 * because Elf64_Addr can hold a full 64-bit host pointer.
 */

#include <elf.h>
#include <malloc.h>
#include <test/fuzz.h>

#define LOAD_BUF_SIZE (1 << 20) /* 1 MiB destination for segment loads */

/*
 * Minimum input: ELF header + one section header.  The shdr loader
 * unconditionally reads the e_shstrndx section header (for the string
 * table) before the loop, so there must always be a readable Elf64_Shdr
 * at e_shoff even when e_shnum == 0.
 */
#define MIN_INPUT_SIZE (sizeof(Elf64_Ehdr) + sizeof(Elf64_Shdr))

static void *load_buf;

static int fuzz_elf_loader(const uint8_t *data, size_t size)
{
	uint8_t *copy;
	Elf64_Ehdr *ehdr;
	unsigned long addr;
	size_t max_n;
	int i;

	if (size < MIN_INPUT_SIZE)
		return 0;

	if (!load_buf) {
		load_buf = malloc(LOAD_BUF_SIZE);
		if (!load_buf)
			return 0;
	}

	/* Mutable copy — we redirect load addresses into load_buf. */
	copy = malloc(size);
	if (!copy)
		return 0;
	memcpy(copy, data, size);

	ehdr = (Elf64_Ehdr *)copy;

	/*
	 * Force a valid ELF64 executable header.  The loader gates on
	 * IS_ELF() + ET_EXEC + EI_CLASS, so stamp those in rather than
	 * waiting for the fuzzer to discover the 4-byte magic.  Everything
	 * else (offsets, counts, sizes) comes straight from fuzz data.
	 */
	ehdr->e_ident[EI_MAG0] = 0x7f;
	ehdr->e_ident[EI_MAG1] = 'E';
	ehdr->e_ident[EI_MAG2] = 'L';
	ehdr->e_ident[EI_MAG3] = 'F';
	ehdr->e_ident[EI_CLASS] = ELFCLASS64;
	ehdr->e_type = ET_EXEC;

	/*
	 * Redirect e_entry into load_buf.  On PPC64 ELF V1 the loader
	 * dereferences e_entry as a function-descriptor pointer, so it
	 * must point to readable memory.
	 */
	ehdr->e_entry = (Elf64_Addr)(uintptr_t)load_buf +
			(ehdr->e_entry % (LOAD_BUF_SIZE / 2));

	/*
	 * Clamp header table offsets and counts.
	 *
	 * e_shoff must ALWAYS point to valid memory because the shdr
	 * loader reads shdr[e_shstrndx] before checking e_shnum.
	 * We guarantee at least sizeof(Elf64_Shdr) bytes past the ehdr
	 * via the MIN_INPUT_SIZE check above.
	 *
	 * Require offsets past the ELF header so phdr/shdr fixups below
	 * cannot corrupt the ehdr fields they depend on.
	 */
	if (ehdr->e_phoff < sizeof(Elf64_Ehdr) || ehdr->e_phoff >= size) {
		ehdr->e_phnum = 0;
	} else {
		max_n = (size - ehdr->e_phoff) / sizeof(Elf64_Phdr);
		if (ehdr->e_phnum > max_n)
			ehdr->e_phnum = (uint16_t)max_n;
	}

	if (ehdr->e_shoff < sizeof(Elf64_Ehdr) ||
	    ehdr->e_shoff + sizeof(Elf64_Shdr) > size) {
		ehdr->e_shoff = sizeof(Elf64_Ehdr);
		ehdr->e_shnum = 0;
		ehdr->e_shstrndx = 0;
	} else {
		max_n = (size - ehdr->e_shoff) / sizeof(Elf64_Shdr);
		if (ehdr->e_shnum > max_n)
			ehdr->e_shnum = (uint16_t)max_n;
	}

	/* If phdr and shdr tables overlap, keep only the first one. */
	if (ehdr->e_phnum > 0 && ehdr->e_shnum > 0) {
		size_t ph_end = ehdr->e_phoff +
				(size_t)ehdr->e_phnum * sizeof(Elf64_Phdr);
		size_t sh_end = ehdr->e_shoff +
				(size_t)ehdr->e_shnum * sizeof(Elf64_Shdr);
		if (ehdr->e_phoff < sh_end && ehdr->e_shoff < ph_end)
			ehdr->e_shnum = 0;
	}

	/*
	 * Clamp e_shstrndx.  The shdr loader reads shdr[e_shstrndx]
	 * unconditionally (before checking e_shnum), so the index must
	 * point to a readable Elf64_Shdr in the buffer.
	 */
	{
		size_t max_idx = (size - ehdr->e_shoff) / sizeof(Elf64_Shdr);

		if (ehdr->e_shstrndx >= max_idx)
			ehdr->e_shstrndx = 0;
		if (ehdr->e_shnum > 0 && ehdr->e_shstrndx >= ehdr->e_shnum)
			ehdr->e_shstrndx = 0;
	}

	/*
	 * ---- String table safety (BEFORE phdr/shdr address fixups) ----
	 *
	 * Pre-clamp section source offsets so the null-termination write
	 * cannot land inside the ELF header (bytes 0-63).  This must
	 * happen before the phdr/shdr address redirections below so that
	 * the null byte cannot corrupt an already-redirected pointer.
	 */
	for (i = 0; i < ehdr->e_shnum; i++) {
		Elf64_Shdr *s = (Elf64_Shdr *)(copy + ehdr->e_shoff) + i;

		if (s->sh_offset < sizeof(Elf64_Ehdr) ||
		    s->sh_offset >= size)
			s->sh_offset = sizeof(Elf64_Ehdr);
		if (s->sh_size > size - s->sh_offset)
			s->sh_size = size - s->sh_offset;
	}

	if (ehdr->e_shnum > 0) {
		Elf64_Shdr *str_s =
			(Elf64_Shdr *)(copy + ehdr->e_shoff) + ehdr->e_shstrndx;

		/*
		 * Force the shstrndx section to SHT_STRTAB so the loader
		 * sets up strtab and exercises the string-table code path.
		 */
		str_s->sh_type = SHT_STRTAB;

		/* Null-terminate whatever the string table points at. */
		if (str_s->sh_size > 0 &&
		    str_s->sh_offset + str_s->sh_size <= size)
			copy[str_s->sh_offset + str_s->sh_size - 1] = '\0';
		else if (str_s->sh_offset < size)
			copy[str_s->sh_offset] = '\0';

		/* Clamp every sh_name into the string table. */
		for (i = 0; i < ehdr->e_shnum; i++) {
			Elf64_Shdr *s =
				(Elf64_Shdr *)(copy + ehdr->e_shoff) + i;
			if (str_s->sh_size == 0 ||
			    s->sh_name >= str_s->sh_size)
				s->sh_name = 0;
		}
	}

	/*
	 * ---- Fix up program headers ----
	 * Done AFTER string table writes so redirected pointers cannot
	 * be corrupted by the null-termination above.
	 */
	for (i = 0; i < ehdr->e_phnum; i++) {
		Elf64_Phdr *p = (Elf64_Phdr *)(copy + ehdr->e_phoff) + i;

		/* Force PT_LOAD so the loader processes every segment. */
		p->p_type = PT_LOAD;

		/* Destination → safe buffer. */
		p->p_paddr = (Elf64_Addr)(uintptr_t)load_buf +
			     (p->p_paddr % (LOAD_BUF_SIZE / 2));

		/* Source → clamp to fuzz data. */
		if (p->p_offset >= size)
			p->p_offset = 0;
		if (p->p_filesz > size - p->p_offset)
			p->p_filesz = size - p->p_offset;

		/* BSS region → keep inside load_buf. */
		if (p->p_memsz > LOAD_BUF_SIZE / 2)
			p->p_memsz = LOAD_BUF_SIZE / 2;
		if (p->p_memsz < p->p_filesz)
			p->p_memsz = p->p_filesz;
	}

	/*
	 * ---- Fix up section headers ----
	 * Also done AFTER string table writes.  Re-clamp offsets/sizes
	 * in case the null-termination corrupted an already-clamped value.
	 */
	for (i = 0; i < ehdr->e_shnum; i++) {
		Elf64_Shdr *s = (Elf64_Shdr *)(copy + ehdr->e_shoff) + i;

		/* Destination → safe buffer. */
		s->sh_addr = (Elf64_Addr)(uintptr_t)load_buf +
			     (s->sh_addr % (LOAD_BUF_SIZE / 2));

		/* Source → re-clamp to fuzz data. */
		if (s->sh_offset < sizeof(Elf64_Ehdr) ||
		    s->sh_offset >= size)
			s->sh_offset = sizeof(Elf64_Ehdr);
		if (s->sh_size > size - s->sh_offset)
			s->sh_size = size - s->sh_offset;
	}

	/*
	 * Re-force shstrndx section to SHT_STRTAB after ALL fixup loops.
	 * Also force a non-strtab section to SHT_NOBITS + SHF_ALLOC to
	 * exercise the BSS-clearing code path in the shdr loader.
	 */
	if (ehdr->e_shnum > 0) {
		Elf64_Shdr *str_s =
			(Elf64_Shdr *)(copy + ehdr->e_shoff) + ehdr->e_shstrndx;
		str_s->sh_type = SHT_STRTAB;

		/* Make a non-strtab section exercise the SHT_NOBITS path. */
		for (i = 0; i < ehdr->e_shnum; i++) {
			Elf64_Shdr *s;

			if (i == ehdr->e_shstrndx)
				continue;
			s = (Elf64_Shdr *)(copy + ehdr->e_shoff) + i;
			s->sh_type = SHT_NOBITS;
			s->sh_flags |= SHF_ALLOC;
			break;
		}
	}

	/*
	 * Re-stamp critical header fields right before the loader calls.
	 * This MUST be the last modification to the buffer.
	 */
	ehdr->e_ident[EI_MAG0] = 0x7f;
	ehdr->e_ident[EI_MAG1] = 'E';
	ehdr->e_ident[EI_MAG2] = 'L';
	ehdr->e_ident[EI_MAG3] = 'F';
	ehdr->e_ident[EI_CLASS] = ELFCLASS64;
	ehdr->e_type = ET_EXEC;

	addr = (unsigned long)(uintptr_t)copy;

	/* Exercise both loading strategies. */
	load_elf_image_phdr(addr);
	load_elf_image_shdr(addr);

	free(copy);
	return 0;
}
FUZZ_TEST(fuzz_elf_loader, 0);
