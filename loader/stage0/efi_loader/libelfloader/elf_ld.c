/*
 * Copyright (c) 2015-2019 Intel Corporation.
 * All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "elf64_ld.h"
#include "elf_ld.h"

//#define local_print(fmt, ...)
#define local_print(fmt, ...) Print(fmt, ##__VA_ARGS__);

void *image_offset(module_file_info_t *file_info,
				uint64_t src_offset, uint64_t bytes_to_read)
{
	if ((src_offset + bytes_to_read) > file_info->loadtime_size) {
		return NULL; /* read no more than size */
	}
	if ((src_offset + bytes_to_read) <= src_offset) {
		return NULL; /* overflow or bytes_to_read == 0 */
	}

	return (void *)(UINTN)(file_info->loadtime_addr+ src_offset);
}

boolean_t image_copy(void *dest, module_file_info_t *file_info,
				uint64_t src_offset, uint64_t bytes_to_copy)
{
	void *src;
	src = image_offset(file_info, src_offset, bytes_to_copy);
	if (!src) {
		return FALSE;
	}
	if (((uint64_t)(UINTN)dest < file_info->runtime_addr) ||
		(((uint64_t)(UINTN)dest + bytes_to_copy) >
		 (file_info->runtime_addr + file_info->runtime_image_size))) {
		return FALSE;
	}
	CopyMem(dest, src, bytes_to_copy);
	return TRUE;
}

/*------------------------- Exported Interface --------------------------*/

/*----------------------------------------------------------------------
 *
 * relocate image in memory
 *
 * Input:
 * uint64_t ld_addr - loadtime address, where the image has been load to.
 * uint64_t ld_size - loadtime size, the image size.
 * uint64_t rt_addr - runtime address, where the image will be relocated.
 * uint64_t rt_size - runtime size.
 *
 * Output:
 * uint64_t* p_entry - address of the uint64_t that will be filled
 * with the address of image entry point if all is ok
 *
 * Output:
 * Return value - FALSE on any error
 *---------------------------------------------------------------------- */
boolean_t relocate_elf_image(	IN uint64_t ld_addr,
				IN uint64_t ld_size,
				IN uint64_t rt_addr,
				IN uint64_t rt_size,
				OUT uint64_t *p_entry)
{
	uint8_t *p_buffer;
	module_file_info_t file_info;

	file_info.loadtime_addr = ld_addr;
	file_info.loadtime_size = ld_size;
	file_info.runtime_addr = rt_addr;
	file_info.runtime_total_size = rt_size;

	p_buffer = (uint8_t *)image_offset(&file_info, 0,
			sizeof(elf64_ehdr_t));
	if (!p_buffer){
		local_print(L"failed to read file's header\n");
		return FALSE;
	}
	if (!elf_header_is_valid((elf64_ehdr_t *)p_buffer)) {
		local_print(L"not an elf binary\n");
		return FALSE;
	}

	if (is_elf64((elf64_ehdr_t *)p_buffer)) {
		return elf64_load_executable(&file_info, p_entry);
	} else {
		local_print(L"not an elf64 binary\n");
		return FALSE;
	}
}
