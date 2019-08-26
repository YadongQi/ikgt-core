/*
 * Copyright (c) 2015-2019 Intel Corporation.
 * All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <efi.h>
#include <efilib.h>
#include "vmm_base.h"
#include "pe.h"

#define	DOS_HEADER_MAGIC 0x5A4D  /* "MZ" */
typedef struct {
	uint16_t  e_magic;
	uint16_t  e_unused[29];
        uint32_t  e_lfanew; // Offset to PE header
} PACKED dos_header_t;

#define PE_MACHINE_X86_64    0x8664
#define PE_HEADER_MAGIC      0x00004550  /* "PE\0\0" */
typedef struct {
	uint32_t magic;
	uint16_t machine;
	uint16_t num_of_sections;
	uint32_t time_date_stamp;
	uint32_t pointer_to_sym_table;
	uint32_t num_of_sym;
	uint16_t size_of_opt_header;
	uint16_t characteristics;
} PACKED pe_header_t;

typedef struct {
	char  name[8];
	uint32_t virtual_size;
	uint32_t virtual_addr;
	uint32_t size_of_rawdata;
	uint32_t pointer_to_rawData;
	uint32_t pointer_to_realocs;
	uint32_t pointer_to_linenums;
	uint16_t num_of_realocs;
	uint16_t num_of_linenums;
	uint32_t characteristics;
} PACKED pe_section_header_t;


boolean_t parse_pe_section(char *base, char *section_name, uint32_t section_name_len, uint64_t *vma, uint64_t *len)
{
        dos_header_t *dh;
        pe_header_t *pe;
        pe_section_header_t *ph;
        uint16_t i;
	uint64_t offset;

        dh = (dos_header_t *)base;

        if (dh->e_magic != DOS_HEADER_MAGIC)
                return FALSE;

        pe = (pe_header_t *)(base + dh->e_lfanew);
	if (pe->magic != PE_HEADER_MAGIC)
                return FALSE;

        if (pe->machine != PE_MACHINE_X86_64)
                return FALSE;

        offset = dh->e_lfanew + sizeof(*pe) + pe->size_of_opt_header;

        for (i = 0; i < pe->num_of_sections; i++) {
                ph = (pe_section_header_t *)(base + offset);
                if (CompareMem(ph->name, section_name, section_name_len) == 0) {
			*vma = ph->virtual_addr;
			*len = ph->virtual_size;
			return TRUE;
		}

                offset += sizeof(*ph);
        }

        return FALSE;
}
