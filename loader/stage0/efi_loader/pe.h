/*
 * Copyright (c) 2015-2019 Intel Corporation.
 * All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __PE_H_
#define __PE_H_

boolean_t parse_pe_section(char *base, char *section_name, uint32_t section_name_len, uint64_t *vaddr, uint64_t *size);

#endif
