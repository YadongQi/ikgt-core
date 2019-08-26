/*
 * Copyright (c) 2015-2019 Intel Corporation.
 * All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef _IMAGE_LOADER_H_
#define _IMAGE_LOADER_H_

boolean_t relocate_elf_image(	IN uint64_t ld_addr,
				IN uint64_t ld_size,
				IN uint64_t rt_addr,
				IN uint64_t rt_size,
				OUT uint64_t *p_entry);

#endif     /* _IMAGE_LOADER_H_ */
