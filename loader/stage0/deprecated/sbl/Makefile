################################################
# Copyright (c) 2015-2019 Intel Corporation.
# All rights reserved.
#
# SPDX-License-Identidfier: Apache-2.0
#
################################################

CSOURCES = stage0.c sbl_boot_param.c seed_list_parse.c
ASOURCES = stage0_entry.S

include $(PROJS)/rule.linux

OBJS = $(OUTDIR)/stage0_entry.o \
	$(OUTDIR)/stage0.o \
	$(OUTDIR)/stage0_lib.o \
	$(OUTDIR)/sbl_boot_param.o \
	$(OUTDIR)/seed_list_parse.o \
	$(LIB_DIR)/elf_ld.o \
	$(LIB_DIR)/elf32_ld.o \
	$(LIB_DIR)/elf64_ld.o \
	$(LIB_DIR)/util.o \
	$(LIB_DIR)/string.o \
	$(LIB_DIR)/print.o \
	$(LIB_DIR)/sprintf.o

ifneq (, $(findstring -DLIB_PCI, $(EVMM_CMPL_FLAGS)))
OBJS += $(LIB_DIR)/pci.o
endif

ifneq (, $(findstring -DLIB_PRINT, $(EVMM_CMPL_FLAGS)))
OBJS += $(LIB_DIR)/serial.o
endif

include $(PROJS)/loader/stage0/rule.stage0_link
