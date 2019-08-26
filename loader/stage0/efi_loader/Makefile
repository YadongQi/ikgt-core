
ARCH = $(shell uname -m)

TARGET := stage0

CSOURCES := stage0.c
CSOURCES += pe.c
CSOURCES += libelfloader/elf64_ld.c libelfloader/elf_ld.c

OBJS := $(OUTDIR)/stage0.o \
	$(OUTDIR)/elf64_ld.o \
	$(OUTDIR)/elf_ld.o \
	$(OUTDIR)/pe.o

SYS_INC := $(SYSROOT)/usr/include
SYS_LIB := $(SYSROOT)/usr/lib64

GNUEFI_DIR := $(SYS_LIB)
EFI_CRT_OBJS := $(GNUEFI_DIR)/crt0-efi-$(ARCH).o
EFI_LDS := stage0_link.lds

INCLUDE := -I$(SYS_INC)/efi -I$(SYS_INC)/efi/$(ARCH)
INCLUDE += -I../../../include -Ilibelfloader/

CFLAGS := $(INCLUDE) $(EVMM_CMPL_FLAGS) -m64 -mno-red-zone -Wall -DEFI_FUNCTION_WRAPPER -fPIC -fshort-wchar -ffreestanding -D$(ARCH) -O2

LDFLAGS := -nostdlib -znocombreloc -T $(EFI_LDS) -shared -Bsymbolic -L$(GNUEFI_DIR) $(EFI_CRT_OBJS)

all: $(TARGET).efi

$(TARGET).efi: $(TARGET).so
	objcopy -j .text -j .sdata -j .data -j .dynamic -j .dynsym -j .rel -j .rela -j .reloc \
		--target=efi-app-x86-64 $(OUTDIR)/$^ $(BUILD_DIR)/$@

$(TARGET).so: $(OBJS)
	ld $(LDFLAGS) -o $(OUTDIR)/$@ $^ -lefi -lgnuefi $(shell $(CC) $(CFLAGS) -print-libgcc-file-name)

clean:
	rm -f $(OUTDIR)

$(OUTDIR)/%.o: $(CURDIR)/libelfloader/%.c
	@echo "CC $@"
	$(CC) -c $(CFLAGS) $< -o $@

$(OUTDIR)/%.o: $(CURDIR)/%.c
	@echo "CC $@"
	$(CC) -c $(CFLAGS) $< -o $@
