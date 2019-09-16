/*
 * Copyright (c) 2015-2019 Intel Corporation.
 * All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <efi.h>
#include <efilib.h>
#include "vmm_asm.h"
#include "vmm_arch.h"
#include "evmm_desc.h"
#include "file_pack.h"
#include "device_sec_info.h"
#include "image_loader.h"
#include "pe.h"

#include "MpService.h"

#define FEATURE_CONTROL_LOCK            (1ULL << 0)
#define FEATURE_CONTROL_VMX_OUT_SMX     (1ULL << 2)

static EFI_STATUS check_vmx(void)
{
	//CPUID[EAX=1] should have VMX feature == 1
	cpuid_params_t cpuid_params = {1, 0, 0, 0};
	uint64_t feature_msr;

	asm_cpuid(&cpuid_params);
	if ((cpuid_params.ecx & CPUID_ECX_VMX) == 0) {
		return EFI_UNSUPPORTED;
	}

	/* MSR_FEATURE_CONTROL should have
	 * either enable_vmx_outside_smx == 1 or
	 * Lock == 0 */

	feature_msr = asm_rdmsr(MSR_FEATURE_CONTROL);
	if (feature_msr & FEATURE_CONTROL_LOCK) {
		if((feature_msr & FEATURE_CONTROL_VMX_OUT_SMX) == 0)
			return EFI_UNSUPPORTED;
	} else {
		feature_msr |= FEATURE_CONTROL_VMX_OUT_SMX
			| FEATURE_CONTROL_LOCK;
		asm_wrmsr(MSR_FEATURE_CONTROL, feature_msr);
	}
	return EFI_SUCCESS;
}

static inline void save_current_cpu_state(gcpu_state_t *s)
{
	asm_sgdt(&(s->gdtr));
	asm_sidt(&(s->idtr));
	s->cr0 = asm_get_cr0();
	s->cr3 = asm_get_cr3();
	s->cr4 = asm_get_cr4();

	s->msr_efer = asm_rdmsr(MSR_EFER);

	/* The selector of LDTR in current environment is invalid which indicates
	 * the bootloader is not using LDTR. So set LDTR unusable here. In
	 * future, exception might occur if LDTR is used in bootloader. Then bootloader
	 * will find us since we changed LDTR to 0, and we can fix it for that bootloader. */
	fill_segment(&s->segment[SEG_LDTR], 0, 0, 0x10000, 0);
	/* TSS is used for RING switch, which is usually not used in bootloader since
	 * bootloader always runs in RING0. So we hardcode TR here. In future, #TS
	 * might occur if TSS is used bootloader. Then bootlaoder will find us since we
	 * changed TR to 0, and we can fix it for that bootlaoder. */
	fill_segment(&s->segment[SEG_TR], 0, 0xffffffff, 0x808b, 0);
	/* For segments: get selector from current environment, selector of ES/FS/GS are from DS,
	 * hardcode other fields to make guest launch successful. */
	fill_segment(&s->segment[SEG_CS], 0, 0xffffffff, 0xa09b, asm_get_cs());
	fill_segment(&s->segment[SEG_DS], 0, 0xffffffff, 0xc093, asm_get_ds());
	fill_segment(&s->segment[SEG_ES], 0, 0xffffffff, 0xc093, asm_get_ds());
	fill_segment(&s->segment[SEG_FS], 0, 0xffffffff, 0xc093, asm_get_ds());
	fill_segment(&s->segment[SEG_GS], 0, 0xffffffff, 0xc093, asm_get_ds());
	fill_segment(&s->segment[SEG_SS], 0, 0xffffffff, 0xc093, asm_get_ds());
}

static UINTN get_cpu_num(void)
{
	UINTN num_core, num_core_enabled;
	EFI_GUID mp_service_guid = EFI_MP_SERVICES_PROTOCOL_GUID;
	EFI_MP_SERVICES_PROTOCOL *mp;
	EFI_STATUS ret;

	ret = uefi_call_wrapper(gBS->LocateProtocol, 3, &mp_service_guid, NULL, (void **)&mp);
	if (ret != EFI_SUCCESS) {
		Print(L"Failed to locate MP services\n");
		return 0;
	}

	ret = uefi_call_wrapper(mp->GetNumberOfProcessors, 3, mp, &num_core, &num_core_enabled);
	if (ret != EFI_SUCCESS) {
		Print(L"Failed to get number of processors\n");
		return 0;
	}

	return num_core_enabled;
}

static EFI_STATUS enable_disable_aps(BOOLEAN enable)
{
	UINTN num_core, num_core_enabled;
	UINTN core_id;
	UINTN i;
	EFI_GUID mp_service_guid = EFI_MP_SERVICES_PROTOCOL_GUID;
	EFI_MP_SERVICES_PROTOCOL *mp;
	EFI_STATUS ret;

	ret = uefi_call_wrapper(gBS->LocateProtocol, 3, &mp_service_guid, NULL, (void **)&mp);
	if (ret != EFI_SUCCESS) {
		Print(L"Failed to locate MP services\n");
		return ret;
	}

	ret = uefi_call_wrapper(mp->GetNumberOfProcessors, 3, mp, &num_core, &num_core_enabled);
	if (ret != EFI_SUCCESS) {
		Print(L"Failed to get number of processors\n");
		return ret;
	}

	ret = uefi_call_wrapper(mp->WhoAmI, 2, mp, &core_id);
	if (ret != EFI_SUCCESS) {
		Print(L"Failed to get current processor's id\n");
		return ret;
	}

	for (i = 0; i < num_core_enabled; i++) {
		if (i == core_id)
			continue;

		ret = uefi_call_wrapper(mp->EnableDisableAP, 4, mp, i, enable, NULL);
		if (ret != EFI_SUCCESS) {
			Print(L"Failed to %s AP[%d]\n", enable ? L"enable" : L"disable", i);
			return ret;
		}
	}

	return EFI_SUCCESS;
}

static inline EFI_STATUS g0_gcpu_setup(evmm_desc_t *evmm_desc, uint64_t rip)
{
	save_current_cpu_state(&evmm_desc->guest0_gcpu0_state);

	evmm_desc->guest0_gcpu0_state.rip = rip;
	evmm_desc->guest0_gcpu0_state.rflags = asm_get_rflags();

	/*
	 * [RAX] is the return value when resume back to stage0,
	 * set it to 0 to inform stage0 trusty boot successfully.
	 */
	evmm_desc->guest0_gcpu0_state.gp_reg[REG_RAX] = 0;

	asm volatile ("movq %%rbx, %0" : "=r"(evmm_desc->guest0_gcpu0_state.gp_reg[REG_RBX]));
	asm volatile ("movq %%rcx, %0" : "=r"(evmm_desc->guest0_gcpu0_state.gp_reg[REG_RCX]));
	asm volatile ("movq %%rdx, %0" : "=r"(evmm_desc->guest0_gcpu0_state.gp_reg[REG_RDX]));
	asm volatile ("movq %%rsp, %0" : "=r"(evmm_desc->guest0_gcpu0_state.gp_reg[REG_RSP]));
	asm volatile ("movq %%rbp, %0" : "=r"(evmm_desc->guest0_gcpu0_state.gp_reg[REG_RBP]));
	asm volatile ("movq %%rsi, %0" : "=r"(evmm_desc->guest0_gcpu0_state.gp_reg[REG_RSI]));
	asm volatile ("movq %%rdi, %0" : "=r"(evmm_desc->guest0_gcpu0_state.gp_reg[REG_RDI]));
	asm volatile ("movq %%r8,  %0" : "=r"(evmm_desc->guest0_gcpu0_state.gp_reg[REG_R8]));
	asm volatile ("movq %%r9,  %0" : "=r"(evmm_desc->guest0_gcpu0_state.gp_reg[REG_R9]));
	asm volatile ("movq %%r10, %0" : "=r"(evmm_desc->guest0_gcpu0_state.gp_reg[REG_R10]));
	asm volatile ("movq %%r11, %0" : "=r"(evmm_desc->guest0_gcpu0_state.gp_reg[REG_R11]));
	asm volatile ("movq %%r12, %0" : "=r"(evmm_desc->guest0_gcpu0_state.gp_reg[REG_R12]));
	asm volatile ("movq %%r13, %0" : "=r"(evmm_desc->guest0_gcpu0_state.gp_reg[REG_R13]));
	asm volatile ("movq %%r14, %0" : "=r"(evmm_desc->guest0_gcpu0_state.gp_reg[REG_R14]));
	asm volatile ("movq %%r15, %0" : "=r"(evmm_desc->guest0_gcpu0_state.gp_reg[REG_R15]));

	return EFI_SUCCESS;
}

static uint64_t get_tom(void)
{
	UINTN mmap_size, map_key, desc_size;
	uint8_t temp_mmap[1];
	uint32_t desc_ver;
	uint64_t tom = 0;
	EFI_MEMORY_DESCRIPTOR *mmap_desc;
	EFI_MEMORY_DESCRIPTOR *mmap_desc_ptr;
	EFI_STATUS status;
	UINTN i;

	/* get mmap_size */
	mmap_size = sizeof(temp_mmap);
	status = uefi_call_wrapper(gBS->GetMemoryMap, 5, &mmap_size, &temp_mmap, &map_key, &desc_size, &desc_ver);
	if (status != EFI_BUFFER_TOO_SMALL) {
		Print(L"failed to get mmap_size\n");
		return 0;
	}

	/* allocate space for mmap */
	mmap_size += EFI_PAGE_SIZE;
	status = uefi_call_wrapper(gBS->AllocatePool, 3, EfiLoaderData, mmap_size, (void **)&mmap_desc);
	if (status != EFI_SUCCESS) {
		Print(L"failed to allocate memory!\n");
		return 0;
	}

	/* get mmap */
	status = uefi_call_wrapper(gBS->GetMemoryMap, 5, &mmap_size, mmap_desc, &map_key, &desc_size, &desc_ver);
	if (status != EFI_SUCCESS) {
		Print(L"failed to get mem map!\n");
		return 0;
	}

	mmap_desc_ptr = mmap_desc;
	for (i = 0; i < mmap_size/desc_size; i++) {
		if (tom < mmap_desc_ptr->PhysicalStart + mmap_desc_ptr->NumberOfPages * EFI_PAGE_SIZE) {
			tom = mmap_desc_ptr->PhysicalStart + mmap_desc_ptr->NumberOfPages * EFI_PAGE_SIZE;
		}

		mmap_desc_ptr = (EFI_MEMORY_DESCRIPTOR *)(((UINTN)mmap_desc_ptr) + desc_size);
	}

	Print(L"top of memory=0x%lx\n", tom);

	return tom;
}

static uint64_t get_tsc_per_ms(void)
{
	uint64_t start, end;

	start = asm_rdtsc();
	uefi_call_wrapper(gBS->Stall, 1, 1000);
	end = asm_rdtsc();

	return (end - start);
}

static EFI_STATUS continue_boot(EFI_LOADED_IMAGE *image, EFI_HANDLE image_handle)
{
	EFI_STATUS status;
	EFI_DEVICE_PATH_PROTOCOL *path;
	EFI_HANDLE boot_handle;
	CHAR16 *path_str = L"\\EFI\\BOOT\\BOOTX64.efi";

	path = FileDevicePath(image->DeviceHandle, path_str);
	if (path == NULL) {
		Print(L"Failed to set path!\n");
		return EFI_DEVICE_ERROR;
	}

	status = uefi_call_wrapper(gBS->LoadImage, 6, FALSE, image_handle, path, NULL, 0, &boot_handle);
	if (status != EFI_SUCCESS) {
		Print(L"failed to load image\n");
		return EFI_LOAD_ERROR;
	}

	UINTN exit_data_size;
	status = uefi_call_wrapper(gBS->StartImage, 3, boot_handle, &exit_data_size, (CHAR16 **)NULL);
	if (status != EFI_SUCCESS) {
		Print(L"Failed to start bootloader(%r)\n", status);
		return status;
	}

	return EFI_SUCCESS;
}

static void make_dummy_dev_sec_info(void *info)
{
	device_sec_info_v0_t *device_sec_info = (device_sec_info_v0_t *)info;

	ZeroMem(device_sec_info, sizeof(device_sec_info_v0_t));

	device_sec_info->size_of_this_struct = sizeof(device_sec_info_v0_t);
	device_sec_info->version = 0;
	device_sec_info->platform = 0;
	device_sec_info->num_seeds = 1;
}

/* Temp STACK for stage1 to launch APs */
#define AP_TEMP_STACK_SIZE            (0x400U * ((MAX_CPU_NUM) + 1U))
#define STAGE1_RT_SIZE                (0xA000U + (AP_TEMP_STACK_SIZE))

#define EVMM_RUNTIME_SIZE 0x1000000U
#define TEE_RUNTIME_SIZE  0x1000000U

extern const uint64_t return_address;
EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *_table)
{
	EFI_STATUS status;
	EFI_LOADED_IMAGE *info;
	evmm_desc_t *evmm_desc;
	uint64_t mem_addr;
	UINTN sec_vma, sec_len;
	uint64_t (*stage1_main) (evmm_desc_t *xd) = NULL;

	InitializeLib(image, _table);

	Print(L"Enter efi stage0 loader\n");
	if (CheckCrc(_table->Hdr.HeaderSize, &_table->Hdr) != TRUE) {
		Print(L"Stage0 Load Error\n");
		return EFI_LOAD_ERROR;
	}

	if (EFI_SUCCESS != check_vmx()) {
		Print(L"VT-x is not supported!\n");
		return EFI_UNSUPPORTED;
	}

	/* Allocate memory for evmm_desc */
	status = uefi_call_wrapper(gBS->AllocatePages, 4, AllocateAnyPages, EfiLoaderData, EFI_SIZE_TO_PAGES(sizeof(evmm_desc_t)), &mem_addr);
	if (status != EFI_SUCCESS) {
		Print(L"allocate memory for loader failed!, error=%d\n", status);
		return status;
	}
	evmm_desc = (evmm_desc_t *)mem_addr;
	ZeroMem(evmm_desc, sizeof(evmm_desc_t));

	/* get image handle */
	status = uefi_call_wrapper(gBS->HandleProtocol, 3, image, &LoadedImageProtocol, (void **)&info);
	if (status != EFI_SUCCESS) {
		Print(L"handle image protocol failed! error=%d\n", status);
		return status;
	}

	/* get stage1 */
	if (!parse_pe_section(info->ImageBase, ".stage1", 7, &sec_vma, &sec_len)) {
		Print(L"Failed to parse stage1\n");
		return EFI_LOAD_ERROR;
	}
	evmm_desc->stage1_file.loadtime_addr = ((UINTN)(info->ImageBase)) + sec_vma;
	evmm_desc->stage1_file.loadtime_size = sec_len;

	status = uefi_call_wrapper(gBS->AllocatePages, 4, AllocateAnyPages, EfiLoaderCode, EFI_SIZE_TO_PAGES(STAGE1_RT_SIZE), &mem_addr);
	if (status != EFI_SUCCESS) {
		Print(L"allocate memory for loader failed!, error=%d\n", status);
		return status;
	}
	evmm_desc->stage1_file.runtime_addr = mem_addr;
	evmm_desc->stage1_file.runtime_total_size = STAGE1_RT_SIZE;

	/* get evmm */
	if (!parse_pe_section(info->ImageBase, ".evmm", 5, &sec_vma, &sec_len)) {
		Print(L"Failed to parse evmm\n");
		return EFI_LOAD_ERROR;
	}
	evmm_desc->evmm_file.loadtime_addr = ((UINTN)(info->ImageBase)) + sec_vma;
	evmm_desc->evmm_file.loadtime_size = sec_len;

	status = uefi_call_wrapper(gBS->AllocatePages, 4, AllocateAnyPages, EfiReservedMemoryType, EFI_SIZE_TO_PAGES(EVMM_RUNTIME_SIZE), &mem_addr);
	if (status != EFI_SUCCESS) {
		Print(L"allocate memory for evmm failed!, error=%r\n", status);
		return status;
	}
	evmm_desc->evmm_file.runtime_addr = mem_addr;
	evmm_desc->evmm_file.runtime_total_size = EVMM_RUNTIME_SIZE;

	/* get sipi page */
	mem_addr = 1U * 1024U * 1024U;  // less than 1MB
#ifdef MODULE_SUSPEND
	status = uefi_call_wrapper(gBS->AllocatePages, 4, AllocateMaxAddress, EfiReservedMemoryType, 1, &mem_addr);
#else
	status = uefi_call_wrapper(gBS->AllocatePages, 4, AllocateMaxAddress, EfiLoaderCode, 1, &mem_addr);
#endif
	if (status != EFI_SUCCESS) {
		Print(L"allocate memory for SIPI page failed!, error=%r\n", status);
		return status;
	}
	evmm_desc->sipi_ap_wkup_addr = mem_addr;

#ifdef MODULE_TRUSTY_TEE
	/* get lk */
	if (!parse_pe_section(info->ImageBase, ".lk", 3, &sec_vma, &sec_len)) {
		Print(L"Failed to parse lk\n");
		return EFI_LOAD_ERROR;
	}
	evmm_desc->trusty_tee_desc.tee_file.loadtime_addr = ((UINTN)(info->ImageBase)) + sec_vma;
	evmm_desc->trusty_tee_desc.tee_file.loadtime_size = sec_len;

	status = uefi_call_wrapper(gBS->AllocatePages, 4, AllocateAnyPages, EfiReservedMemoryType, EFI_SIZE_TO_PAGES(TEE_RUNTIME_SIZE), &mem_addr);
	if (status != EFI_SUCCESS) {
		Print(L"allocate memory for lk failed!, error=%d\n", status);
		return status;
	}
	evmm_desc->trusty_tee_desc.tee_file.runtime_addr = mem_addr;
	evmm_desc->trusty_tee_desc.tee_file.runtime_total_size = TEE_RUNTIME_SIZE;

	/*  */
	status = uefi_call_wrapper(gBS->AllocatePages, 4, AllocateAnyPages, EfiLoaderData, EFI_SIZE_TO_PAGES(sizeof(device_sec_info_v0_t)), &mem_addr);
	if (status != EFI_SUCCESS) {
		Print(L"allocate memory for device sec info failed!, error=%d\n", status);
		return status;
	}
	evmm_desc->trusty_tee_desc.dev_sec_info = (void *)mem_addr;
	make_dummy_dev_sec_info(evmm_desc->trusty_tee_desc.dev_sec_info);
#endif

	/* others */
	evmm_desc->tsc_per_ms = get_tsc_per_ms();
	evmm_desc->num_of_cpu = get_cpu_num();
	if (evmm_desc->num_of_cpu == 0) {
		Print(L"Failed to get cpu number!\n");
		return EFI_LOAD_ERROR;
	}

	evmm_desc->top_of_mem = get_tom();
	if (evmm_desc->top_of_mem == 0) {
		Print(L"Failed to get top of memory!\n");
		return EFI_LOAD_ERROR;
	}

	if (!relocate_elf_image(evmm_desc->stage1_file.loadtime_addr,
				evmm_desc->stage1_file.loadtime_size,
				evmm_desc->stage1_file.runtime_addr,
				evmm_desc->stage1_file.runtime_total_size,
				(uint64_t *)&stage1_main)) {
		Print(L"relocate stage1 failed!\n");
	}
	Print(L"Jump to stage1(entry=0x%lx)\n", (UINTN)stage1_main);

	/* Disable APs in BIOS */
	status = enable_disable_aps(FALSE);
	if (status != EFI_SUCCESS) {
		Print(L"Failed to disable APs\n");
		return status;
	}

	if(stage1_main) {
		g0_gcpu_setup(evmm_desc, (uint64_t)&return_address);
		asm volatile("cli");
		stage1_main(evmm_desc);
		return EFI_ABORTED;
	}

	asm volatile (".global return_address \n\t"
		      "return_address: \n\t"
	);

	Print(L"EVMM launched successfully!\n");

	/* Enable APs in BIOS */
	status = enable_disable_aps(TRUE);
	if (status != EFI_SUCCESS) {
		Print(L"Failed to enable APs\n");
		return status;
	}

	continue_boot(info, image);

	return status;
}
