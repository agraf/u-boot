/*
 *  EFI application loader
 *
 *  Copyright (c) 2016 Alexander Graf
 *
 *  SPDX-License-Identifier:     GPL-2.0+
 */

#include <common.h>
#include <part_efi.h>
#include <efi_api.h>

#ifdef CONFIG_EFI_LOADER

#include <linux/list.h>

/* #define DEBUG_EFI */

#ifdef DEBUG_EFI
#define EFI_ENTRY(format, ...) do { \
	efi_restore_gd(); \
	printf("EFI: Entry %s(" format ")\n", __func__, ##__VA_ARGS__); \
	} while(0)
#else
#define EFI_ENTRY(format, ...) do { \
	efi_restore_gd(); \
	} while(0)
#endif

#define EFI_EXIT(ret) efi_exit_func(ret);

extern struct efi_system_table systab;

extern const struct efi_simple_text_output_protocol efi_con_out;
extern const struct efi_simple_input_interface efi_con_in;
extern const struct efi_console_control_protocol efi_console_control;

extern const efi_guid_t efi_guid_console_control;
extern const efi_guid_t efi_guid_device_path;
extern const efi_guid_t efi_guid_loaded_image;

struct efi_class_map {
	const efi_guid_t *guid;
	const void *interface;
};

struct efi_handler {
	const efi_guid_t *guid;
	efi_status_t (EFIAPI *open)(void *handle,
			efi_guid_t *protocol, void **protocol_interface,
			void *agent_handle, void *controller_handle,
			uint32_t attributes);
};

struct efi_object {
	struct list_head link;
	struct efi_handler protocols[4];
	void *handle;
};
extern struct list_head efi_obj_list;

efi_status_t efi_return_handle(void *handle,
		efi_guid_t *protocol, void **protocol_interface,
		void *agent_handle, void *controller_handle,
		uint32_t attributes);
void efi_timer_check(void);
void *efi_load_pe(void *efi, struct efi_loaded_image *loaded_image_info);
void efi_save_gd(void);
void efi_restore_gd(void);
efi_status_t efi_exit_func(efi_status_t ret);

#define EFI_LOADER_POOL_SIZE (128 * 1024 * 1024)
void *efi_loader_alloc(uint64_t len);

#else /* defined(EFI_LOADER) */

static inline void efi_restore_gd(void) { }

#endif
