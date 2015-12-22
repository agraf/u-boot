/*
 *  EFI application loader
 *
 *  Copyright (c) 2015 Alexander Graf
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 *  SPDX-License-Identifier:     LGPL-2.1+
 */

#include <part_efi.h>
#include <efi_api.h>
#include <linux/list.h>

extern const efi_guid_t efi_guid_device_path;
extern const efi_guid_t efi_guid_loaded_image;

efi_status_t efi_return_handle(void *handle,
		efi_guid_t *protocol, void **protocol_interface,
		void *agent_handle, void *controller_handle,
		uint32_t attributes);
void *efi_load_pe(void *efi, struct efi_loaded_image *loaded_image_info);

#define EFI_LOADER_POOL_SIZE (128 * 1024 * 1024)
void *efi_loader_alloc(uint64_t len);
