/*
 *  EFI application runtime services
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

#include <common.h>
#include <efi_loader.h>

/*
 * EFI Runtime code is still alive when U-Boot is long overwritten. To isolate
 * this code from the rest, we put it into a special section.
 *
 *        !!WARNING!!
 *
 * This means that we can not rely on any code outside of this file at runtime.
 * Please keep it fully self-contained.
 */
asm(".section efi_runtime,\"a\"");

static efi_status_t efi_unimplemented(void)
{
	return EFI_UNSUPPORTED;
}

const struct efi_runtime_services efi_runtime_services = {
	.hdr = {
		.signature = EFI_RUNTIME_SERVICES_SIGNATURE,
		.revision = EFI_RUNTIME_SERVICES_REVISION,
		.headersize = sizeof(struct efi_table_hdr),
	},
	.get_time = (void *)&efi_unimplemented,
	.set_time = (void *)&efi_unimplemented,
	.get_wakeup_time = (void *)&efi_unimplemented,
	.set_wakeup_time = (void *)&efi_unimplemented,
	.set_virtual_address_map = (void *)&efi_unimplemented,
	.convert_pointer = (void *)&efi_unimplemented,
	.get_variable = (void *)&efi_unimplemented,
	.get_next_variable = (void *)&efi_unimplemented,
	.set_variable = (void *)&efi_unimplemented,
	.get_next_high_mono_count = (void *)&efi_unimplemented,
	.reset_system = (void *)&efi_unimplemented,
};
