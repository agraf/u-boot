/*
 *  EFI application disk support
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
#include <part.h>
#include <malloc.h>
#include <inttypes.h>

static const efi_guid_t efi_block_io_guid = BLOCK_IO_GUID;

struct efi_disk_obj {
	struct efi_object parent;
	struct efi_block_io ops;
	const char *ifname;
	int dev_index;
	struct efi_block_io_media media;
	struct efi_device_path_file_path *dp;
};

static void ascii2unicode(u16 *unicode, char *ascii)
{
	while (*ascii)
		*(unicode++) = *(ascii++);
}

static efi_status_t efi_disk_open_block(void *handle, efi_guid_t *protocol,
			void **protocol_interface, void *agent_handle,
			void *controller_handle, uint32_t attributes)
{
	struct efi_disk_obj *diskobj = handle;

	*protocol_interface = &diskobj->ops;

	return EFI_SUCCESS;
}

static efi_status_t efi_disk_open_dp(void *handle, efi_guid_t *protocol,
			void **protocol_interface, void *agent_handle,
			void *controller_handle, uint32_t attributes)
{
	struct efi_disk_obj *diskobj = handle;

	*protocol_interface = diskobj->dp;

	return EFI_SUCCESS;
}

static efi_status_t efi_disk_reset(struct efi_block_io *this,
			char extended_verification)
{
	EFI_ENTRY("%p, %x", this, extended_verification);
	return EFI_EXIT(EFI_DEVICE_ERROR);
}

enum efi_disk_direction {
	EFI_DISK_READ,
	EFI_DISK_WRITE,
};

static efi_status_t efi_disk_rw_blocks(struct efi_block_io *this,
			u32 media_id, u64 lba, unsigned long buffer_size,
			void *buffer, enum efi_disk_direction direction)
{
	struct efi_disk_obj *diskobj;
	struct block_dev_desc *desc;
	int blksz;
	int blocks;
	unsigned long n;

	EFI_ENTRY("%p, %x, %"PRIx64", %lx, %p", this, media_id, lba,
		  buffer_size, buffer);

	diskobj = container_of(this, struct efi_disk_obj, ops);
	if (!(desc = get_dev(diskobj->ifname, diskobj->dev_index)))
		return EFI_EXIT(EFI_DEVICE_ERROR);
	blksz = desc->blksz;
	blocks = buffer_size / blksz;

#ifdef DEBUG_EFI
	printf("EFI: %s:%d blocks=%x lba=%"PRIx64" blksz=%x dir=%d\n", __func__,
	       __LINE__, blocks, lba, blksz, direction);
#endif

	/* We only support full block access */
	if (buffer_size & (blksz - 1))
		return EFI_EXIT(EFI_DEVICE_ERROR);

	if (direction == EFI_DISK_READ)
		n = desc->block_read(desc->dev, lba, blocks, buffer);
	else
		n = desc->block_write(desc->dev, lba, blocks, buffer);

	/* We don't do interrupts, so check for timers cooperatively */
	efi_timer_check();

#ifdef DEBUG_EFI
	printf("EFI: %s:%d n=%lx blocks=%x\n", __func__, __LINE__, n, blocks);
#endif
	if (n != blocks)
		return EFI_EXIT(EFI_DEVICE_ERROR);

	return EFI_EXIT(EFI_SUCCESS);
}

static efi_status_t efi_disk_read_blocks(struct efi_block_io *this,
			u32 media_id, u64 lba, unsigned long buffer_size,
			void *buffer)
{
	return efi_disk_rw_blocks(this, media_id, lba, buffer_size, buffer,
				  EFI_DISK_READ);
}

static efi_status_t efi_disk_write_blocks(struct efi_block_io *this,
			u32 media_id, u64 lba, unsigned long buffer_size,
			void *buffer)
{
	return efi_disk_rw_blocks(this, media_id, lba, buffer_size, buffer,
				  EFI_DISK_WRITE);
}

static efi_status_t efi_disk_flush_blocks(struct efi_block_io *this)
{
	/* We always write synchronously */
	return EFI_SUCCESS;
}

static const struct efi_block_io block_io_disk_template = {
	.reset = &efi_disk_reset,
	.read_blocks = &efi_disk_read_blocks,
	.write_blocks = &efi_disk_write_blocks,
	.flush_blocks = &efi_disk_flush_blocks,
};

/*
 * U-Boot doesn't have a list of all online disk devices. So when running our
 * EFI payload, we scan through all of the potentially available ones and
 * store them in our object pool.
 *
 * This gets called from do_bootefi_exec().
 */
int efi_disk_register(void)
{
	const char **cur_drvr;
	int i;
	int disks = 0;

	/* Search for all available disk devices */
	for (cur_drvr = available_block_drvrs; *cur_drvr; cur_drvr++) {
		printf("Scanning disks on %s...\n", *cur_drvr);
		for (i = 0; i < 4; i++) {
			block_dev_desc_t *desc;
			struct efi_disk_obj *diskobj;
			struct efi_device_path_file_path *dp;
			int objlen = sizeof(*diskobj) + (sizeof(*dp) * 2);
			char devname[16];

			desc = get_dev(*cur_drvr, i);
			if (!desc)
				continue;

			diskobj = malloc(objlen);
			memset(diskobj, 0, objlen);

			/* Fill in object data */

			diskobj->parent.protocols[0].guid = &efi_block_io_guid;
			diskobj->parent.protocols[0].open = efi_disk_open_block;
			diskobj->parent.protocols[1].guid = &efi_guid_device_path;
			diskobj->parent.protocols[1].open = efi_disk_open_dp;
			diskobj->parent.handle = diskobj;
			diskobj->ops = block_io_disk_template;
			diskobj->ifname = *cur_drvr;
			diskobj->dev_index = i;

			/* Fill in EFI IO Media info (for read/write callbacks) */

			diskobj->media.removable_media = desc->removable;
			diskobj->media.media_present = 1;
			diskobj->media.block_size = desc->blksz;
			diskobj->media.io_align = desc->blksz;
			diskobj->media.last_block = desc->lba;
			diskobj->ops.media = &diskobj->media;

			/* Fill in device path */

			dp = (void*)&diskobj[1];
			diskobj->dp = dp;
			dp[0].dp.type = DEVICE_PATH_TYPE_MEDIA_DEVICE;
			dp[0].dp.sub_type = DEVICE_PATH_SUB_TYPE_FILE_PATH;
			dp[0].dp.length = sizeof(*dp);
			sprintf(devname, "%s%d", *cur_drvr, i);
			ascii2unicode(dp[0].str, devname);

			dp[1].dp.type = DEVICE_PATH_TYPE_END;
			dp[1].dp.sub_type = DEVICE_PATH_SUB_TYPE_END;
			dp[1].dp.length = sizeof(*dp);

			/* Hook up to the device list */

			list_add_tail(&diskobj->parent.link, &efi_obj_list);
			disks++;
		}
	}
	printf("Found %d disks\n", disks);

	return 0;
}
