#
# (C) Copyright 2015 Alexander Graf
#
#  SPDX-License-Identifier:     LGPL-2.1+
#

# This file only gets included with CONFIG_EFI_LOADER set, so all
# object inclusion implicitly depends on it

obj-y += efi_image_loader.o efi_boottime.o efi_runtime.o efi_console.o
obj-$(CONFIG_PARTITIONS) += efi_disk.o
