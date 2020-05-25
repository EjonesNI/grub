/* linux.h - ARM linux specific definitions */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2012  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GRUB_LINUX_CPU_HEADER
#define GRUB_LINUX_CPU_HEADER 1

#define LINUX_ZIMAGE_OFFSET 0x24
#define LINUX_ZIMAGE_MAGIC  0x016f2818

#if defined GRUB_MACHINE_UBOOT
#include <grub/uboot/uboot.h>
#define LINUX_ADDRESS        (start_of_ram + 0x8000)
#define LINUX_INITRD_ADDRESS (start_of_ram + 0x02000000)
#define LINUX_FDT_ADDRESS    (LINUX_INITRD_ADDRESS - 0x10000)
#define firmware_get_boot_data uboot_get_boot_data
#define firmware_get_machine_type uboot_get_machine_type
#endif

#define FDT_ADDITIONAL_ENTRIES_SIZE	0x300

typedef void (*kernel_entry_t) (int, unsigned long, void *);

#endif /* ! GRUB_LINUX_CPU_HEADER */
