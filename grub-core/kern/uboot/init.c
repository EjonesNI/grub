/* init.c - generic U-Boot initialization and finalization */
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


#include <grub/env.h>
#include <grub/kernel.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/term.h>
#include <grub/time.h>
#include <grub/machine/kernel.h>
#include <grub/uboot/console.h>
#include <grub/uboot/disk.h>
#include <grub/uboot/uboot.h>

extern char __bss_start[];
extern char _end[];
extern grub_size_t grub_total_module_size;
extern int (*uboot_syscall_ptr) (int, int *, ...);

grub_addr_t grub_modbase;

grub_uint32_t uboot_machine_type;
grub_addr_t uboot_boot_data;

static unsigned long timer_start;

void
grub_exit (void)
{
  uboot_return (0);
}

grub_uint32_t
uboot_get_machine_type (void)
{
  return uboot_machine_type;
}

grub_addr_t
uboot_get_boot_data (void)
{
  return uboot_boot_data;
}

static grub_uint64_t
uboot_timer_ms (void)
{
  return (grub_uint64_t) uboot_get_timer (timer_start);
}

void
grub_machine_init (void)
{
  grub_addr_t end;
  int ver;

  /* First of all - establish connection with U-Boot */
  ver = uboot_api_init ();
  if (!ver)
    {
      /* Don't even have a console to log errors to... */
      grub_exit ();
    }
  else if (ver > API_SIG_VERSION)
    {
      /* Try to print an error message */
      uboot_puts ("invalid U-Boot API version\n");
    }

  /*
   * Modules were relocated to _end, or __bss_start + grub_total_module_size,
   * whichever greater.
   */
  end = (grub_addr_t) __bss_start + grub_total_module_size;
  if (end < (grub_addr_t) _end)
    end = (grub_addr_t) _end;
  grub_modbase = end;

  /* Initialize the console so that GRUB can display messages.  */
  grub_console_init_early ();

  grub_dprintf ("init", "__bss_start: 0x%08x, end: 0x%08x, _end: 0x%08x\n",
		(grub_addr_t) __bss_start,
		(grub_addr_t) __bss_start + grub_total_module_size,
		(grub_addr_t) _end);
  grub_dprintf ("init", "grub_modbase: %p\n", (void *) grub_modbase);
  grub_dprintf ("init", "grub_modules_get_end(): %p\n",
		(void *) grub_modules_get_end ());

  /* Enumerate memory and initialize the memory management system. */
  grub_uboot_mm_init ();

  /* Initialise full terminfo support */
  grub_console_init_lately ();

  /* Enumerate uboot devices */
  grub_uboot_probe_hardware ();

  /* Initialise timer */
  timer_start = uboot_get_timer (0);
  grub_install_get_time_ms (uboot_timer_ms);

  /* Initialize  */
  grub_ubootdisk_init ();
}


void
grub_machine_fini (void)
{
}

/*
 * grub_machine_get_bootlocation():
 *   Called from kern/main.c, which expects a device name (minus parentheses)
 *   and a filesystem path back, if any are known.
 *   Any returned values must be pointers to dynamically allocated strings.
 */
void
grub_machine_get_bootlocation (char **device, char **path)
{
  char *tmp;

  tmp = uboot_env_get ("grub_bootdev");
  if (tmp)
    {
      *device = grub_malloc (grub_strlen (tmp) + 1);
      if (*device == NULL)
	return;
      grub_strncpy (*device, tmp, grub_strlen (tmp) + 1);
    }
  else
    *device = NULL;

  tmp = uboot_env_get ("grub_bootpath");
  if (tmp)
    {
      *path = grub_malloc (grub_strlen (tmp) + 1);
      if (*path == NULL)
	return;
      grub_strncpy (*path, tmp, grub_strlen (tmp) + 1);
    }
  else
    *path = NULL;
}

void
grub_uboot_fini (void)
{
  grub_ubootdisk_fini ();
  grub_console_fini ();
}
