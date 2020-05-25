/* dl.c - arch-dependent part of loadable module support */
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

#include <grub/dl.h>
#include <grub/elf.h>
#include <grub/misc.h>
#include <grub/err.h>
#include <grub/mm.h>
#include <grub/i18n.h>

#if !defined(__thumb2__)
#error "Relocations not implemented for A32 ("ARM") instruction set yet!"
#endif

#ifdef DL_DEBUG
static const char *symstrtab;

/*
 * This is a bit of a hack, setting the symstrtab pointer to the last STRTAB
 * section in the module (which is where symbol names are in the objects I've
 * inspected manually). 
 */
static void
set_symstrtab (Elf_Ehdr * e)
{
  int i;
  Elf_Shdr *s;

  symstrtab = NULL;

  for (i = 0, s = (Elf_Shdr *) ((grub_uint32_t) e + e->e_shoff);
       i < e->e_shnum;
       i++, s = (Elf_Shdr *) ((grub_uint32_t) s + e->e_shentsize))
    if (s->sh_type == SHT_STRTAB)
      symstrtab = (void *) ((grub_addr_t) e + s->sh_offset);
}

static const char *
get_symbolname (Elf_Sym * sym)
{
  const char *symbolname = symstrtab + sym->st_name;

  return (*symbolname ? symbolname : NULL);
}
#endif /* DL_DEBUG */


/*
 * Simple relocation of 32-bit value (in literal pool)
 */
static grub_err_t
reloc_abs32 (Elf_Word * addr, Elf_Sym * sym)
{
#ifdef DL_DEBUG
  grub_printf ("%s: ABS32 @ 0x%08x -> %s @ 0x%08x\n",
	       __FUNCTION__, (grub_addr_t) addr,
	       get_symbolname (sym), sym->st_value);
#endif

  *addr += sym->st_value;

  return GRUB_ERR_NONE;
}

/*
 * R_ARM_THM_CALL/THM_JUMP24
 *
 * Deals with relocation of Thumb (T32) instruction set relative branches
 * B.W, BL and BLX
 *
 * 32-bit Thumb instructions can be 16-bit aligned, and are fetched
 * little-endian, requiring some additional fiddling.
 */
static grub_err_t
reloc_thm_call (grub_uint16_t * addr, Elf_Sym * sym)
{
  grub_int32_t offset, offset_low, offset_high;
  grub_uint32_t sign, j1, j2, is_blx;
  grub_uint32_t insword, insmask;

  /* Extract instruction word in alignment-safe manner */
  insword = (*addr << 16) | *(addr + 1);
  insmask = 0xf800d000;

  /* B.W/BL or BLX? Affects range and expected target state */
  if (((insword >> 12) & 0xd) == 0xc)
    is_blx = 1;
  else
    is_blx = 0;

  offset_low = -16777216;
  offset_high = is_blx ? 16777212 : 16777214;

#ifdef DL_DEBUG
  grub_printf ("%s: %s @ 0x%08x -> %s @ 0x%08x\n",
	       __FUNCTION__, is_blx ? "BLX" : "B(L)",
	       (grub_addr_t) addr, get_symbolname (sym), sym->st_value);
#endif

  /* Extract bitfields from instruction words */
  sign = (insword >> 26) & 1;
  j1 = (insword >> 13) & 1;
  j2 = (insword >> 11) & 1;
  offset = (sign << 24) | ((~(j1 ^ sign) & 1) << 23) |
    ((~(j2 ^ sign) & 1) << 22) |
    ((insword & 0x03ff0000) >> 4) | ((insword & 0x000007ff) << 1);

  /* Sign adjust and calculate offset */
  if (offset & 0x01000000)
    offset -= 0x02000000;
  offset += sym->st_value - (grub_uint32_t) addr;

  if ((offset < offset_low) || (offset > offset_high))
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
		       N_("offset %d (0x%08x) is out of range"),
		       offset, offset);

  /* If BLX, target symbol must be ARM (target address LSB == 0) */
  if (is_blx && (offset & 1))
    return grub_error
      (GRUB_ERR_BUG, N_("Relocation targeting wrong execution state"));

  /* Reassemble instruction word */
  sign = (offset >> 24) & 1;
  j1 = sign ^ (~(offset >> 23) & 1);
  j2 = sign ^ (~(offset >> 22) & 1);
  insword = (insword & insmask) |
    (sign << 26) |
    (((offset >> 12) & 0x03ff) << 16) |
    (j1 << 13) | (j2 << 11) | ((offset >> 1) & 0x07ff);

  /* Write instruction word back in alignment-safe manner */
  *(grub_uint16_t *) addr = (insword >> 16) & 0xffff;
  *(grub_uint16_t *) (addr + 1) = insword & 0xffff;

  return GRUB_ERR_NONE;
}

/*
 * find_segment(): finds a module segment matching sh_info
 */
static grub_dl_segment_t
find_segment (grub_dl_segment_t seg, Elf32_Word sh_info)
{
  for (; seg; seg = seg->next)
    if (seg->section == sh_info)
      return seg;

  return NULL;
}

/*
 * do_relocations():
 *   Iterate over all relocations in section, calling appropriate functions
 *   for patching.
 */
static grub_err_t
do_relocations (Elf_Shdr * relhdr, Elf_Ehdr * e, grub_dl_t mod)
{
  grub_dl_segment_t seg;
  Elf_Rel *rel;
  Elf_Sym *sym;
  int i, entnum;

  entnum = relhdr->sh_size / sizeof (Elf_Rel);

  /* Find the target segment for this relocation section. */
  seg = find_segment (mod->segment, relhdr->sh_info);
  if (!seg)
    return grub_error (GRUB_ERR_EOF, N_("relocation segment not found"));

  rel = (Elf_Rel *) ((grub_addr_t) e + relhdr->sh_offset);

  /* Step through all relocations */
  for (i = 0, sym = mod->symtab; i < entnum; i++)
    {
      Elf_Word *addr;
      int relsym, reltype;
      grub_err_t retval;

      if (seg->size < rel[i].r_offset)
	return grub_error (GRUB_ERR_BAD_MODULE,
			   "reloc offset is out of the segment");
      relsym = ELF_R_SYM (rel[i].r_info);
      reltype = ELF_R_TYPE (rel[i].r_info);
      addr = (Elf_Word *) ((grub_addr_t) seg->addr + rel[i].r_offset);

      switch (reltype)
	{
	case R_ARM_ABS32:
	  {
	    /* Data will be naturally aligned */
	    retval = reloc_abs32 (addr, &sym[relsym]);
	    if (retval != GRUB_ERR_NONE)
	      return retval;
	  }
	  break;
	case R_ARM_THM_CALL:
	case R_ARM_THM_JUMP24:
	  {
	    /* Thumb instructions can be 16-bit aligned */
	    retval = reloc_thm_call ((grub_uint16_t *) addr, &sym[relsym]);
	    if (retval != GRUB_ERR_NONE)
	      return retval;
	  }
	  break;
	default:
	  return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
			     N_("relocation 0x%x is not implemented yet"),
			     reltype);
	}
    }

  return GRUB_ERR_NONE;
}


/*
 * Check if EHDR is a valid ELF header.
 */
grub_err_t
grub_arch_dl_check_header (void *ehdr)
{
  Elf_Ehdr *e = ehdr;

  /* Check the magic numbers.  */
  if (e->e_ident[EI_CLASS] != ELFCLASS32
      || e->e_ident[EI_DATA] != ELFDATA2LSB || e->e_machine != EM_ARM)
    return grub_error (GRUB_ERR_BAD_OS,
		       N_("invalid arch-dependent ELF magic"));

  return GRUB_ERR_NONE;
}

/*
 * Verify that provided ELF header contains reference to a symbol table
 */
static int
has_symtab (Elf_Ehdr * e)
{
  int i;
  Elf_Shdr *s;

  for (i = 0, s = (Elf_Shdr *) ((grub_uint32_t) e + e->e_shoff);
       i < e->e_shnum;
       i++, s = (Elf_Shdr *) ((grub_uint32_t) s + e->e_shentsize))
    if (s->sh_type == SHT_SYMTAB)
      return 1;

  return 0;
}

/*
 * grub_arch_dl_relocate_symbols():
 *   Only externally visible function in this file.
 *   Locates the relocations section of the ELF object, and calls
 *   do_relocations() to deal with it.
 */
grub_err_t
grub_arch_dl_relocate_symbols (grub_dl_t mod, void *ehdr)
{
  Elf_Ehdr *e = ehdr;
  Elf_Shdr *s;
  unsigned i;

  if (!has_symtab (e))
    return grub_error (GRUB_ERR_BAD_MODULE, N_("no symbol table"));

#ifdef DL_DEBUG
  set_symstrtab (e);
#endif

#define FIRST_SHDR(x) ((Elf_Shdr *) ((grub_addr_t)(x) + (x)->e_shoff))
#define NEXT_SHDR(x, y) ((Elf_Shdr *) ((grub_addr_t)(y) + (x)->e_shentsize))

  for (i = 0, s = FIRST_SHDR (e); i < e->e_shnum; i++, s = NEXT_SHDR (e, s))
    {
      grub_err_t ret;

      switch (s->sh_type)
	{
	case SHT_REL:
	  {
	    /* Relocations, no addends */
	    ret = do_relocations (s, e, mod);
	    if (ret != GRUB_ERR_NONE)
	      return ret;
	  }
	  break;
	case SHT_NULL:
	case SHT_PROGBITS:
	case SHT_SYMTAB:
	case SHT_STRTAB:
	case SHT_NOBITS:
	case SHT_ARM_ATTRIBUTES:
	  break;
	case SHT_RELA:
	default:
	  {
	    grub_printf ("unhandled section_type: %d (0x%08x)\n",
			 s->sh_type, s->sh_type);
	    return GRUB_ERR_NOT_IMPLEMENTED_YET;
	  };
	}
    }

#undef FIRST_SHDR
#undef NEXT_SHDR

  return GRUB_ERR_NONE;
}
