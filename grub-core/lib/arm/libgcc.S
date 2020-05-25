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

#include <grub/symbol.h>
#include <grub/dl.h>

	.file	"libgcc.S"
	.syntax	unified
#if !defined (__thumb2__)
	.arm
#define ARM(x...)	x
#define THUMB(x...)
#else
	.thumb
#define THUMB(x...)	x
#define ARM(x...)
#endif

	
#ifdef __ARMEB__
#define al r1
#define ah r0
#else
#define al r0
#define ah r1
#endif

GRUB_MOD_LICENSE "GPLv3+"

/*
 *  helper functions - __aeabi* with macros imported from Linux kernel:
 *    linux/arch/arm/lib/lib1funcs.S
 *    linux/arch/arm/lib/ashldi3.S
 *    linux/arch/arm/lib/ashrdi3.S
 *    linux/arch/arm/lib/lshrdi3.S
 */

/*
 * Taken from linux/arch/arm/lib/lib1funcs.S
 * Retaining only ARMv5+ code paths
 */
.macro ARM_DIV_BODY dividend, divisor, result, curbit
        clz     \curbit, \divisor
        clz     \result, \dividend
        sub     \result, \curbit, \result
        mov     \curbit, #1
        mov     \divisor, \divisor, lsl \result
        mov     \curbit, \curbit, lsl \result
        mov     \result, #0

        @ Division loop
1:      cmp     \dividend, \divisor
        subhs   \dividend, \dividend, \divisor
        orrhs   \result,   \result,   \curbit
        cmp     \dividend, \divisor,  lsr #1
        subhs   \dividend, \dividend, \divisor, lsr #1
        orrhs   \result,   \result,   \curbit,  lsr #1
        cmp     \dividend, \divisor,  lsr #2
        subhs   \dividend, \dividend, \divisor, lsr #2
        orrhs   \result,   \result,   \curbit,  lsr #2
        cmp     \dividend, \divisor,  lsr #3
        subhs   \dividend, \dividend, \divisor, lsr #3
        orrhs   \result,   \result,   \curbit,  lsr #3
        cmp     \dividend, #0                   @ Early termination?
        movnes  \curbit,   \curbit,  lsr #4     @ No, any more bits to do?
        movne   \divisor,  \divisor, lsr #4
        bne     1b

.endm

.macro ARM_DIV2_ORDER divisor, order
        clz     \order, \divisor
        rsb     \order, \order, #31
.endm

.macro ARM_MOD_BODY dividend, divisor, order, spare
        clz     \order, \divisor
        clz     \spare, \dividend
        sub     \order, \order, \spare
        mov     \divisor, \divisor, lsl \order
        @ Perform all needed substractions to keep only the reminder.
        @ Do comparisons in batch of 4 first.
        subs    \order, \order, #3              @ yes, 3 is intended here
        blt     2f

1:      cmp     \dividend, \divisor
        subhs   \dividend, \dividend, \divisor
        cmp     \dividend, \divisor,  lsr #1
        subhs   \dividend, \dividend, \divisor, lsr #1
        cmp     \dividend, \divisor,  lsr #2
        subhs   \dividend, \dividend, \divisor, lsr #2
        cmp     \dividend, \divisor,  lsr #3
        subhs   \dividend, \dividend, \divisor, lsr #3
        cmp     \dividend, #1
        mov     \divisor, \divisor, lsr #4
        subges  \order, \order, #4
        bge     1b

        tst     \order, #3
        teqne   \dividend, #0
        beq     5f

        @ Either 1, 2 or 3 comparison/substractions are left.
2:      cmn     \order, #2
        blt     4f
        beq     3f
        cmp     \dividend, \divisor
        subhs   \dividend, \dividend, \divisor
        mov     \divisor,  \divisor,  lsr #1
3:      cmp     \dividend, \divisor
        subhs   \dividend, \dividend, \divisor
        mov     \divisor,  \divisor,  lsr #1
4:      cmp     \dividend, \divisor
        subhs   \dividend, \dividend, \divisor
5:
.endm

	.text
FUNCTION(__aeabi_uidiv)
       subs    r2, r1, #1
        moveq   pc, lr
        bcc     Ldiv0
        cmp     r0, r1
        bls     11f
        tst     r1, r2
        beq     12f

        ARM_DIV_BODY r0, r1, r2, r3

        mov     r0, r2
        mov     pc, lr

11:     moveq   r0, #1
        movne   r0, #0
	bx	lr

12:     ARM_DIV2_ORDER r1, r2

        mov     r0, r0, lsr r2
	bx	lr

FUNCTION(__aeabi_idiv)
        cmp     r1, #0
        eor     ip, r0, r1                      @ save the sign of the result.
        beq     Ldiv0
        rsbmi   r1, r1, #0                      @ loops below use unsigned.
        subs    r2, r1, #1                      @ division by 1 or -1 ?
        beq     10f
        movs    r3, r0
        rsbmi   r3, r0, #0                      @ positive dividend value
        cmp     r3, r1
        bls     11f
        tst     r1, r2                          @ divisor is power of 2 ?
        beq     12f

        ARM_DIV_BODY r3, r1, r0, r2

        cmp     ip, #0
        rsbmi   r0, r0, #0
	bx	lr

10:     teq     ip, r0                          @ same sign ?
        rsbmi   r0, r0, #0
	bx	lr

11:     movlo   r0, #0
        moveq   r0, ip, asr #31
        orreq   r0, r0, #1
	bx	lr

12:     ARM_DIV2_ORDER r1, r2

        cmp     ip, #0
        mov     r0, r3, lsr r2
        rsbmi   r0, r0, #0
	bx	lr

FUNCTION(__aeabi_uidivmod)
        stmfd   sp!, {r0, r1, ip, lr}
        bl      __aeabi_uidiv
        ldmfd   sp!, {r1, r2, ip, lr}
        mul     r3, r0, r2
        sub     r1, r1, r3
	bx	lr

FUNCTION(__aeabi_idivmod)
        stmfd   sp!, {r0, r1, ip, lr}
        bl      __aeabi_idiv
        ldmfd   sp!, {r1, r2, ip, lr}
        mul     r3, r0, r2
        sub     r1, r1, r3
	bx	lr

@ (Don't) handle division by 0
FUNCTION(Ldiv0)
	push	{r4, lr}
        mov     r0, #0                  @ About as wrong as it could be.
	pop	{r4, pc}


/*
 * From linux/arch/arm/lib/?sh*3.S
 */
FUNCTION(__aeabi_lasr)
        subs    r3, r2, #32
        rsb     ip, r2, #32
        movmi   al, al, lsr r2
        movpl   al, ah, asr r3
 ARM(   orrmi   al, al, ah, lsl ip      )
 THUMB( lslmi   r3, ah, ip              )
 THUMB( orrmi   al, al, r3              )
        mov     ah, ah, asr r2
	bx	lr

FUNCTION(__aeabi_llsl)
        subs    r3, r2, #32
        rsb     ip, r2, #32
        movmi   ah, ah, lsl r2
        movpl   ah, al, lsl r3
 ARM(   orrmi   ah, ah, al, lsr ip      )
 THUMB( lsrmi   r3, al, ip              )
 THUMB( orrmi   ah, ah, r3              )
        mov     al, al, lsl r2
	bx	lr

FUNCTION(__aeabi_llsr)
        subs    r3, r2, #32
        rsb     ip, r2, #32
        movmi   al, al, lsr r2
        movpl   al, ah, lsr r3
 ARM(   orrmi   al, al, ah, lsl ip      )
 THUMB( lslmi   r3, ah, ip              )
 THUMB( orrmi   al, al, r3              )
        mov     ah, ah, lsr r2
	bx	lr


/*
 * Simple cache maintenance functions
 */

@ r0 - *beg (inclusive)
@ r1 - *end (exclusive)	
clean_dcache_range:
	@ Clean data cache range for range to point-of-unification
	ldr	r2, dlinesz
1:	cmp	r0, r1
	bge	2f
#ifdef DEBUG
	push	{r0-r2, lr}
	mov	r1, r2
	mov	r2, r0
	ldr	r0, =dcstr
	bl	EXT_C(grub_printf)
	pop	{r0-r2, lr}
#endif
	mcr	p15, 0, r0, c7, c11, 1	@ DCCMVAU
	add	r0, r0, r2		@ Next line
	b	1b
2:	dsb
	bx	lr

@ r0 - *beg (inclusive)
@ r1 - *end (exclusive)	
invalidate_icache_range:
	@ Invalidate instruction cache for range to point-of-unification
	ldr	r2, ilinesz
1:	cmp	r0, r1
	bge	2f
#ifdef DEBUG
	push	{r0-r2, lr}
	mov	r1, r2
	mov	r2, r0
	ldr	r0, =icstr
	bl	EXT_C(grub_printf)
	pop	{r0-r2, lr}
#endif
	mcr	p15, 0, r0, c7, c5, 1	@ ICIMVAU
	add	r0, r0, r2		@ Next line
	b	1b
	@ Branch predictor invalidate all
2:	mcr	p15, 0, r0, c7,	c5, 6	@ BPIALL
	dsb
	isb
	bx	lr
	
@void __clear_cache(char *beg, char *end);
FUNCTION(__clear_cache)
	dmb
	dsb
	push	{r4-r6, lr}
	ldr	r2, probed	@ If first call, probe cache sizes
	cmp	r2, #0
	bleq	probe_caches	@ This call corrupts r3
	mov	r4, r0
	mov	r5, r1
	bl	clean_dcache_range
	mov	r0, r4
	mov	r1, r5
	bl	invalidate_icache_range
	pop	{r4-r6, pc}

probe_caches:
	push	{r4-r6, lr}
	mrc 	p15, 0, r4, c0, c0, 1	@ Read Cache Type Register
	mov	r5, #1
	ubfx	r6, r4, #16, #4		@ Extract min D-cache num word log2
	add	r6, r6, #2		@ words->bytes
	lsl	r6, r5, r6		@ Convert to num bytes
	ldr	r3, =dlinesz
	str	r6, [r3]
	and	r6, r4, #0xf		@ Extract min I-cache num word log2
	add	r6, r6, #2		@ words->bytes
	lsl	r6, r5, r6		@ Convert to num bytes
	ldr	r3, =ilinesz
	str	r6, [r3]
	ldr	r3, =probed		@ Flag cache probing done
	str	r5, [r3]
	pop	{r4-r6, pc}

#ifdef DEBUG
dcstr:	.asciz	"cleaning %d bytes of D cache @ 0x%08x\n"
icstr:	.asciz	"invalidating %d bytes of I cache @ 0x%08x\n"
#endif
	
	.align	3
probed:	.long	0
dlinesz:
	.long	0
ilinesz:
	.long	0

@void grub_arch_sync_caches (void *address, grub_size_t len)
FUNCTION(grub_arch_sync_caches)
	add	r1, r0, r1
	b	__clear_cache

	.end
