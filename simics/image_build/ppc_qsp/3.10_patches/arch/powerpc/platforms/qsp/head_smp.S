
/* This is instead of a bootloader...
 */
#include <asm/ppc_asm.h>
#include <asm/reg.h>

#define CPU_ID_REG 0xe0001010

	.text
	.global __secondary_start_qsp
__secondary_start_qsp:
	/* Enable timebase. Normally done in u-boot and will be done later
	 * when we restore cpu context from core 0, but it doesn't
	 * hurt to do it here since there might be some delays early on.
	 */
	mfspr	r11, SPRN_HID0
	oris	r11,r11,HID0_TBEN@ha
	mtspr	SPRN_HID0, r11

	/* Fetch cpu id from sysregs and pass it on to generic code. */
	lis	r3,CPU_ID_REG@ha
	addi	r4,r3,CPU_ID_REG@l
	lwbrx   r3,r5,r4 /* in wrong endian... */
	stw	r3, __secondary_hold_acknowledge@l(0)
	mr	r24, r3			/* cpu # */
	b	__secondary_start
