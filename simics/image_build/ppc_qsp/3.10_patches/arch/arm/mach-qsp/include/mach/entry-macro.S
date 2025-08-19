
#ifndef HAVE_GET_IRQNR_PREAMBLE
	.macro	get_irqnr_preamble, base, tmp
	.endm
#endif
	.macro  get_irqnr_and_base, irqnr, irqstat, base, tmp
	.endm

	.macro test_for_ipi, irqnr, irqstat, base, tmp
	.endm

	.macro	disable_fiq
	.endm

	.macro	arch_ret_to_user, tmp1, tmp2
	.endm
