/*
 * QSP PPC setup and early boot code plus other random bits.
 *
 * Copyright 2011 Wind River
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <asm/udbg.h>
#include <linux/kernel.h>
#include <asm/machdep.h>
#include <linux/of_platform.h>
#include <linux/qsp/qsp_pic.h>

#include "smp.h"
#include <linux/delay.h>

static int __init declare_of_platform_devices(void)
{
	of_platform_populate(NULL, of_default_bus_match_table, NULL, NULL);
	return 0;
}
machine_device_initcall(qsp, declare_of_platform_devices);

#define SOFT_RESET_REG 0x48

/*
 * Reset the system. It is called by machine_restart().
 */
void qsp_restart(char *cmd)
{
        static void __iomem *sysregs_base;
        struct device_node *np;
        np = of_find_node_by_type(NULL, "sysregs");
        BUG_ON(np == NULL);

        sysregs_base = of_iomap(np, 0);
        BUG_ON(sysregs_base == 0);

        // write reset register
        writel(1, sysregs_base + SOFT_RESET_REG);

        mdelay(500);
}

static void __init qsp_setup_arch(void)
{
	pr_info("QSP setup arch.");
#ifdef CONFIG_SMP
	qsp_smp_init();
#endif
}

static void qsp_show_cpuinfo(struct seq_file *m)
{
	seq_printf(m, "machine\t\t: qsp-ppc\n");
}

/*
 * Called very early, device-tree isn't unflattened
 */
static int __init qsp_probe(void)
{
	unsigned long root = of_get_flat_dt_root();
	pr_debug("Probe QSP\n");
	return of_flat_dt_is_compatible(root, "simics,qsp-ppc");
}

static void __init qsp_init_early(void)
{
	pr_info("QSP early init\n");
#ifdef CONFIG_SMP
	qsp_smp_early_init();
#endif
}

define_machine(qsp) {
	.name			= "QSP PPC",
	.probe			= qsp_probe,
	.init_early             = qsp_init_early,
	.setup_arch		= qsp_setup_arch,
	.init_IRQ		= qsp_pic_init,
	.show_cpuinfo		= qsp_show_cpuinfo,
	.get_irq		= qsp_pic_get_irq,
	.calibrate_decr		= generic_calibrate_decr,
        .restart                = qsp_restart,
};

