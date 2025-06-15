/*
 *  linux/arch/arm/mach-qsp/platsmp.c
 *
 *  Copyright (C) 2012 Wind River
 *  All Rights Reserved
 *  Author: Ivar Holmqvist <ivar.holmqvist@windriver.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/errno.h>
#include <linux/smp.h>
#include <linux/io.h>
#include <linux/of_fdt.h>
#include <linux/of_address.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/jiffies.h>

#include <linux/qsp/qsp_pic.h>

/* TODO: The pen_release and boot_lock stuff are stolen from vexpress and
 *       is really overkill on QSP and should be removed.
 */

#define ID_REG	       0x00
#define ENABLE_REG     0x04
#define DISABLE_REG    0x08
#define BOOT_PC_REG    0x0c
#define CPU_STATUS_REG 0x14
#define PROBE_REG      0x18

static void __iomem *sysregs_base;

/*
 * control for which core is the next to come out of the secondary
 * boot "holding pen"
 */
volatile int __cpuinitdata pen_release = -1;

/*
 * Write pen_release in a way that is guaranteed to be visible to all
 * observers, irrespective of whether they're taking part in coherency
 * or not.  This is necessary for the hotplug code to work reliably.
 */
static void __cpuinit write_pen_release(int val)
{
	pen_release = val;
}

static DEFINE_SPINLOCK(boot_lock);


/* FIXME: probe max cores from sysregs... */
#define QSP_MAX_CORES 128

static void generate_ipi(const struct cpumask *mask, unsigned int irq)
{
	int cpu;
	BUG_ON(irq > (IPI_NUM_TYPES - 1));
	for_each_cpu(cpu, mask) {
		/* FIXME: should we do cpu_logical_map(cpu) here
		 */
		qsp_pic_message_pass(cpu, irq);
	}
}

/*
 * Initialise the CPU possible map early - this describes the CPUs
 * which may be present or become present in the system.
 */
void __init smp_init_cpus(void)
{
	int hw_cpu;
	struct device_node *np;

	np = of_find_node_by_type(NULL, "sysregs");
	BUG_ON(np == NULL);

	sysregs_base = of_iomap(np, 0);
	BUG_ON(sysregs_base == 0);

	for (hw_cpu = 0; hw_cpu < QSP_MAX_CORES; ++hw_cpu) {
		writel(hw_cpu, sysregs_base + PROBE_REG);
		if (readl(sysregs_base + CPU_STATUS_REG) == 1)
			set_cpu_possible(hw_cpu, true);
	}

	set_smp_cross_call(generate_ipi);

}

void __init platform_smp_prepare_cpus(unsigned int max_cpus)
{
	smp_qsp_pic_probe();
}

extern void secondary_startup(void);

int __cpuinit boot_secondary(unsigned int cpu, struct task_struct *idle)
{
	int i;
	/*
	 * Set synchronisation state between this boot processor
	 * and the secondary one
	 */
	spin_lock(&boot_lock);

	/*
	 * This is really belt and braces; we hold unintended secondary
	 * CPUs in the holding pen until we're ready for them.  However,
	 * since we haven't sent them a soft interrupt, they shouldn't
	 * be there.
	 */
	write_pen_release(cpu);

	/*
	 * Send the secondary CPU a soft interrupt, thereby causing
	 * the boot monitor to read the system wide flags register,
	 * and branch to the address found there.
	 */
	writel(__pa(secondary_startup), sysregs_base + BOOT_PC_REG);
	writel(cpu, sysregs_base + ENABLE_REG);
	if (readl(sysregs_base + CPU_STATUS_REG) != 1)
		return -ENOSYS;

	for (i = 0; i < 10000; i++) {
		if (pen_release == -1)
			break;
		udelay(100);
	}

	/*
	 * now the secondary core is starting up let it run its
	 * calibrations, then wait for it to finish
	 */
	spin_unlock(&boot_lock);
	return pen_release != -1 ? -ENOSYS : 0;
}


void __cpuinit platform_secondary_init(unsigned int cpu)

{
	/*
	 * let the primary processor know we're out of the
	 * pen, then head off into the C entry point
	 */
	BUG_ON(pen_release != cpu);
	write_pen_release(-1);

	/*
	 * Synchronise with the boot thread.
	 */
	spin_lock(&boot_lock);
	spin_unlock(&boot_lock);
}

