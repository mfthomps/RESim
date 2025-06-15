#include <linux/smp.h>
#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/qsp/qsp_pic.h>

#include "smp.h"

#define ID_REG	       0x00
#define ENABLE_REG     0x04
#define DISABLE_REG    0x08
#define BOOT_PC_REG    0x0c
#define CPU_STATUS_REG 0x14
#define PROBE_REG      0x18

#define QSP_MAX_CPUS 128

static void __iomem *sysregs_base;

/* For QSP-PPC The default dtb is populated with all possible cpus (i.e 128)
 * since there is no bootloader competent enough to create the exact dtb.
 *
 * We probe sysregs early to find out how many is actually present so the
 * cpu_possible map setup in setup-common.c is not larger than needed.
 */
static void __init qsp_setup_max_cpus(void)
{
	int hw_cpu;
	int possible = 0;

	for (hw_cpu = 0; hw_cpu < QSP_MAX_CPUS; hw_cpu++) {
		writel(hw_cpu, sysregs_base + PROBE_REG);
		if (readl(sysregs_base + CPU_STATUS_REG) != 1) {
			pr_debug(KERN_INFO "Probe cpu:%d not present.", hw_cpu);
		} else {
			possible++;
			pr_debug(KERN_INFO "Probe cpu:%d present.", hw_cpu);
		}
	}
	pr_info("QSP found %d possible cpus from probing sysregs.", possible);
	pr_info(" previoud maxcpus %d\n", setup_max_cpus);
	if (possible < setup_max_cpus) {
		pr_info(" adjusting maxcpus from %d down to %d\n",
			setup_max_cpus, possible);
		setup_max_cpus = possible;
	}
}

static int __init smp_qsp_kick_cpu(int nr)
{
	int n;
	int hw_cpu = get_hard_smp_processor_id(nr);

	BUG_ON(sysregs_base == NULL);

	writel(__pa(__secondary_start_qsp), sysregs_base + BOOT_PC_REG);
	writel(hw_cpu, sysregs_base + ENABLE_REG);
	if (readl(sysregs_base + CPU_STATUS_REG) != 1) {
		printk(KERN_INFO "cpu:%d not present.", hw_cpu);
		return -EINVAL;
	}

	n = 0;
	/* Wait a bit for the CPU to ack. */
	while ((__secondary_hold_acknowledge != hw_cpu) && (++n < 1000))
		mdelay(1);

	if (__secondary_hold_acknowledge != hw_cpu) {
		printk(KERN_WARNING "cpu:%d stuck (post %08lx)\n", nr,
		       __secondary_hold_acknowledge);
		return -EINVAL;
	}

	return 0;
}

static struct smp_ops_t smp_qsp_ops = {
	.kick_cpu       = smp_qsp_kick_cpu,
	.message_pass   = qsp_pic_message_pass,
	.probe          = smp_qsp_pic_probe,
	.setup_cpu	= smp_qsp_pic_setup_cpu,
#ifdef CONFIG_PPC_QSP_SYNC_TIMEBASE
	.take_timebase  = smp_generic_take_timebase,
	.give_timebase  = smp_generic_give_timebase,
#endif
};

void __init qsp_smp_init(void)
{
	pr_info("QSP smp  init\n");
}

void __init qsp_smp_early_init(void)
{
	struct device_node *np;
	pr_info("QSP smp early init\n");
	np = of_find_node_by_type(NULL, "sysregs");
	if (np)
		sysregs_base = of_iomap(np, 0);
	qsp_setup_max_cpus();
	smp_ops = &smp_qsp_ops;
}
