#include <linux/init.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <asm/mach/arch.h>
#include <asm/mach/time.h>
#include <asm/mach/map.h>
#include <linux/qsp/qsp_pic.h>
#include <linux/qsp/qsp_clk.h>
#include <linux/delay.h>

#define SOFT_RESET_REG 0x48
/*
 * Reset the system. It is called by machine_restart().
 */
void qsp_restart(char mode, const char *cmd)
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

static struct map_desc sysreg_io_desc[] __initdata = {
	{
		.virtual	= 0xf8000000,
		.pfn		= __phys_to_pfn(0xe0000000),
		.length		= SZ_128K,
		.type		= MT_DEVICE,
	},
};

void qsp_init_machine(void)
{
	of_platform_populate(NULL, of_default_bus_match_table, NULL, NULL);
}

static void __init qsp_map_io(void)
{
#ifdef CONFIG_SMP
	/* platsmp.c - smp_init_cpus() needs to access sysreg early... */
	iotable_init(sysreg_io_desc, ARRAY_SIZE(sysreg_io_desc));
	pr_debug(KERN_INFO "qsp_map_io called\n");
#endif
}

asmlinkage void qsp_pic_handle_irq(struct pt_regs *regs)
{
	int irq;
	irq = qsp_pic_get_irq();
	BUG_ON(irq == NO_IRQ);
#if CONFIG_SMP
	if (irq > IPI_BASE) {
		qsp_ipi_eoi(irq);
		handle_IPI(IPI_GET_MSG(irq), regs);
		return;
	}
#endif
	handle_IRQ(irq, regs);
}

static void qsp_timer_init(void)
{

	int irq;
	struct device_node *np;
	void __iomem *timer_base;

	pr_info(KERN_INFO "qsp timer init\n");

	np = of_find_compatible_node(NULL, NULL, "qsp,timer");
	WARN_ON(np == NULL);

	timer_base = of_iomap(np, 0);
	WARN_ON(!timer_base);
	pr_debug("Timer base %p\n", timer_base);

	irq = irq_of_parse_and_map(np, 0);
	WARN_ON(irq == 0);

	qsp_timer_init_one(irq, timer_base);
}

static struct sys_timer qsp_timer = {
	.init = qsp_timer_init,
};

static const char *qsp_dt_compat[] __initdata = {
	"simics,qsp-arm",
	NULL,
};


DT_MACHINE_START(QSP, "Simics QSP (Device Tree)")
	.map_io		= qsp_map_io,
	.init_irq	= qsp_pic_init,
	.handle_irq	= qsp_pic_handle_irq,
	.timer		= &qsp_timer,
	.init_machine	= qsp_init_machine,
	.dt_compat	= qsp_dt_compat,
        .restart	= qsp_restart,
MACHINE_END
