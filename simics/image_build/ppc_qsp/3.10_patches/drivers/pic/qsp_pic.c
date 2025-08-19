/*

 * QSP Programmable Interrup Controller
 *
 * Copyright 2011 Ivar Holmqvist <ivar.holmqvist@windriver.com> Wind River
 * Copyright 2007 David Gibson <dwg@au1.ibm.com>, IBM Corporation.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 * Most code stolen from uic.c/mpic.c
 */

/* This is an attempt to create a arch independant interrupt controller.
 * It's been tested on arm (cortexA9) and ppc (e600)
 *
 * Currently the major difference is that ppc version
 * assumes that the platform/arch code registers normal handlers
 * for IPIs (i.e requst_irq()). When compiled for arm, we shortcut
 * this and directly enables IPIs and they are handled separately
 * in the machine specific parts.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/reboot.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/device.h>
#include <linux/bootmem.h>
#include <linux/spinlock.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/io.h>
#include <linux/err.h>

#include <asm/irq.h>

#include <linux/of_fdt.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>

#include <linux/qsp/qsp.h>
#include <linux/qsp/qsp_pic.h>

#if 0
#define DEBUG_IPI
#define DBG(fmt, args...) printk(KERN_DEBUG "PIC:" fmt, ## args)
#else
#define DBG(fmt, args...) do {} while (0)
#endif
#define NR_QSP_PIC_INTS	1024

/* Register offsets */
#define QSP_PIC_ID      0x00
#define QSP_PIC_ENABLE  0x04
#define QSP_PIC_DISABLE 0x08
#define QSP_PIC_DST     0x10
#define QSP_PIC_GEN     0x14
#define QSP_PIC_TYPE    0x18

#define QSP_PIC_PENDING 0x20
#define QSP_PIC_EOI     0x24

#define QSP_NO_IRQ      (NR_QSP_PIC_INTS + 1)

/* bit definitions */
#define TYPE_EDGE (1<<16)

#define CPU_DST_SHIFT (16)


static struct qsp_pic *primary_qsp_pic;

/* TODO: Need to properly investigate which handlers are best
 * for this interrupt controller (keeping in mind that I can
 * rewrite the controller itself if needed). Seems like the
 * lockless percpu handlers would be best.
 */

struct qsp_pic {
	int index;
	void __iomem *base;
	struct irq_domain *domain;
};

static void qsp_pic_write_register(struct qsp_pic *pic, int reg_num, u32 val)
{
	writel(val, pic->base + reg_num);
}

static u32 qsp_pic_read_register(struct qsp_pic *pic, int reg_num)
{
	u32 ret;
	ret = readl(pic->base + reg_num);
	return ret;
}


static void qsp_pic_unmask_irq(struct irq_data *d)
{
	struct qsp_pic *qsp_pic = irq_data_get_irq_chip_data(d);

	DBG("unamsk %d\n", d->hwirq);
	qsp_pic_write_register(qsp_pic, QSP_PIC_ENABLE, d->hwirq);
}

static void qsp_pic_mask_irq(struct irq_data *d)
{
	struct qsp_pic *qsp_pic = irq_data_get_irq_chip_data(d);

	DBG("mask %d\n", d->hwirq);
	qsp_pic_write_register(qsp_pic, QSP_PIC_DISABLE, d->hwirq);
}

static void qsp_pic_eoi(struct irq_data *d)
{
	struct qsp_pic *qsp_pic = irq_data_get_irq_chip_data(d);

	DBG("EOI %d hw:%d\n", d->irq, d->hwirq);
	qsp_pic_write_register(qsp_pic, QSP_PIC_EOI, d->hwirq);
}

/* Only used by arm machines.
 */
void qsp_ipi_eoi(int irq)
{
	struct qsp_pic *qsp_pic = primary_qsp_pic;
	qsp_pic_write_register(qsp_pic, QSP_PIC_EOI, irq);
}

static int qsp_pic_set_irq_type(struct irq_data *d, unsigned int flow_type)
{
	struct qsp_pic *qsp_pic = irq_data_get_irq_chip_data(d);
	u32 edge;

	switch (flow_type & IRQ_TYPE_SENSE_MASK) {
	case IRQ_TYPE_NONE:
		DBG("set type none %d\n", d->hwirq);
		qsp_pic_mask_irq(d);
		return 0;

	case IRQ_TYPE_EDGE_RISING:
		DBG("set type edge rising %d\n", d->hwirq);
		edge = TYPE_EDGE;
		break;

	case IRQ_TYPE_LEVEL_HIGH:
		DBG("set type level high %d\n", d->hwirq);
		edge = 0;
		break;

	case IRQ_TYPE_LEVEL_LOW:
	case IRQ_TYPE_EDGE_FALLING:
		printk(KERN_ERR "Unhandled flow type %d\n", flow_type);
		BUG();
		break;

	default:
		printk(KERN_ERR "Illegal flow type %d\n", flow_type);
		BUG();
		return -EINVAL;
	}


	qsp_pic_write_register(qsp_pic, QSP_PIC_TYPE, edge | d->hwirq);
	irqd_set_trigger_type(d, flow_type);

	return 0;
}

#ifdef CONFIG_SMP

static void qsp_pic_request_ipis(int nr_cpus)
{
	struct qsp_pic *qsp_pic = primary_qsp_pic;
	int i;
	int cpu;
	cpumask_t tmpmask;

	BUG_ON(qsp_pic == NULL);

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		cpumask_clear(&tmpmask);
		cpumask_set_cpu(cpu, &tmpmask);
		for (i = 0; i < IPI_NUM_TYPES; i++) {

			unsigned int vipi = irq_create_mapping(qsp_pic->domain,
							       IPI_NR(cpu, i));
			if (vipi == NO_IRQ) {
				printk(KERN_ERR "Failed to map ipi %d\n", i);
				continue;
			}
			irq_set_irq_type(vipi, IRQ_TYPE_EDGE_RISING);
			irq_set_affinity(vipi, &tmpmask);

#ifdef CONFIG_ARM
			/* FIXME: Maybe we should switch to request_irq()
			 * based ipi handling in arm as well instead of
			 * shortcutting it in machine->handle_irq()
			 */
			qsp_pic_write_register(qsp_pic,
					       QSP_PIC_ENABLE,
					       IPI_NR(cpu, i));
#else
			/* powerpc does a simple request_irq() here.*/
			smp_request_message_ipi(vipi, i);
#endif
		}
	}
}

int smp_qsp_pic_probe(void)
{
	int nr_possible;
	int nr_ipis;

	pr_debug("smp_qsp_pic_probe()...\n");
	/* QSP-PPC updates setup_max_cpus since possible_map is always "full".
	 * We just wan't as few IPIs as possible.
	 */
	nr_possible = cpumask_weight(cpu_possible_mask);
	nr_ipis = min_t(int, nr_possible, setup_max_cpus);

	if (nr_ipis > 1) {
		pr_info("qps-pic: Requesting %d ipis (cpu_possible=%d, maxcpus=%d)\n",
			nr_ipis,
			nr_possible,
			setup_max_cpus);
		qsp_pic_request_ipis(nr_ipis);
	}

	return nr_ipis;
}

void smp_qsp_pic_setup_cpu(int cpu)
{
}

static int qsp_pic_set_affinity(struct irq_data *d,
				const struct cpumask *cpumask,
				bool force)
{
	struct qsp_pic *qsp_pic = irq_data_get_irq_chip_data(d);
	unsigned int irq = d->hwirq;
	int cpuid;

	BUG_ON(cpumask_weight(cpumask) == 0);
	cpuid = cpumask_first(cpumask);

	DBG("single dest cpu -> %d (mask;%08lx)\n",
	    cpuid, cpumask_bits(cpumask)[0]);
	qsp_pic_write_register(qsp_pic, QSP_PIC_DST,
			       (cpuid<<CPU_DST_SHIFT) | irq);

	return 0;
}

void qsp_pic_message_pass(int cpu, int msg)
{
	struct qsp_pic *qsp_pic = primary_qsp_pic;

	BUG_ON(qsp_pic == NULL);

	/* make sure we're sending something that translates to an IPI */
	if ((unsigned int)msg > (IPI_NUM_TYPES - 1)) {
		printk(KERN_ERR "SMP %d: smp_message_pass: unknown msg %d\n",
		       smp_processor_id(), msg);
		return;
	}

#ifdef DEBUG_IPI
	DBG("%s: %d->%d (vipi:%d) send_ipi(ipi_no: %d)\n", "qsp_pic",
	    smp_processor_id(), cpu, IPI_NR(cpu, msg), msg);
#endif
	qsp_pic_write_register(qsp_pic, QSP_PIC_GEN, IPI_NR(cpu, msg));
}
#endif


static struct irq_chip qsp_pic_irq_chip = {
	.name		= "QSP_PIC",
	.irq_unmask	= qsp_pic_unmask_irq,
	.irq_mask	= qsp_pic_mask_irq,
	.irq_set_type	= qsp_pic_set_irq_type,
	.irq_eoi	= qsp_pic_eoi,
#ifdef CONFIG_SMP
	.irq_set_affinity = qsp_pic_set_affinity,
#endif
};


static int qsp_pic_domain_map(struct irq_domain *d, unsigned int virq,
			    unsigned long hw)
{
	struct qsp_pic *qsp_pic = d->host_data;

	irq_set_chip_data(virq, qsp_pic);

	if ((hw - IPI_BASE) > 0 && (hw - IPI_BASE) < IPI_NUM_TYPES) {
		DBG("MAP IPI %ld (%ld:%ld)\n", hw,
		    IPI_GET_CPU(hw), IPI_GET_MSG(hw));
		irq_set_chip_data(virq, qsp_pic);
		irq_set_chip_and_handler(virq, &qsp_pic_irq_chip,
					 handle_percpu_irq);
		return 0;
	}

	/* Use fasteoi_irq as handler.
	 */
	irq_set_chip_and_handler(virq, &qsp_pic_irq_chip, handle_fasteoi_irq);

	/* Set default irq type */
	irq_set_irq_type(virq, IRQ_TYPE_NONE);

	return 0;
}

static int qsp_pic_domain_xlate(struct irq_domain *d, struct device_node *ct,
			      const u32 *intspec, unsigned int intsize,
			      unsigned long *out_hwirq,
			      unsigned int *out_type)

{
	/* QSP_PIC intspecs must have 2 cells src and type.
	 */
	BUG_ON(intsize != 2);
	*out_hwirq = intspec[0];
	*out_type = intspec[1]; /* i.e edge or level */
	return 0;
}

const struct irq_domain_ops qsp_irq_domain_ops = {
	.map = qsp_pic_domain_map,
	.xlate = qsp_pic_domain_xlate,
};

static struct qsp_pic * qsp_pic_init_one(struct device_node *node)
{
	struct qsp_pic *qsp_pic;
	const u32 *indexp, *reg;
	int len;
	int i;
	u32 id;

	BUG_ON(!of_device_is_compatible(node, "qsp-pic"));
	WARN_ON(NR_QSP_PIC_INTS > NR_IRQS);

	qsp_pic = kzalloc(sizeof(*qsp_pic), GFP_KERNEL);
	if (!qsp_pic)
		return NULL;

	indexp = of_get_property(node, "cell-index", &len);
	if (!indexp || (len != sizeof(u32))) {
		printk(KERN_ERR "qsp_pic: Device node %s has missing or" \
		       "invalid cell-index property\n", node->full_name);
		return NULL;
	}
	qsp_pic->index = *indexp;

	reg = of_get_property(node, "reg", &len);
	if (!reg || (len != 3*sizeof(u32))) {
		printk(KERN_ERR "qsp_pic: Device node %s has missing or"\
		       "invalid reg property\n", node->full_name);
		return NULL;
	}
	qsp_pic->base = of_iomap(node, 0);
	BUG_ON(qsp_pic->base == NULL);

	/* Probe ID of pic.
	 */
	id = qsp_pic_read_register(qsp_pic, QSP_PIC_ID);
	if (id != QSP_PIC_ID_VAL)
		panic("pic id %08x != %08x\n", id, QSP_PIC_ID_VAL);

	/* Disable all interrupts. */
	for (i = 0; i < NR_QSP_PIC_INTS; i++)
		qsp_pic_write_register(qsp_pic, QSP_PIC_DISABLE, i);

	qsp_pic->domain = irq_domain_add_tree(node,
					      &qsp_irq_domain_ops,
					      (void *)qsp_pic);

	DBG("QSP_PIC%d (%d IRQ sources) @%p\n", qsp_pic->index,
	    NR_QSP_PIC_INTS, qsp_pic->base);

	return qsp_pic;
}

void qsp_pic_init(void)
{
	struct device_node *np;
	const u32 *interrupts;

	/* First locate and initialize the top-level QSP_PIC */
	for_each_compatible_node(np, NULL, "qsp-pic") {
		interrupts = of_get_property(np, "interrupts", NULL);
		if (!interrupts)
			break;
	}

	BUG_ON(!np); /* qsp_pic_init_tree() assumes there's a QSP_PIC as the
		      * top-level interrupt controller */
	primary_qsp_pic = qsp_pic_init_one(np);
	if (!primary_qsp_pic)
		panic("Unable to initialize primary QSP_PIC %s\n",
		      np->full_name);

	of_node_put(np);

}

/* Return an interrupt vector or NO_IRQ if no interrupt is pending. */
unsigned int qsp_pic_get_irq(void)
{
	u32 pending;
	u32 rev;
	BUG_ON(!primary_qsp_pic);

	pending = qsp_pic_read_register(primary_qsp_pic, QSP_PIC_PENDING);
	DBG("get irq %d\n", pending);

	if (pending == QSP_NO_IRQ)
		return NO_IRQ;

	rev = irq_find_mapping(primary_qsp_pic->domain, pending);

#ifdef DEBUG_IPI
	if (rev > IPI_BASE)
		DBG("%s IPI  %d -> cpu:%d msg:%d\n", __func__, rev,
		    IPI_GET_CPU(rev), IPI_GET_MSG(rev));
#endif
	return rev;
}

