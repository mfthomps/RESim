/*
 * QSP disk controller
 *
 * Based on ps3disk.c, xen-blkfront.c and the example block driver in ldd.
 *
 * (C) Copyright 2012, Ivar Holmqvist <ivarholmqvist@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#undef DEBUG

#include <linux/clockchips.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/spinlock.h>
#include <linux/timex.h>
#include <linux/module.h>
#include <linux/smp.h>
#include <linux/irq.h>
#include <linux/irqreturn.h>
#include <linux/interrupt.h>
#include <linux/qsp/qsp_clk.h>

/* TODO:
 * - This driver only supports 1 instance...
 * - Cleanup
 */

DEFINE_RAW_SPINLOCK(qsp_lock);

static void __iomem *clk_base;

#define CLK_ID      0x00
#define CLK_FREQ    0x04
#define CLK_COUNT   0x08
#define CLK_ONESHOT 0x0c
#define CLK_PERIOD  0x10

cycle_t qsp_read(struct clocksource *cs)
{
	return readl(clk_base + CLK_COUNT);
}


static struct clocksource qsp_cs = {
	.name		= "qsp",
	.rating		= 110,
	.read		= qsp_read,
	.mask		= CLOCKSOURCE_MASK(32),
};


/*
 * Initialize the QSP timer.
 *
 */
static void init_qsp_timer(enum clock_event_mode mode,
			   struct clock_event_device *evt)
{
	u32 freq;
	pr_debug("INIT TIMER\n");
	raw_spin_lock(&qsp_lock);

	switch (mode) {
	case CLOCK_EVT_MODE_PERIODIC:
		pr_debug("PERIODIC\n");
		freq = readl(clk_base + CLK_FREQ);
		pr_info("Setting up periodic mode freq:%dHz HZ:%dHz\n",
			freq, HZ);
		WARN_ON(freq % HZ != 0);
		writel(freq/HZ, clk_base + CLK_PERIOD);
		break;

	case CLOCK_EVT_MODE_SHUTDOWN:
		pr_debug("SHUTDOWN\n");
		/* Fall-through */
	case CLOCK_EVT_MODE_UNUSED:
		pr_debug("UNUSED\n");
		writel(0, clk_base + CLK_ONESHOT);
		break;

	case CLOCK_EVT_MODE_ONESHOT:
		pr_debug("ONESHOT\n");
		WARN_ON(evt->mode == CLOCK_EVT_MODE_ONESHOT ||
			evt->mode == CLOCK_EVT_MODE_PERIODIC);
		/* One shot setup not needed, all is done in next event. */
		break;

	case CLOCK_EVT_MODE_RESUME:
		pr_debug("RESUME\n");
		/* Nothing to do here */
		break;
	}
	raw_spin_unlock(&qsp_lock);
}

/*
 * Program the next event in oneshot mode
 *
 * Delta is given in QSP ticks
 */
static int qsp_next_event(unsigned long delta, struct clock_event_device *evt)
{
	WARN_ON(evt->mode != CLOCK_EVT_MODE_ONESHOT);
	writel(delta, clk_base + CLK_ONESHOT);
	return 0;
}

struct clock_event_device qsp_clockevent = {
	.name		= "qsp",
	.features	= CLOCK_EVT_FEAT_PERIODIC | CLOCK_EVT_FEAT_ONESHOT,
	.set_mode	= init_qsp_timer,
	.set_next_event = qsp_next_event,
};

static irqreturn_t qsp_timer_interrupt(int irq, void *dev_id)
{
	struct clock_event_device *evt = dev_id;
	if (dev_id == NULL) {
		pr_err("Spurious timer irq %d\n", irq);
		return IRQ_NONE;
	}
	evt->event_handler(evt);

	return IRQ_HANDLED;
}

static struct irqaction qsp_timer_irq = {
	.name		= "timer",
	.flags		= IRQF_TIMER,
	.handler	= qsp_timer_interrupt,
	.dev_id		= &qsp_clockevent,
};


/*
 * Register this timer as both clocksource and clockevent.
 */
void __init qsp_timer_init_one(int irq, void __iomem *base)
{
	u32 freq;

	/* FIXME: one timer per cpu? arm...
	 */
	qsp_clockevent.cpumask = cpumask_of(0);

	freq = readl(base + CLK_FREQ);
	pr_debug("IRQ %d freq %d\\n", irq, freq);
	clk_base = base;
	setup_irq(irq, &qsp_timer_irq);
	clockevents_config_and_register(&qsp_clockevent, freq,
					0xF, 0xFFFFFFFF);

	clocksource_register_hz(&qsp_cs, freq);
}



