/*
 * qsp_uart.c -- QSP Serial driver
 *
 * Based on altera_uart.c -- Altera UART driver
 *
 * (C) Copyright 2012, Ivar Holmqvist <ivarholmqvist@gmail.com>
 * (C) Copyright 2003-2007, Greg Ungerer <gerg@snapgear.com>
 * (C) Copyright 2008, Thomas Chou <thomas@wytron.com.tw>
 * (C) Copyright 2010, Tobias Klauser <tklauser@distanz.ch>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/console.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/serial.h>
#include <linux/serial_core.h>
#include <linux/platform_device.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of.h>
#include <linux/io.h>
#include <linux/device.h>

#include <linux/qsp/qsp.h>

#define DRV_NAME "qsp_uart"
#define SERIAL_QSP_MAJOR 204
#define SERIAL_QSP_MINOR 16

#define CONFIG_SERIAL_QSP_UART_MAXPORTS 32
#define QSP_UART_SIZE			32

/* Register offfsets
 */
#define ID_REG      0x00
#define STATUS_REG  0x04
#define CONTROL_REG 0x08
#define TXDATA_REG  0x0c
#define RXDATA_REG  0x10

/* Status register bits
 */
#define TX_READY (1<<0)
#define RX_READY (1<<1)

/* Control register bits
 */
#define TX_INT (1<<0)
#define RX_INT (1<<1)

/*
 * Local per-uart structure.
 */
struct qsp_uart {
	struct uart_port port;
	int irq;
};

static u32 qsp_uart_readl(struct uart_port *port, int reg)
{
	return readl(port->membase + (reg << port->regshift));
}

static void qsp_uart_writel(struct uart_port *port, u32 dat, int reg)
{
	writel(dat, port->membase + (reg << port->regshift));
}

static unsigned int qsp_uart_tx_empty(struct uart_port *port)
{
	return (qsp_uart_readl(port, STATUS_REG) & TX_READY) ? TIOCSER_TEMT : 0;
}

/* No modem control lines
 */
static unsigned int qsp_uart_get_mctrl(struct uart_port *port)
{
	return TIOCM_CAR | TIOCM_DSR | TIOCM_CTS;
}

static void qsp_uart_set_mctrl(struct uart_port *port, unsigned int mctrl)
{
}

static void qsp_uart_start_tx(struct uart_port *port)
{
	u32 pre;

	pre = qsp_uart_readl(port, CONTROL_REG);
	qsp_uart_writel(port, pre|TX_INT, CONTROL_REG);
}

static void qsp_uart_stop_tx(struct uart_port *port)
{
	u32 pre;

	pre = qsp_uart_readl(port, CONTROL_REG);
	qsp_uart_writel(port, pre & ~TX_INT, CONTROL_REG);
}

static void qsp_uart_stop_rx(struct uart_port *port)
{
	u32 pre;

	pre = qsp_uart_readl(port, CONTROL_REG);
	qsp_uart_writel(port, pre & ~RX_INT, CONTROL_REG);
}

static void qsp_uart_break_ctl(struct uart_port *port, int break_state)
{
	dev_dbg(port->dev, "ignoring break_ctl\n");
}

static void qsp_uart_enable_ms(struct uart_port *port)
{
	dev_dbg(port->dev, "ignoring enable_ms\n");
}

static void qsp_uart_set_termios(struct uart_port *port,
				    struct ktermios *termios,
				    struct ktermios *old)
{
	unsigned int baud;

	baud = uart_get_baud_rate(port, termios, old, 0, 4000000);

	if (old)
		tty_termios_copy_hw(termios, old);
	tty_termios_encode_baud_rate(termios, baud, baud);

	uart_update_timeout(port, termios->c_cflag, baud);
}

static void qsp_uart_rx_chars(struct qsp_uart *pp)
{
	struct uart_port *port = &pp->port;
	unsigned char ch, flag;
	unsigned short status;

	while ((status = qsp_uart_readl(port, STATUS_REG)) &
	       RX_READY) {
		ch = qsp_uart_readl(port, RXDATA_REG);
		flag = TTY_NORMAL;
		port->icount.rx++;

		/* There is no possibility to errors on this HW (i.e framing
		 * etc) so there's no other icount updates and we always
		 * return TTY_NORMAL.
		 */

		if (uart_handle_sysrq_char(port, ch))
			continue;

		/* RX Ovverun not supported by HW, so we skip passing
		 * status/mask for that.
		 */
		uart_insert_char(port, 0, 0, ch, flag);
	}

	tty_flip_buffer_push(port->state->port.tty);
}

static void qsp_uart_tx_chars(struct qsp_uart *pp)
{
	struct uart_port *port = &pp->port;
	struct circ_buf *xmit = &port->state->xmit;

	if (port->x_char) {
		/* Send special char - probably flow control */
		qsp_uart_writel(port, port->x_char, TXDATA_REG);
		port->x_char = 0;
		port->icount.tx++;
		return;
	}

	while (qsp_uart_readl(port, STATUS_REG) &
	       TX_READY) {
		if (xmit->head == xmit->tail)
			break;
		qsp_uart_writel(port, xmit->buf[xmit->tail],
		       TXDATA_REG);
		xmit->tail = (xmit->tail + 1) & (UART_XMIT_SIZE - 1);
		port->icount.tx++;
	}

	if (uart_circ_chars_pending(xmit) < WAKEUP_CHARS)
		uart_write_wakeup(port);

	if (xmit->head == xmit->tail) {
		qsp_uart_writel(port,
				   qsp_uart_readl(port, CONTROL_REG) & ~TX_INT,
				   CONTROL_REG);
	}
}

static irqreturn_t qsp_uart_interrupt(int irq, void *data)
{
	struct uart_port *port = data;
	struct qsp_uart *pp = container_of(port, struct qsp_uart, port);
	unsigned int isr;

	isr = qsp_uart_readl(port, STATUS_REG) &
		qsp_uart_readl(port, CONTROL_REG);

	spin_lock(&port->lock);
	if (isr & RX_READY)
		qsp_uart_rx_chars(pp);
	if (isr & TX_READY)
		qsp_uart_tx_chars(pp);
	spin_unlock(&port->lock);

	return IRQ_RETVAL(isr);
}

static void qsp_uart_config_port(struct uart_port *port, int flags)
{
	port->type = PORT_QSP_UART;

	/* Clear interrupt mask */
	qsp_uart_writel(port, 0, CONTROL_REG);
}

static int qsp_uart_startup(struct uart_port *port)
{
	int ret;
	unsigned long flags;
	u32 pre;

	dev_dbg(port->dev, "startup\n");

	port->irq = irq_of_parse_and_map(port->dev->of_node,  0);
	if (!port->irq) {
		dev_err(port->dev, "IRQ not specified in dtb\n");
		return -EINVAL;
	}
	dev_dbg(port->dev, "got irq %d\n", port->irq);

	ret = request_irq(port->irq, qsp_uart_interrupt, 0,
			DRV_NAME, port);
	if (ret) {
		pr_err(DRV_NAME ": unable to attach Adp UART %d "
		       "interrupt vector=%d\n", port->line, port->irq);
		return ret;
	}

	/* Enable RX interrupts now */
	spin_lock_irqsave(&port->lock, flags);
	pre = qsp_uart_readl(port, CONTROL_REG);
	qsp_uart_writel(port, pre | RX_INT, CONTROL_REG);
	spin_unlock_irqrestore(&port->lock, flags);

	return 0;
}

static void qsp_uart_shutdown(struct uart_port *port)
{
	unsigned long flags;

	spin_lock_irqsave(&port->lock, flags);

	/* Disable all interrupts now */
	qsp_uart_writel(port, 0, CONTROL_REG);

	spin_unlock_irqrestore(&port->lock, flags);

	free_irq(port->irq, port);
}

static const char *qsp_uart_type(struct uart_port *port)
{
	return (port->type == PORT_QSP_UART) ? "QSP UART" : NULL;
}

static int qsp_uart_request_port(struct uart_port *port)
{
	/* Resources taken in probe. */
	dev_dbg(port->dev, "request port\n");
	return 0;
}

static void qsp_uart_release_port(struct uart_port *port)
{
	/* Nothing to release... */
	dev_dbg(port->dev, "release port\n");
}

static int qsp_uart_verify_port(struct uart_port *port,
				   struct serial_struct *ser)
{
	if ((ser->type != PORT_UNKNOWN) && (ser->type != PORT_QSP_UART))
		return -EINVAL;
	return 0;
}

/* Define the basic serial functions we support.
 */
static struct uart_ops qsp_uart_ops = {
	.tx_empty	= qsp_uart_tx_empty,
	.get_mctrl	= qsp_uart_get_mctrl,
	.set_mctrl	= qsp_uart_set_mctrl,
	.start_tx	= qsp_uart_start_tx,
	.stop_tx	= qsp_uart_stop_tx,
	.stop_rx	= qsp_uart_stop_rx,
	.enable_ms	= qsp_uart_enable_ms,
	.break_ctl	= qsp_uart_break_ctl,
	.startup	= qsp_uart_startup,
	.shutdown	= qsp_uart_shutdown,
	.set_termios	= qsp_uart_set_termios,
	.type		= qsp_uart_type,
	.request_port	= qsp_uart_request_port,
	.release_port	= qsp_uart_release_port,
	.config_port	= qsp_uart_config_port,
	.verify_port	= qsp_uart_verify_port,
};

static struct qsp_uart qsp_uart_ports[CONFIG_SERIAL_QSP_MAXPORTS];

#if defined(CONFIG_SERIAL_QSP_CONSOLE)


static void qsp_uart_console_putc(struct uart_port *port, const char c)
{
	while (!(qsp_uart_readl(port, STATUS_REG) &
		 TX_READY))
		cpu_relax();

	qsp_uart_writel(port, c, TXDATA_REG);
}

static void qsp_uart_console_write(struct console *co, const char *s,
				      unsigned int count)
{
	struct uart_port *port = &(qsp_uart_ports + co->index)->port;

	for (; count; count--, s++) {
		qsp_uart_console_putc(port, *s);
		if (*s == '\n')
			qsp_uart_console_putc(port, '\r');
	}
}

static int __init qsp_uart_console_setup(struct console *co, char *options)
{
	struct uart_port *port;
	int baud = 115200;
	int bits = 8;
	int parity = 'n';
	int flow = 'n';

	if (co->index < 0 || co->index >= CONFIG_SERIAL_QSP_MAXPORTS)
		return -EINVAL;

	port = &qsp_uart_ports[co->index].port;
	if (!port->membase)
		return -ENODEV;

	if (options)
		uart_parse_options(options, &baud, &parity, &bits, &flow);

	return uart_set_options(port, co, baud, parity, bits, flow);
}

static struct uart_driver qsp_uart_driver;

static struct console qsp_uart_console = {
	.name	= "ttyAM",
	.write	= qsp_uart_console_write,
	.device	= uart_console_device,
	.setup	= qsp_uart_console_setup,
	.flags	= CON_PRINTBUFFER,
	.index	= -1,
	.data	= &qsp_uart_driver,
};

static int __init qsp_uart_console_init(void)
{
	register_console(&qsp_uart_console);
	return 0;
}

console_initcall(qsp_uart_console_init);

#define	ALT_UART_KEEP_CONSOLE	(&qsp_uart_console)

#else

#define	ALT_UART_KEEP_CONSOLE	NULL

#endif /* CONFIG_ALT_UART_KEEP_CONSOLE */

/* Define the qsp_uart UART driver structure.
 */
static struct uart_driver qsp_uart_driver = {
	.owner		= THIS_MODULE,
	.driver_name	= DRV_NAME,
	.dev_name	= "ttyAM",
	.major		= SERIAL_QSP_MAJOR,
	.minor		= SERIAL_QSP_MINOR,
	.nr		= CONFIG_SERIAL_QSP_MAXPORTS,
	.cons		= ALT_UART_KEEP_CONSOLE,
};

static int qsp_uart_probe(struct platform_device *pdev)
{
	struct resource res;
	struct uart_port *port;
	int i = pdev->id;
	u32 id;

	dev_dbg(&pdev->dev, "probe %d\n", i);
	/* if id is -1 scan for a free id and use that one */
	if (i == -1) {
		for (i = 0; i < CONFIG_SERIAL_QSP_MAXPORTS; i++)
			if (qsp_uart_ports[i].port.membase == 0)
				break;
	}

	if (i < 0 || i >= CONFIG_SERIAL_QSP_MAXPORTS)
		return -EINVAL;

	dev_dbg(&pdev->dev, "using index %d\n", i);
	port = &qsp_uart_ports[i].port;

	port->membase = of_iomap(pdev->dev.of_node, 0);
	port->irq = irq_of_parse_and_map(pdev->dev.of_node,  0);
	port->line = i;
	port->type = PORT_QSP_UART;
	port->iotype = SERIAL_IO_MEM;
	port->fifosize = 1;
	port->ops = &qsp_uart_ops;
	port->flags = UPF_BOOT_AUTOCONF;
	port->dev = &pdev->dev;
	dev_set_drvdata(&pdev->dev, port);

	/* Get phys addr of membase as well,
	 * for pretty print out by serial_core.c */
	of_address_to_resource(pdev->dev.of_node, 0, &res);
	port->mapbase = res.start;

	id = qsp_uart_readl(port, 0);
	dev_dbg(&pdev->dev, "id %08x\n", id);
	if (id != QSP_SERIAL_ID_VAL)
		return -ENODEV;

	uart_add_one_port(&qsp_uart_driver, port);
	dev_dbg(&pdev->dev, "one port added\n");
	return 0;
}

static int qsp_uart_remove(struct platform_device *pdev)
{
	struct uart_port *port = dev_get_drvdata(&pdev->dev);

	if (port) {
		uart_remove_one_port(&qsp_uart_driver, port);
		dev_set_drvdata(&pdev->dev, NULL);
		port->mapbase = 0;
	}

	return 0;
}

static struct of_device_id qsp_uart_match[] = {
	{ .compatible = "qsp-serial" },
	{},
};
MODULE_DEVICE_TABLE(of, qsp_uart_match);

static struct platform_driver qsp_uart_platform_driver = {
	.probe	= qsp_uart_probe,
	.remove	= qsp_uart_remove,
	.driver	= {
		.name		= DRV_NAME,
		.owner		= THIS_MODULE,
		.of_match_table	= of_match_ptr(qsp_uart_match),
	},
};

static int __init qsp_uart_init(void)
{
	int rc;
	rc = uart_register_driver(&qsp_uart_driver);
	if (rc) {
		pr_err(DRV_NAME "Failed to register uart driver.\n");
		return rc;
	}

	rc = platform_driver_register(&qsp_uart_platform_driver);
	if (rc) {
		pr_err(DRV_NAME "Failed to register platform driver.\n");
		uart_unregister_driver(&qsp_uart_driver);
	}
	return rc;
}

static void __exit qsp_uart_exit(void)
{
	platform_driver_unregister(&qsp_uart_platform_driver);
	uart_unregister_driver(&qsp_uart_driver);
}

module_init(qsp_uart_init);
module_exit(qsp_uart_exit);

MODULE_DESCRIPTION("QSP UART driver");
MODULE_AUTHOR("Ivar Holmqvist <ivarholmqvist@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:" DRV_NAME);
MODULE_ALIAS_CHARDEV_MAJOR(SERIAL_QSP_MAJOR);
