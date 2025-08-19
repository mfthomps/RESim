/*
 * .../drivers/rtc/rtc-qsp.c
 *
 * Real-time clock driver for the QSP platform
 *
 * Copyright (c) 2012 Wind River Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/rtc.h>
#include <linux/of_device.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/qsp/qsp.h>

/* Register offsets */
#define ID_REG           0x00
#define TIME_REG         0x04
#define OFFSET_REG       0x08

struct qsp_rtc_priv {
	unsigned char __iomem *membase;
	struct rtc_device *rtc;
};

static int qsp_rtc_read_time(struct device *dev, struct rtc_time *tm)
{
	struct qsp_rtc_priv *priv = dev_get_drvdata(dev);
	unsigned long now;

	now = readl(priv->membase + TIME_REG) +
		readl(priv->membase + OFFSET_REG);
	pr_debug("%s: %li\n", __func__, now);
	rtc_time_to_tm(now, tm);

	return 0;
}


static int qsp_rtc_set_time(struct device *dev, struct rtc_time *tm)
{
	struct qsp_rtc_priv *priv = dev_get_drvdata(dev);
	unsigned long now;

	rtc_tm_to_time(tm, &now);
	now = now - readl(priv->membase + TIME_REG);

	pr_debug("%s: %li\n", __func__, now);
	writel(now, priv->membase + OFFSET_REG);

	return 0;
}

static const struct rtc_class_ops qsp_rtc_ops = {
	.read_time = qsp_rtc_read_time,
	.set_time = qsp_rtc_set_time,
};

static int qsp_rtc_probe(struct platform_device *pdev)
{
	struct qsp_rtc_priv *priv;

	dev_dbg(&pdev->dev, "%s\n", __func__);

	priv = kzalloc(sizeof(struct qsp_rtc_priv), GFP_KERNEL);
	if (!priv)
		return -ENODEV;

	priv->membase = of_iomap(pdev->dev.of_node, 0);
	if (priv->membase == NULL)
		goto err1;

	if (qsp_device_valid(priv->membase, QSP_RTC_ID_VAL) != 0)
		goto err2;

	platform_set_drvdata(pdev, priv);

	priv->rtc = rtc_device_register("qsp-rtc", &pdev->dev,
					&qsp_rtc_ops, THIS_MODULE);
	if (IS_ERR_OR_NULL(priv->rtc)) {
		dev_err(&pdev->dev, "Can't register RTC device (%p)\n",
			priv->rtc);
		goto err2;
	}

	return 0;

err2:
	iounmap(priv->membase);
err1:
	kfree(priv);
	return -ENODEV;
}

static int qsp_rtc_remove(struct platform_device *pdev)
{
	struct qsp_rtc_priv *priv = platform_get_drvdata(pdev);

	dev_dbg(&pdev->dev, "%s\n", __func__);

	rtc_device_unregister(priv->rtc);
	platform_set_drvdata(pdev, NULL);
	iounmap(priv->membase);
	kfree(priv);

	return 0;
}

static struct of_device_id of_qsp_rtc_match[] = {
	{ .compatible = "qsp-rtc", },
	{},
};

static struct platform_driver qsp_rtc_driver = {
	.probe = qsp_rtc_probe,
	.remove = qsp_rtc_remove,
	.driver = {
		.name = "qsp-rtc",
		.owner = THIS_MODULE,
		.of_match_table = of_qsp_rtc_match,
	},
};

module_platform_driver(qsp_rtc_driver);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("LED support for QSP");
MODULE_AUTHOR("Anders Wallin <anders.wallin@windriver.com>");
