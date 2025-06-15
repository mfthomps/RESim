/*
 * drivers/leds/leds-qsp.c
 *
 * LEDs driver for the QSP, driver based on the leds-gpio driver
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

#include <linux/kernel.h>
#include <linux/leds.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/io.h>
#include <linux/qsp/qsp.h>

#define NO_OF_LEDS       16

/* Register offsets */
#define ID_REG           0x00
#define LED_REG          0x04

/* LED register bits */
#define BRIGHTNESS_SHIFT 0
#define BRIGHTNESS_MASK  0x00000001

struct qsp_led_data {
	struct led_classdev cdev;
	unsigned char __iomem *reg;
};

struct qsp_leds_priv {
	unsigned char __iomem *membase;
	int num_leds;
	struct qsp_led_data leds[NO_OF_LEDS];
};

static void qsp_led_set(struct led_classdev *led_cdev,
			enum led_brightness value)
{
	struct qsp_led_data *led_data =
		container_of(led_cdev, struct qsp_led_data, cdev);

	pr_debug("%s: %s = %i\n", __func__, led_data->cdev.name, value);
	writel(value, led_data->reg);
}

static enum led_brightness qsp_led_get(struct led_classdev *led_cdev)
{
	int value;
	struct qsp_led_data *led_data =
		container_of(led_cdev, struct qsp_led_data, cdev);

	value = readl(led_data->reg);
	pr_debug("%s: %i\n", __func__, value);

	return value & BRIGHTNESS_MASK;
}

static int qsp_index_get(struct device_node *np)
{
	int index;

	if (of_property_read_u32(np, "index", &index)) {
		pr_warn("LED index not specified (%s)\n", np->name);
		return -EINVAL;
	}

	if ((index < 0) || (index >= NO_OF_LEDS)) {
		pr_warn("LED index outside valid area %i (0 - %i)\n",
			index, NO_OF_LEDS);
		return -EINVAL;
	}

	return index;
}

static char *qsp_get_led_name(struct device_node *np, struct device_node *child)
{
	const char *led_name;
	const char *ctrl_name;
	char *led_long_name;

	ctrl_name = of_get_property(np, "label", NULL) ? : np->name;
	led_name  = of_get_property(child, "label", NULL) ? : child->name;

	led_long_name = kmalloc(strlen(ctrl_name) + strlen(led_name) + 2,
				GFP_KERNEL);
	BUG_ON(led_long_name == NULL);

	strcpy(led_long_name, ctrl_name);
	strcat(led_long_name, "-");
	strcat(led_long_name, led_name);
	return led_long_name;
}

static struct qsp_leds_priv * __devinit qsp_leds_create_of(
	struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node, *child;
	struct qsp_leds_priv *priv;
	int ret;

	dev_dbg(&pdev->dev, "%s: Controller %s\n", __func__, np->name);

	priv = kzalloc(sizeof(struct qsp_leds_priv), GFP_KERNEL);
	if (!priv)
		return NULL;

	priv->membase = of_iomap(pdev->dev.of_node, 0);
	if (priv->membase == NULL)
		goto err1;

	if (qsp_device_valid(priv->membase, QSP_LED_ID_VAL) != 0)
		goto err2;

	for_each_child_of_node(np, child) {
		struct qsp_led_data *led_data;
		int index;

		if (priv->num_leds >= NO_OF_LEDS) {
			dev_warn(&pdev->dev, "To many LEDS defined in DTB\n");
			break;
		}

		led_data = &priv->leds[priv->num_leds];

		index = qsp_index_get(child);
		if (index < 0)
			continue;

		led_data->reg = priv->membase + (LED_REG + index * 4);
		led_data->cdev.name = qsp_get_led_name(np, child);
		led_data->cdev.default_trigger =
			of_get_property(child, "linux,default-trigger", NULL);
		led_data->cdev.brightness_set = qsp_led_set;
		led_data->cdev.brightness_get = qsp_led_get;
		led_data->cdev.brightness = 0; /* LED_OFF */
		led_data->cdev.max_brightness = 1;

		ret = led_classdev_register(&pdev->dev, &led_data->cdev);
		if (ret < 0) {
			dev_err(&pdev->dev, "Can't register LED device (%i)\n",
				ret);
			goto err2;
		}

		priv->num_leds++;
	}
	return priv;

err2:
	iounmap(priv->membase);
err1:
	kfree(priv);
	return NULL;
}

static int __devinit qsp_led_probe(struct platform_device *pdev)
{
	struct qsp_leds_priv *priv;

	priv = qsp_leds_create_of(pdev);
	if (!priv)
		return -ENODEV;

	platform_set_drvdata(pdev, priv);

	return 0;
}

static int __devexit qsp_led_remove(struct platform_device *pdev)
{
	struct qsp_leds_priv *priv = platform_get_drvdata(pdev);
	int i;

	for (i = 0; i < priv->num_leds; i++)
		led_classdev_unregister(&priv->leds[i].cdev);

	platform_set_drvdata(pdev, NULL);
	iounmap(priv->membase);

	kfree(priv);
	return 0;
}

static const struct of_device_id of_qsp_leds_match[] = {
	{ .compatible = "leds-qsp", },
	{ },
};

static struct platform_driver qsp_led_driver = {
	.probe = qsp_led_probe,
	.remove = __devexit_p(qsp_led_remove),
	.driver = {
		.name = "qsp-leds",
		.owner = THIS_MODULE,
		.of_match_table = of_qsp_leds_match,
	},
};

module_platform_driver(qsp_led_driver);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("LED support for QSP");
MODULE_AUTHOR("Anders Wallin <anders.wallin@windriver.com>");
