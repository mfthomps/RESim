/*
 * drivers/mtd/chips/qsp-flash.c
 *
 * Flash driver for the QSP platform
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

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <asm/byteorder.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/map.h>
#include <linux/qsp/qsp.h>

#define DEVICE_TYPE "QSP Flash"

static int qsp_flash_read(struct mtd_info *, loff_t, size_t,
			  size_t *, u_char *);
static int qsp_flash_write(struct mtd_info *, loff_t, size_t,
			   size_t *, const u_char *);
static int qsp_flash_erase(struct mtd_info *, struct erase_info *);
static void qsp_flash_nop(struct mtd_info *);
static struct mtd_info *qsp_flash_probe(struct map_info *map);
static unsigned long qsp_flash_unmapped_area(struct mtd_info *, unsigned long,
					     unsigned long, unsigned long);

static struct mtd_chip_driver qsp_flash_chipdrv = {
	.probe	= qsp_flash_probe,
	.name	= "qsp-probe",
	.module	= THIS_MODULE
};

static uint32_t flash_property_at(struct map_info *map, uint32_t at)
{
	volatile uint32_t *flash = (uint32_t *)map->virt;
	*flash = 0xd00dd00d;
	flash += at;
	return *flash;
}

static struct mtd_info *qsp_flash_probe(struct map_info *map)
{
	struct mtd_info *mtd;
	uint32_t fl_size = 0;
	pr_info(DEVICE_TYPE ": Probing Chip at %p (virt) / 0x%x (phys)\n",
		map->virt, map->phys);

	if (flash_property_at(map, 0) == QSP_FLASH_ID_VAL)
		pr_info(DEVICE_TYPE ": Detected QSP Flash!\n");
	else
		return NULL;

	fl_size = flash_property_at(map, 1);
	pr_info(DEVICE_TYPE ": Detected Size of 0x%x!\n", fl_size);
	if (fl_size != map->size) {
		pr_info(DEVICE_TYPE ": Size does not match kernel config!\n");
		return NULL;
	}

	mtd = kzalloc(sizeof(*mtd), GFP_KERNEL);
	if (!mtd)
		return NULL;

	map->fldrv = &qsp_flash_chipdrv;
	mtd->priv = map;
	mtd->name = map->name;
	mtd->type = MTD_NORFLASH;
	mtd->size = map->size;
	mtd->_erase = qsp_flash_erase;
	mtd->_get_unmapped_area = qsp_flash_unmapped_area;
	mtd->_read = qsp_flash_read;
	mtd->_write = qsp_flash_write;
	mtd->_sync = qsp_flash_nop;
	mtd->flags = MTD_CAP_NORFLASH;
	mtd->writesize = 1;

	mtd->erasesize = PAGE_SIZE;
	while (mtd->size & (mtd->erasesize - 1))
		mtd->erasesize >>= 1;

	__module_get(THIS_MODULE);
	return mtd;
}

/* Allow NOMMU mmap() to directly map the device (if not NULL)
 * - return the address to which the offset maps
 * - return -ENOSYS to indicate refusal to do the mapping
 */
static unsigned long qsp_flash_unmapped_area(struct mtd_info *mtd,
					     unsigned long len,
					     unsigned long offset,
					     unsigned long flags)
{
	struct map_info *map = mtd->priv;
	return (unsigned long) map->virt + offset;
}

static int qsp_flash_read(struct mtd_info *mtd, loff_t from,
			  size_t len, size_t *retlen, u_char *buf)
{
	struct map_info *map = mtd->priv;
	map_copy_from(map, buf, from, len);
	*retlen = len;
	return 0;
}

static int qsp_flash_write(struct mtd_info *mtd, loff_t to,
			   size_t len, size_t *retlen, const u_char *buf)
{
	struct map_info *map = mtd->priv;
	volatile uint8_t *flash = map->virt + to;
	unsigned int i, num, left;
	volatile uint32_t *aligned;
	uint32_t data;

	num = (uint32_t)to & 0x3;
	aligned = (volatile uint32_t *)((unsigned long)flash - num);
	left = len;

	if (num != 0) {
		data = *aligned;

		for (i = num ; i < 4; i++) {
			data &= ~(0xFF << ((3 - i) * 8));
			data |= ((*(buf + i - num)) << ((3 - i) * 8));
		}

		*aligned = 0xdeadbeef;
		*aligned = data;

		buf  += (4 - num);
		left -= (4 - num);
		aligned++;
	}

	while (left >= 4) {
		data = *(uint32_t *)buf;
		*aligned = 0xdeadbeef;
		*aligned = data;
		buf  += 4;
		left -= 4;
		aligned++;
	}

	if (left > 0) {
		data = *aligned;

		for (i = 0 ; i < left; i++) {
			data &= ~(0xFF << ((3 - i) * 8));
			data |= ((*(buf + i)) << ((3 - i) * 8));
		}

		*aligned = 0xdeadbeef;
		*aligned = data;
	}

	*retlen = len;
	return 0;
}

static int qsp_flash_erase(struct mtd_info *mtd, struct erase_info *instr)
{
	struct map_info *map = mtd->priv;
	unsigned long i;
	volatile uint32_t *flash =
		(volatile uint32_t *)((uint8_t *)map->virt + instr->addr);

	for (i = 0; i < instr->len; i += 4) {
		*flash = 0xdeadbeef;
		*flash = 0xffffffff;
		flash++;
	}
	instr->state = MTD_ERASE_DONE;
	mtd_erase_callback(instr);
	return 0;
}

static void qsp_flash_nop(struct mtd_info *mtd)
{
	/* Nothing to see here */
}

static int __init qsp_flash_init(void)
{
	pr_info("QSP FLash Init");
	register_mtd_chip_driver(&qsp_flash_chipdrv);
	return 0;
}

static void __exit qsp_flash_exit(void)
{
	unregister_mtd_chip_driver(&qsp_flash_chipdrv);
}
module_init(qsp_flash_init);
module_exit(qsp_flash_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Wind River");
MODULE_DESCRIPTION("MTD chip driver for QSP Flash");
