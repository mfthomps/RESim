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

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/hdreg.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/interrupt.h>

#include <linux/qsp/qsp.h>

#define MINOR_SHIFT     4
#define QSP_BLK_MINORS	(1<<MINOR_SHIFT)
#define QSP_BLK_MAJOR	99
#define DEVICE_NAME	"qspblk"
#define QSP_DISK_NAME	"qspd"
#define QSP_BLK_SIZE	512

/* Commands */
#define QSP_BLK_CMD_READ  0x101
#define QSP_BLK_CMD_WRITE 0x102
#define QSP_BLK_CMD_SENSE 0x103

/* Registers */
#define ID            0x00
#define STATUS        0x04
#define CONTROL       0x08
#define CMD           0x0C
#define CMD_RESPONSE  0x10
#define BLOCK         0x14
#define PADDR         0x18


/* Status Register Bits */
#define STATUS_CMD_COMPLETE (1<<0)
#define STATUS_CHANN_ERR    (1<<1)
#define STATUS_SEEK_ERR     (1<<2)
#define STATUS_DMA_ERR      (1<<3)
#define STATUS_DISK_PRESENT (1<<4)

/* Control Register Bits */
#define CONTROL_IE   (1<<0)

static atomic_t usage_count = ATOMIC_INIT(0);

static int qsp_getgeo(struct block_device *bd, struct hd_geometry *hg)
{
	/* We don't have real geometry info, but let's at least return
	 * values consistent with the size of the device
	 */
	sector_t nsect = get_capacity(bd->bd_disk);
	sector_t cylinders = nsect;

	hg->heads = 0xff;
	hg->sectors = 0x3f;
	sector_div(cylinders, hg->heads * hg->sectors);
	hg->cylinders = cylinders;
	if ((sector_t)(hg->cylinders + 1) * hg->heads * hg->sectors < nsect)
		hg->cylinders = 0xffff;
	return 0;
}
/*
 * The device operations structure.
 */
static const struct block_device_operations qsp_blk_ops = {
	.owner   = THIS_MODULE,
	.getgeo  = qsp_getgeo,
};

struct qsp_blk {
	struct platform_device *ofdev;
	struct gendisk *gd;
	struct request_queue *queue;
	int idx;
	u64 size;
	unsigned int irq;
	void __iomem *base;
};

static void qsp_blk_write_register(struct qsp_blk *blk, int reg_num, u32 val)
{
	dev_dbg(&blk->ofdev->dev, "write reg %08x %08x\n", reg_num, val);
	writel(val, blk->base + reg_num);
}

static u32 qsp_blk_read_register(struct qsp_blk *blk, int reg_num)
{
	u32 ret;
	ret = readl(blk->base + reg_num);
	dev_dbg(&blk->ofdev->dev, "read reg %08x -> %08x\n", reg_num, ret);
	return ret;
}

/* The direct make request version.
 */
static void ablk_make_request(struct request_queue *q, struct bio *bio)
{
	struct qsp_blk *ablk = q->queuedata;
	int i;
	struct bio_vec *bvec;
	sector_t sector = bio->bi_sector;
	u32 status;

	dev_dbg(&ablk->ofdev->dev, "MAKE REQUEST %lld", sector);

	bio_for_each_segment(bvec, bio, i) {
		u64 paddr = page_to_phys(bvec->bv_page) + bvec->bv_offset;
		size_t len = bvec->bv_len;

		dev_dbg(&ablk->ofdev->dev, "i=%d\n", i);
		while (len > 0) {
			dev_dbg(&ablk->ofdev->dev, "paddr:%llx\n", paddr);
			qsp_blk_write_register(ablk, PADDR, (u32)paddr);
			qsp_blk_write_register(ablk, BLOCK, (u32)(sector));

			dev_dbg(&ablk->ofdev->dev,
				"sector: %lld len:%d size:%d\n", sector, len,
				bio->bi_size);

			switch (bio_data_dir(bio)) {
			case WRITE:
				qsp_blk_write_register(ablk,
						       CMD, QSP_BLK_CMD_WRITE);
				break;
			case READ:
				qsp_blk_write_register(ablk,
						       CMD, QSP_BLK_CMD_READ);
				break;
			}

			status = qsp_blk_read_register(ablk, STATUS);
			if (status & STATUS_CHANN_ERR) {
				dev_err(&ablk->ofdev->dev, "channel error\n");
				bio_endio(bio, -1);
				return;
			}
			if (status & STATUS_DMA_ERR) {
				dev_err(&ablk->ofdev->dev, "DMA error\n");
				bio_endio(bio, -1);
				return;
			}
			if (status & STATUS_SEEK_ERR) {
				dev_err(&ablk->ofdev->dev, "seek error\n");
				bio_endio(bio, -1);
				return;
			}
			if (status & STATUS_CMD_COMPLETE)
				dev_dbg(&ablk->ofdev->dev, "cmd complete\n");

			paddr += QSP_BLK_SIZE;
			sector += 1;
			len -= QSP_BLK_SIZE;
			dev_dbg(&ablk->ofdev->dev, "remain len %d\n", len);
		}
	}
	bio_endio(bio, 0);
}


static irqreturn_t ablk_interrupt(int irq, void *dev_id)
{
	pr_info("FIXME: CMD_SENSE interrupt.\n");
	return IRQ_HANDLED;
}


//static int __devinit qsp_blk_probe(struct platform_device *ofdev)
static int qsp_blk_probe(struct platform_device *ofdev)
{
	int err;
	struct qsp_blk *ablk;
	u32 status;
	u32 id;
	pr_debug("probe\n");

	ablk = kzalloc(sizeof(struct qsp_blk), GFP_KERNEL);
	if (!ablk) {
		err = -ENOMEM;
		goto no_mem;
	}
	ablk->ofdev = ofdev;
	dev_set_drvdata(&ofdev->dev, ablk);

	ablk->base = of_iomap(ofdev->dev.of_node, 0);
	if (ablk->base == NULL) {
		dev_err(&ofdev->dev, "failed to map resources.\n");
		err = -EINVAL;
		goto no_map;
	}

	id = qsp_blk_read_register(ablk, ID);
	if (id != QSP_BLK_ID_VAL) {
		dev_dbg(&ofdev->dev, "Failed to probe hardware with ID=0x%08x "
			" @%p\n", id, ablk->base);
		err = -ENODEV;
		goto bad_id;
	}

	/* FIXME: we assume that CMD_SENSE completes immediately if there
	 * is a disk connected...
	 */
	qsp_blk_write_register(ablk, CMD, QSP_BLK_CMD_SENSE);
	status = qsp_blk_read_register(ablk, STATUS);
	if (!(status & STATUS_CMD_COMPLETE)) {
		dev_info(&ofdev->dev, "No disk present, skipping this controller.");
		goto no_disk;
	}
	ablk->size = qsp_blk_read_register(ablk, CMD_RESPONSE);
	dev_info(&ofdev->dev, "Disk of size %lld attached\n", ablk->size);

	/* Setup the queue
	 * Direct make request is the easiest block device interface, would
	 * blk_init_queue() be significantly faster?
	 */
	ablk->queue = blk_alloc_queue(GFP_KERNEL);
	blk_queue_make_request(ablk->queue, ablk_make_request);
	if (ablk->queue == NULL) {
		err = -ENOMEM;
		goto no_queue;
	}
	ablk->queue->queuedata = ablk;

	/* Setup the disk
	 */
	ablk->gd = alloc_disk(QSP_BLK_MINORS);
	if (ablk->gd == NULL) {
		err = -ENOMEM;
		goto no_disk_mem;
	}

	ablk->idx = atomic_inc_return(&usage_count);
	ablk->gd->major = QSP_BLK_MAJOR;
	ablk->gd->first_minor = (ablk->idx - 1) << MINOR_SHIFT;
	ablk->gd->fops = &qsp_blk_ops;
	ablk->gd->queue = ablk->queue;
	ablk->gd->private_data = ofdev;
	ablk->gd->driverfs_dev = &ofdev->dev;
	snprintf(ablk->gd->disk_name,
		 sizeof(ablk->gd->disk_name),
		 "%s%c",
		 QSP_DISK_NAME,
		 ablk->idx+'a');
	set_capacity(ablk->gd, ablk->size);
	add_disk(ablk->gd);
	dev_info(&ofdev->dev, "add disk name:%s size:%lld done\n",
		 ablk->gd->disk_name, get_capacity(ablk->gd));

	/* Setup interrupt (currently unused...)
	 */
	ablk->irq = irq_of_parse_and_map(ofdev->dev.of_node,  0);
	dev_dbg(&ofdev->dev, "got irq %d\n", ablk->irq);
	if (!ablk->irq) {
		dev_err(&ofdev->dev, "IRQ not specified in dtb\n");
		return -EINVAL;
	}
	err = request_irq(ablk->irq, ablk_interrupt, 0, "qsp_blk",
			  ablk);
	if (err != 0) {
		dev_err(&ofdev->dev, "Failed to request irq %d\n",  err);
		return err;
	}

	return 0;
no_disk_mem:
	blk_cleanup_queue(ablk->queue);
no_queue:
no_disk:
	iounmap(ablk->base);
no_map:
bad_id:
	kfree(ablk);
no_mem:
	return err;
}

//static int __devexit qsp_blk_remove(struct platform_device *ofdev)
static int qsp_blk_remove(struct platform_device *ofdev)
{
	struct qsp_blk *ablk = dev_get_drvdata(&ofdev->dev);

	dev_info(&ofdev->dev, "removing disk\n");
	atomic_dec(&usage_count);

	if (ablk->gd) {
		dev_dbg(&ofdev->dev, "delete gendisk\n");
		del_gendisk(ablk->gd);
		put_disk(ablk->gd);
	}
	if (ablk->queue) {
		dev_dbg(&ofdev->dev, "cleanup queue\n");
		blk_cleanup_queue(ablk->queue);
	}

	dev_set_drvdata(&ofdev->dev, NULL);
	kfree(ablk);

	return 0;
}

static const struct of_device_id qsp_blk_match[] = {
	{ .compatible = "qsp,disk-controller" },
	{},
};
MODULE_DEVICE_TABLE(of, qsp_blk_match);

static struct platform_driver qsp_blk_driver = {
	.probe		= qsp_blk_probe,
	.remove		= qsp_blk_remove,
	.driver = {
		.name = "adb-blk",
		.owner = THIS_MODULE,
		.of_match_table = qsp_blk_match,
	},
};

static int qsp_blk_init(void)
{
	int berror;
	int perror;

	berror = register_blkdev(QSP_BLK_MAJOR, DEVICE_NAME);
	if (berror < 0) {
		pr_err("%s: register_blkdev failed - %d (major %d)\n",
		       DEVICE_NAME,
		       berror,
		       QSP_BLK_MAJOR);
		return berror;
	}

	perror = platform_driver_register(&qsp_blk_driver);
	if (perror) {
		pr_err("%s: platform_driver_register failed - %d\n",
		       DEVICE_NAME, berror);
		unregister_blkdev(QSP_BLK_MAJOR, DEVICE_NAME);
		return perror;
	}

	pr_info("%s: registered succesfully\n", DEVICE_NAME);
	return 0;
}

static void __exit qsp_blk_exit(void)
{
	platform_driver_unregister(&qsp_blk_driver);
}

module_init(qsp_blk_init);
module_exit(qsp_blk_exit);

MODULE_AUTHOR("Ivar Holmqvist <ivarholmqvist@gmail.com>");
MODULE_DESCRIPTION("Block device driver for disk controllers on QSP boards.");
MODULE_LICENSE("GPL");
