/*
 * Driver for QSP Ethernet device
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
#include <linux/delay.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/phy.h>
#include <linux/in.h>
#include <linux/io.h>
#include <linux/ip.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <linux/spinlock.h>
#include <linux/qsp/qsp.h>


#define TX_BD_NUM   128
#define RX_BD_NUM   128

#define QSP_FRAME_SIZE 1518

/* Register offsets.
 */
#define QSP_NET_ID       0x0000
#define QSP_NET_STATUS   0x0004
#define QSP_NET_CONTROL  0x0008
#define QSP_NET_TX_DESC  0x0010
#define QSP_NET_TX_SZ    0x0014
#define QSP_NET_TX_CI    0x0018
#define QSP_NET_TX_PI    0x001c
#define QSP_NET_RX_DESC  0x0020
#define QSP_NET_RX_SZ    0x0024
#define QSP_NET_RX_CI    0x0028
#define QSP_NET_RX_PI    0x002c
#define QSP_NET_MDIO     0x0100

#define QSP_NET_MAC_ADDR(i)     (0x030+(i)*4)

/* Bit defines.
 */
#define CONTROL_RESET (1<<0)


struct qsp_net_bd {
	u32 __phys;
	u32 __len;
};

/* Don't access the buffer descriptors directly. They are big-endian.
 */
#define BD_GET_PHYS(bd) be32_to_cpu((bd).__phys)
#define BD_GET_LEN(bd)  be32_to_cpu((bd).__len)
#define BD_SET_PHYS(bd, p) do {(bd).__phys = cpu_to_be32(p); } while (0)
#define BD_SET_LEN(bd, l)  do {(bd).__len = cpu_to_be32(l); } while (0)

struct qsp_net_local {
	struct net_device *ndev;
	struct device *dev;

	void __iomem *regs;
	int tx_irq;

	struct sk_buff **rx_skb;
	struct sk_buff **tx_skb;
	spinlock_t tx_lock;

	/* Buffer descriptors */
	struct qsp_net_bd *tx_bd_v;
	dma_addr_t tx_bd_p;
	struct qsp_net_bd *rx_bd_v;
	dma_addr_t rx_bd_p;
};


/*
 * Low level register access functions
 */
u32 qsp_net_readl(struct qsp_net_local *lp, int offset)
{
	u32 ret;
	ret = readl(lp->regs + offset);
	pr_debug("read %08x regs @ %p -> %08x\n", offset, lp->regs, ret);
	return ret;
}

u8 qsp_net_readb(struct qsp_net_local *lp, int offset)
{
	u8 ret;
	ret = (u8)readl(lp->regs + offset);
	pr_debug("read %08x regs @ %p -> %08x\n", offset, lp->regs, ret);
	return ret;
}

void qsp_net_writel(struct qsp_net_local *lp, int offset, u32 value)
{
	pr_debug("write %08x %08x regs @ %p\n", value, offset, lp->regs);
	writel(value, lp->regs + offset);
}

void qsp_net_writeb(struct qsp_net_local *lp, int offset, u8 value)
{
	pr_debug("write %08x %08x regs @ %p\n", value, offset, lp->regs);
	writel((u32)value, lp->regs + offset);
}

/**
 *  qsp_net_bd_release - Release buffer descriptor rings
 */
static void qsp_net_bd_release(struct net_device *ndev)
{
	struct qsp_net_local *lp = netdev_priv(ndev);
	int i;

	/* Release/free descriptors, skb:s and ptr arrays.
	 */
	if (lp->rx_skb) {
		for (i = 0; i < RX_BD_NUM; i++) {
			if (!lp->rx_skb[i])
				continue;
			pr_debug("Release RX skb %p\n", lp->rx_skb[i]);
			dev_kfree_skb(lp->rx_skb[i]);
			lp->rx_skb[i] = 0;
		}
		pr_debug("Release RX skb_arr %p\n", lp->rx_skb);
		kfree(lp->rx_skb);
		lp->rx_skb = 0;
	}
	if (lp->rx_bd_v) {
		pr_debug("Release rx_bd_v %p\n", lp->rx_bd_v);
		kfree(lp->rx_bd_v);
		lp->rx_bd_v = 0;
	}

	if (lp->tx_skb) {
		for (i = 0; i < TX_BD_NUM; i++) {
			if (!lp->tx_skb[i])
				continue;
			pr_debug("Release TX skb %p\n", lp->tx_skb[i]);
			dev_kfree_skb(lp->tx_skb[i]);
			lp->tx_skb[i] = 0;
		}
		pr_debug("Release TX skb_arr %p\n", lp->tx_skb);
		kfree(lp->tx_skb);
		lp->tx_skb = 0;
	}
	if (lp->tx_bd_v) {
		pr_debug("Release tx_bd_v %p\n", lp->tx_bd_v);
		kfree(lp->tx_bd_v);
		lp->tx_bd_v = 0;
	}
	pr_debug("bd_release done.\n");
}

static int add_one_rx_bd(struct net_device *ndev)
{
	struct qsp_net_local *lp = netdev_priv(ndev);
	struct sk_buff *skb;
	int pi;

	pi  = qsp_net_readl(lp, QSP_NET_RX_PI);
	if (pi == RX_BD_NUM)
		return 0;

	skb = netdev_alloc_skb_ip_align(ndev,
					QSP_FRAME_SIZE);
	if (skb == 0) {
		dev_err(&ndev->dev, "alloc_skb error %d\n", pi);
		return 0;
	}
	pr_debug("num_frags %d\n", skb_shinfo(skb)->nr_frags);
	BUG_ON(skb_shinfo(skb)->nr_frags > 1);
	lp->rx_skb[pi] = skb;
	/* returns physical address of skb->data */
	BD_SET_PHYS(lp->rx_bd_v[pi], virt_to_phys(skb->data));
	BD_SET_LEN(lp->rx_bd_v[pi], QSP_FRAME_SIZE);

	pr_debug("add_one_rx_bd[%d]: phys:%08x len:%d (%d)\n",
		 pi,
		 BD_GET_PHYS(lp->rx_bd_v[pi]),
		 BD_GET_LEN(lp->rx_bd_v[pi]), QSP_FRAME_SIZE);
	qsp_net_writel(lp, QSP_NET_RX_PI, pi);
	return 1;
}

static void process_tx(struct net_device *ndev, int in_interrupt)
{
	struct qsp_net_local *lp = netdev_priv(ndev);
	int ti;
	struct sk_buff *skb;
	int loops;

	/* Check for transmitted entries on the consumer index.
	 */
	loops = 0;
	while ((ti = qsp_net_readl(lp, QSP_NET_TX_CI)) != TX_BD_NUM) {
		pr_debug("got tx index %d\n", ti);
		loops++;
		skb = lp->tx_skb[ti];
		WARN_ON(skb == NULL);
		if (in_interrupt)
			dev_kfree_skb_irq(skb);
		else
			dev_kfree_skb(skb);
		lp->tx_skb[ti] = 0;
		ndev->stats.tx_packets++;
		ndev->stats.tx_bytes += BD_GET_LEN(lp->tx_bd_v[ti]);

		/* Release the entry back to the mac
		 */
		qsp_net_writel(lp, QSP_NET_TX_CI, ti);
		netif_wake_queue(ndev);
	}
	pr_debug("process_tx: Handled %d skb:s in %s mode\n",
		 loops, in_interrupt ? "interrupt" : "normal");
}


/**
 * qsp_net_bd_init - Setup buffer descriptor rings
 */
static int qsp_net_bd_init(struct net_device *ndev)
{
	struct qsp_net_local *lp = netdev_priv(ndev);

	int num_rx;

	lp->rx_skb = kcalloc(RX_BD_NUM, sizeof(*lp->rx_skb), GFP_KERNEL);
	if (!lp->rx_skb) {
		dev_err(&ndev->dev,
			"can't allocate memory for DMA RX skb pointers.\n");
		goto out;
	}
	lp->tx_skb = kcalloc(TX_BD_NUM, sizeof(*lp->tx_skb), GFP_KERNEL);
	if (!lp->tx_skb) {
		dev_err(&ndev->dev,
			"can't allocate memory for DMA TX skb pointers.\n");
		goto out;
	}
	/* allocate the tx and rx ring buffer descriptors. */
	/* returns a virtual address and a physical address. */
	lp->rx_skb = kcalloc(RX_BD_NUM, sizeof(*lp->rx_skb), GFP_KERNEL);
	lp->tx_bd_v = kcalloc(TX_BD_NUM, sizeof(struct qsp_net_bd), GFP_KERNEL);
	if (!lp->tx_bd_v) {
		dev_err(&ndev->dev,
				"unable to allocate DMA TX buffer descriptors");
		goto out;
	}
	lp->rx_bd_v = kcalloc(RX_BD_NUM, sizeof(struct qsp_net_bd), GFP_KERNEL);
	if (!lp->rx_bd_v) {
		dev_err(&ndev->dev,
				"unable to allocate DMA RX buffer descriptors");
		goto out;
	}

	memset(lp->tx_bd_v, 0, sizeof(*lp->tx_bd_v) * TX_BD_NUM);
	qsp_net_writel(lp, QSP_NET_TX_DESC, virt_to_phys(lp->tx_bd_v));
	qsp_net_writel(lp, QSP_NET_TX_SZ, TX_BD_NUM);

	qsp_net_writel(lp, QSP_NET_RX_DESC, virt_to_phys(lp->rx_bd_v));
	qsp_net_writel(lp, QSP_NET_RX_SZ, RX_BD_NUM);

	num_rx = 0;
	while (add_one_rx_bd(ndev) == 1)
		num_rx++;

	pr_debug("%d != %d\n", num_rx, RX_BD_NUM);
	WARN_ON(num_rx+1 != RX_BD_NUM);

	return 0;

out:
	qsp_net_bd_release(ndev);
	return -ENOMEM;
}

/* ---------------------------------------------------------------------
 * net_device_ops
 */

static int qsp_net_set_mac_address(struct net_device *ndev, void *address)
{
	int i;
	struct qsp_net_local *lp = netdev_priv(ndev);

	if (address)
		memcpy(ndev->dev_addr, address, ETH_ALEN);

	if (!is_valid_ether_addr(ndev->dev_addr))
		eth_hw_addr_random(ndev);
	else
		ndev->addr_assign_type &= ~NET_ADDR_RANDOM;

	for (i = 0; i < 6; i++)
		qsp_net_writeb(lp, QSP_NET_MAC_ADDR(i), ndev->dev_addr[i]);

	return 0;
}

static int netdev_set_mac_address(struct net_device *ndev, void *p)
{
	struct sockaddr *addr = p;

	return qsp_net_set_mac_address(ndev, addr->sa_data);
}

/* Initialize qsp_net */
static void qsp_net_device_reset(struct net_device *ndev)
{
	if (qsp_net_bd_init(ndev)) {
		dev_err(&ndev->dev,
			"qsp_net_device_reset descriptor allocation failed\n");
	}

	qsp_net_set_mac_address(ndev, NULL);

	/* Init Driver variable */
	ndev->trans_start = jiffies; /* prevent tx timeout */
}


static int qsp_net_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct qsp_net_local *lp = netdev_priv(ndev);

	pr_debug("Transmit %p %p\n", skb, skb->data);
	BUG_ON(skb_shinfo(skb)->nr_frags > 1);
	{
		int ti;
		unsigned long flags;

		/* Try to get a fresh producer index in the ring.
		 */
		ti = qsp_net_readl(lp, QSP_NET_TX_PI);
		if (ti == TX_BD_NUM) {
			pr_debug("Not enough free tx descriptors in ring.\n");
			if (!netif_queue_stopped(ndev)) {
				pr_debug("Stopping queue\n");
				netif_stop_queue(ndev);
			}
			return NETDEV_TX_BUSY;
		}
		pr_debug("xmit index %d\n", ti);

		/* Fill in the buffer descriptor at that index.
		 */
		BD_SET_PHYS(lp->tx_bd_v[ti], virt_to_phys(skb->data));
		BD_SET_LEN(lp->tx_bd_v[ti], skb->len);

		pr_debug("Send packet of len %d\n", skb->len);

		/* Kick off the transfer.
		 */
		pr_debug("tx_desc[%d]: %08x %d\n", ti,
			 BD_GET_PHYS(lp->tx_bd_v[ti]),
			 BD_GET_LEN(lp->tx_bd_v[ti]));
		lp->tx_skb[ti] = skb;
		spin_lock_irqsave(&lp->tx_lock, flags);
		qsp_net_writel(lp, QSP_NET_TX_PI, ti);
		skb_tx_timestamp(skb);
		/* Check if it trasmitted immediately?
		 */
		process_tx(ndev, 0);
		spin_unlock_irqrestore(&lp->tx_lock, flags);
	}

	return NETDEV_TX_OK;
}


static void process_rx(struct net_device *ndev)
{
	struct qsp_net_local *lp = netdev_priv(ndev);
	struct sk_buff *skb;
	struct qsp_net_bd *cur_p;
	int ci;

	do {
		ci = qsp_net_readl(lp, QSP_NET_RX_CI);
		if (ci == RX_BD_NUM) {
			pr_debug("No more rx descriptors in ring.\n");
			break;
		}
		pr_debug("Got rx index %d\n", ci);
		qsp_net_writel(lp, QSP_NET_RX_CI, ci);

		cur_p = &lp->rx_bd_v[ci];
		skb = lp->rx_skb[ci];
		pr_debug("bd[%d] skb:%p phys:0x%08x : %d\n",
			 ci, skb, BD_GET_PHYS(*cur_p), BD_GET_LEN(*cur_p));
		skb_put(skb, BD_GET_LEN(*cur_p));

		skb->dev = ndev;
		skb->protocol = eth_type_trans(skb, ndev);

		if (!skb_defer_rx_timestamp(skb)) {
			lp->rx_skb[ci] = 0;
			netif_rx(skb);
		} else {
			/* FIXME: needs investigation... */
			BUG_ON(1);
		}

		ndev->stats.rx_packets++;
		ndev->stats.rx_bytes += BD_GET_LEN(*cur_p);

		add_one_rx_bd(ndev);

	} while (1);
}

static irqreturn_t ll_qsp_net_irq(int irq, void *_ndev)
{
	struct net_device *ndev = _ndev;
	struct qsp_net_local *lp = netdev_priv(ndev);

	pr_debug("GOT IRQ\n");
	process_rx(ndev);
	spin_lock(&lp->tx_lock);
	process_tx(ndev, 1);
	spin_unlock(&lp->tx_lock);
	return IRQ_HANDLED;
}

static int qsp_net_open(struct net_device *ndev)
{
	struct qsp_net_local *lp = netdev_priv(ndev);
	int rc;

	dev_dbg(&ndev->dev, "qsp_net_open()\n");

	qsp_net_device_reset(ndev);

	rc = request_irq(lp->tx_irq, ll_qsp_net_irq, 0, ndev->name, ndev);
	if (rc) {
		dev_err(lp->dev, "request_irq() failed\n");
		return rc;
	}
	return 0;
}

static int qsp_net_stop(struct net_device *ndev)
{
	struct qsp_net_local *lp = netdev_priv(ndev);

	/* Stop tx/rx
	 */
	qsp_net_writel(lp, QSP_NET_CONTROL, CONTROL_RESET);

	dev_dbg(&ndev->dev, "qsp_net_close()\n");

	free_irq(lp->tx_irq, ndev);

#if 0
	if (lp->phy_dev)
		phy_disconnect(lp->phy_dev);
	lp->phy_dev = NULL;
#endif
	qsp_net_bd_release(ndev);

	return 0;
}

static int qsp_net_ioctl(struct net_device *ndev, struct ifreq *rq, int cmd)
{
	return -EINVAL;
}

static const struct net_device_ops qsp_net_netdev_ops = {
	.ndo_open = qsp_net_open,
	.ndo_stop = qsp_net_stop,
	.ndo_start_xmit = qsp_net_start_xmit,
	.ndo_set_mac_address = netdev_set_mac_address,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_do_ioctl = qsp_net_ioctl,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller = qsp_net_poll_controller,
#endif
};


static int qsp_mac_probe(struct platform_device *op)
{
	struct device_node *np;
	struct qsp_net_local *lp;
	struct net_device *ndev;
	u8 macaddr[6];

	int rc = 0;
	int i;

	/* Init network device structure */
	ndev = alloc_etherdev(sizeof(*lp));
	if (!ndev) {
		pr_err("Failed to alloc etherdev\n");
		return -ENOMEM;
	}
	ether_setup(ndev);
	dev_set_drvdata(&op->dev, ndev);
	SET_NETDEV_DEV(ndev, &op->dev);
	ndev->flags &= ~IFF_MULTICAST;  /* clear multicast */
#if 0
	ndev->features = NETIF_F_SG | NETIF_F_FRAGLIST;
#endif
	ndev->netdev_ops = &qsp_net_netdev_ops;

	ndev->features |= NETIF_F_HIGHDMA; /* Can DMA to high memory. */

	/* setup qsp_net private info structure */
	lp = netdev_priv(ndev);
	lp->ndev = ndev;
	lp->dev = &op->dev;

	spin_lock_init(&lp->tx_lock);

	/* map device registers */
	lp->regs = of_iomap(op->dev.of_node, 0);
	if (!lp->regs) {
		dev_err(&op->dev, "could not map qsp_net regs eth.\n");
		goto nodev;
	}
	pr_debug("regs @ %p\n", lp->regs);

	/* Check that it's instantiated.
	 */
	if (qsp_net_readl(lp, QSP_NET_ID) != QSP_NET_ID_VAL) {
		pr_debug("Could not find eth\n");
		goto nodev;
	}

	np = op->dev.of_node;
	pr_debug("IRQ 0 %p\n", np);
	lp->tx_irq = irq_of_parse_and_map(np, 0);
	pr_debug("ok %d\n", lp->tx_irq);

	of_node_put(np); /* Finished with the node; drop the reference */

	if (!lp->tx_irq) {
		dev_err(&op->dev, "could not determine irq\n");
		rc = -ENOMEM;
		goto err_no_irq;
	}


	for (i = 0; i < 6; i++) {
		/* Retrieve the MAC address */
		macaddr[i] = qsp_net_readb(lp, QSP_NET_MAC_ADDR(i));
		pr_debug("MAC%d %02x\n", i, macaddr[i]);
	}
	qsp_net_set_mac_address(ndev, (void *)macaddr);

	rc = register_netdev(lp->ndev);
	if (rc) {
		dev_err(lp->dev, "register_netdev() error (%i)\n", rc);
		goto err_register_ndev;
	}
	pr_info("qsp_net: succesfully probed\n");
	return 0;

 err_no_irq:
 err_register_ndev:
	iounmap(lp->regs);
 nodev:
	free_netdev(ndev);
	ndev = NULL;
	return rc;
}

static int qsp_mac_remove(struct platform_device *op)
{
	struct net_device *ndev = dev_get_drvdata(&op->dev);
	struct qsp_net_local *lp = netdev_priv(ndev);

	unregister_netdev(ndev);

	dev_set_drvdata(&op->dev, NULL);
	iounmap(lp->regs);
	free_netdev(ndev);
	return 0;
}

static struct of_device_id qsp_mac_match[] = {
	{ .compatible = "qsp-mac", },
	{},
};
MODULE_DEVICE_TABLE(of, qsp_mac_match);

static struct platform_driver qsp_mac_driver = {
	.probe = qsp_mac_probe,
	.remove = qsp_mac_remove,
	.driver = {
		.owner = THIS_MODULE,
		.name = "qsp-mac",
		.of_match_table = qsp_mac_match,
	},
};

module_platform_driver(qsp_mac_driver);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Ethernet support for QSP");
MODULE_AUTHOR("Anders Wallin <anders.wallin@windriver.com>");
