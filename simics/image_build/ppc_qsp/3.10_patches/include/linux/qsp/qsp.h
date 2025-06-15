/*
 *  Copyright 2012 Wind River, Inc
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef __LINUX_QSP_H
#define __LINUX_QSP_H

#define QSP_ID_VAL 0x12340000

#define QSP_PIC_ID_VAL     (QSP_ID_VAL | 0x0001)
#define QSP_SERIAL_ID_VAL  (QSP_ID_VAL | 0x0002)
#define QSP_BLK_ID_VAL     (QSP_ID_VAL | 0x0003)
#define QSP_RTC_ID_VAL     (QSP_ID_VAL | 0x0004)
#define QSP_LED_ID_VAL     (QSP_ID_VAL | 0x0005)
#define QSP_NET_ID_VAL     (QSP_ID_VAL | 0x0006)
#define QSP_TIMER_ID_VAL   (QSP_ID_VAL | 0x0007)
#define QSP_SYSREGS_ID_VAL (QSP_ID_VAL | 0x0008)
#define QSP_FLASH_ID_VAL   (QSP_ID_VAL | 0x0009)
#define QSP_PROBE_ID_VAL   (QSP_ID_VAL | 0x9999)


static inline int qsp_device_valid(unsigned char __iomem *addr, int device_id)
{
	int id = readl(addr);
	if (id == QSP_PROBE_ID_VAL) {
		pr_debug("Device id is probe (%x != %x)\n", id, device_id);
		return -EINVAL;
	} else if (id != device_id) {
		pr_warn("Device id is wrong (%x != %x)\n", id, device_id);
		return -EINVAL;
	} else
		return 0;
}

#endif /* __LINUX_QSP_H */
