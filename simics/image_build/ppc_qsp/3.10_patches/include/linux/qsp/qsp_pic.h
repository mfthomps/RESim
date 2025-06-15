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

#ifndef __LINUX_QSP_PIC_H
#define __LINUX_QSP_PIC_H

void  qsp_pic_init(void);
unsigned int qsp_pic_get_irq(void);

#ifdef CONFIG_SMP
void qsp_pic_message_pass(int cpu, int msg);
void smp_qsp_pic_setup_cpu(int cpu);
int __init smp_qsp_pic_probe(void);
void qsp_ipi_eoi(int irq);

#define IPI_BASE 128
#ifdef CONFIG_ARM
/* FIXME: */
// ipi_msg_type for ARM begins from IPI_TIMER = 2 to IPI_CPU_STOP = 6
// then our IPI_NUM_TYPES needs to be 7. 7 is fine for the irq number limit
// in pic model
#define IPI_NUM_TYPES 7
#else
#define IPI_NUM_TYPES 4
#endif
#define IPI_NR(cpu, type) (IPI_BASE+(cpu)*IPI_NUM_TYPES+type)
#define IPI_GET_CPU(vipi) (((vipi)-IPI_BASE)/IPI_NUM_TYPES)
#define IPI_GET_MSG(vipi) (((vipi)-IPI_BASE)%IPI_NUM_TYPES)

#endif

#endif /* __LINUX_QSP_PIC_H */
