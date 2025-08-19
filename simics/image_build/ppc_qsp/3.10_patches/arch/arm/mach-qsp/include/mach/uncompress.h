/*
 *  arch/arm/mach-qsp/include/mach/uncompress.h
 *
 *  Copyright (C) 2012 Wind River
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/* Status register bits
 */
#define TX_READY (1<<0)
#define RX_READY (1<<1)

/* Control register bits
 */
#define TX_INT (1<<0)
#define RX_INT (1<<1)

/* Register defines
 */
#define ID_REG      0x00
#define STATUS_REG  0x04
#define CONTROL_REG 0x08
#define TXDATA_REG  0x0c
#define RXDATA_REG  0x10

#define QSP_SERIAL_BASE 0xe0010000

/*
 * This does not append a newline
 */
static inline void putc(int c)
{
	*(volatile unsigned long *)(QSP_SERIAL_BASE + TXDATA_REG) = c;
}

/*
 * nothing to do
 */
#define arch_decomp_setup()
#define arch_decomp_wdog()
#define flush()
