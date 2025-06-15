/*
 * Copyright 2012 Wind River
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#ifndef __QSP_SMP_H
#define __QSP_SMP_H

void qsp_smp_init(void);
void qsp_smp_early_init(void);
extern void __secondary_start_qsp(void);

#endif
