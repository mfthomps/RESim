/* This Software is part of Wind River Simics. The rights to copy, distribute,
   modify, or otherwise make use of this Software may be licensed only
   pursuant to the terms of an applicable Wind River license agreement.
 
   Copyright 2010-2017 Intel Corporation */

#include "gdb-remote.h"

static const regspec_t regs[] = {
        {32, "r0",   regclass_i},
        {32, "r1",   regclass_i},
        {32, "r2",   regclass_i},
        {32, "r3",   regclass_i},
        {32, "r4",   regclass_i},
        {32, "r5",   regclass_i},
        {32, "r6",   regclass_i},
        {32, "r7",   regclass_i},
        {32, "r8",   regclass_i},
        {32, "r9",   regclass_i},
        {32, "r10",  regclass_i},
        {32, "r11",  regclass_i},
        {32, "r12",  regclass_i},
        {32, "sp",   regclass_i},
        {32, "lr",   regclass_i},
        {32, "pc",   regclass_i},
        {32, "f0",   regclass_unused},
        {32, "f1",   regclass_unused},
        {32, "f2",   regclass_unused},
        {32, "f3",   regclass_unused},
        {32, "f4",   regclass_unused},
        {32, "f5",   regclass_unused},
        {32, "f6",   regclass_unused},
        {32, "f7",   regclass_unused},
        {32, "fps",  regclass_unused},
        {32, "cpsr", regclass_i},
};

const gdb_arch_t gdb_arch_armbe = {
        .name = "armbe",
        .arch_name = "arm",
        .help = {
                .target_flag = "armbe-unknown-linux-gnu",
                .prompt_cmd = NULL,
        },
        .is_be = true,
        .regs = regs,
        .nregs = ALEN(regs)
};
