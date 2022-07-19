/* This Software is part of Wind River Simics. The rights to copy, distribute,
   modify, or otherwise make use of this Software may be licensed only
   pursuant to the terms of an applicable license agreement.
 
   Copyright 2010-2019 Intel Corporation */

#include "gdb-remote.h"

static const regspec_t regs[] = {
        {32, "er0",      regclass_i},
        {32, "er1",      regclass_i},
        {32, "er2",      regclass_i},
        {32, "er3",      regclass_i},
        {32, "er4",      regclass_i},
        {32, "er5",      regclass_i},
        {32, "er6",      regclass_i},
        {32, "sp",       regclass_i},
        {8, "ccr",      regclass_i},
        {8, "ccr_pad1", regclass_unused},
        {16, "ccr_pad2", regclass_unused},
        {32, "pc",       regclass_i},
        {32, "cycles",   regclass_unused},
        {8, "exr",      regclass_i},
        {8, "exr_pad1", regclass_unused},
        {16, "exr_pad2", regclass_unused},
        {32, "ticks",    regclass_unused},
        {32, "insts",    regclass_unused},
        {32, "mach",     regclass_unused},
        {32, "macl",     regclass_unused},
        {32, "sbr",      regclass_unused},
        {32, "vbr",      regclass_unused},
};

const gdb_arch_t gdb_arch_h8300 = {
        .name = "h8300",
        .arch_name = "h8300",
        .help = {
                .target_flag = "h8300-elf",
                .prompt_cmd = "set architecture h8300(s|h)"
        },
        .is_be = true,
        .regs = regs,
        .nregs = ALEN(regs)
};
