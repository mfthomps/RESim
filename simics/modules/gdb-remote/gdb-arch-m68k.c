/* This Software is part of Wind River Simics. The rights to copy, distribute,
   modify, or otherwise make use of this Software may be licensed only
   pursuant to the terms of an applicable license agreement.
  
   Copyright 2010-2019 Intel Corporation */

#include "gdb-remote.h"

static const regspec_t regs[] = {
        {32, "d0", regclass_i},
        {32, "d1", regclass_i},
        {32, "d2", regclass_i},
        {32, "d3", regclass_i},
        {32, "d4", regclass_i},
        {32, "d5", regclass_i},
        {32, "d6", regclass_i},
        {32, "d7", regclass_i},
        {32, "a0", regclass_i},
        {32, "a1", regclass_i},
        {32, "a2", regclass_i},
        {32, "a3", regclass_i},
        {32, "a4", regclass_i},
        {32, "a5", regclass_i},
        {32, "a6", regclass_i},
        {32, "a7", regclass_i},
        {32, "sr", regclass_i},
        {32, "pc", regclass_i},
};

const gdb_arch_t gdb_arch_m68k = {
        .name = "m68k",
        .arch_name = "m68k",
        .help = {
                .target_flag = "m68k",
                .prompt_cmd = "set architecture m68k"
        },
        .is_be = true,
        .regs = regs,
        .nregs = ALEN(regs)
};
