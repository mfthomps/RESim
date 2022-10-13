/* This Software is part of Wind River Simics. The rights to copy, distribute,
   modify, or otherwise make use of this Software may be licensed only
   pursuant to the terms of an applicable license agreement.
 
   Copyright 2010-2019 Intel Corporation */

#include "gdb-remote.h"

static const regspec_t regs[] = {
        {32, "zero", regclass_i},
        {32, "at", regclass_i},
        {32, "v0", regclass_i},
        {32, "v1", regclass_i},
        {32, "a0", regclass_i},
        {32, "a1", regclass_i},
        {32, "a2", regclass_i},
        {32, "a3", regclass_i},
        {32, "t0", regclass_i},
        {32, "t1", regclass_i},
        {32, "t2", regclass_i},
        {32, "t3", regclass_i},
        {32, "t4", regclass_i},
        {32, "t5", regclass_i},
        {32, "t6", regclass_i},
        {32, "t7", regclass_i},
        {32, "s0", regclass_i},
        {32, "s1", regclass_i},
        {32, "s2", regclass_i},
        {32, "s3", regclass_i},
        {32, "s4", regclass_i},
        {32, "s5", regclass_i},
        {32, "s6", regclass_i},
        {32, "s7", regclass_i},
        {32, "t8", regclass_i},
        {32, "t9", regclass_i},
        {32, "k0", regclass_i},
        {32, "k1", regclass_i},
        {32, "gp", regclass_i},
        {32, "sp", regclass_i},
        {32, "fp", regclass_i},           /* s8 */
        {32, "ra", regclass_i},
        {32, "status", regclass_i},       /* sr */
        {32, "lo", regclass_i},
        {32, "hi", regclass_i},
        {32, "badvaddr", regclass_i},     /* bad */
        {32, "cause", regclass_i},
        {32, "pc", regclass_i},
        {32, "f0", regclass_unused},
        {32, "f1", regclass_unused},
        {32, "f2", regclass_unused},
        {32, "f3", regclass_unused},
        {32, "f4", regclass_unused},
        {32, "f5", regclass_unused},
        {32, "f6", regclass_unused},
        {32, "f7", regclass_unused},
        {32, "f8", regclass_unused},
        {32, "f9", regclass_unused},
        {32, "f10", regclass_unused},
        {32, "f11", regclass_unused},
        {32, "f12", regclass_unused},
        {32, "f13", regclass_unused},
        {32, "f14", regclass_unused},
        {32, "f15", regclass_unused},
        {32, "f16", regclass_unused},
        {32, "f17", regclass_unused},
        {32, "f18", regclass_unused},
        {32, "f19", regclass_unused},
        {32, "f20", regclass_unused},
        {32, "f21", regclass_unused},
        {32, "f22", regclass_unused},
        {32, "f23", regclass_unused},
        {32, "f24", regclass_unused},
        {32, "f25", regclass_unused},
        {32, "f26", regclass_unused},
        {32, "f27", regclass_unused},
        {32, "f28", regclass_unused},
        {32, "f29", regclass_unused},
        {32, "f30", regclass_unused},
        {32, "f31", regclass_unused},
        {32, "fsr", regclass_unused},
        {32, "fir", regclass_unused},
        {32, "ffp", regclass_unused},
        {32, "index", regclass_i},        /* inx */
        {32, "random", regclass_i},       /* rand */
        {32, "entrylo", regclass_unused}, /* elo */
        {32, "context", regclass_i},      /* ctxt */
        {32, "entryhi", regclass_i},      /* ehi */
        {32, "epc", regclass_i},
};

const gdb_arch_t gdb_arch_mips32be = {
        .name = "mips32be",
        .arch_name = "mips:isa32r2",
        .help = {
                .target_flag = "mips-elf-linux",
                .prompt_cmd = "set architecture mips:isa32r2",
        },
        .is_be = true,
        .regs = regs,
        .nregs = ALEN(regs)
};
