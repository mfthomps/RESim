/* This Software is part of Wind River Simics. The rights to copy, distribute,
   modify, or otherwise make use of this Software may be licensed only
   pursuant to the terms of an applicable license agreement.

   Copyright 2016-2019 Intel Corporation */

#include "gdb-remote.h"

static const regspec_t regs[] = {
        {64, "x0",         regclass_i},
        {64, "x1",         regclass_i},
        {64, "x2",         regclass_i},
        {64, "x3",         regclass_i},
        {64, "x4",         regclass_i},
        {64, "x5",         regclass_i},
        {64, "x6",         regclass_i},
        {64, "x7",         regclass_i},
        {64, "x8",         regclass_i},
        {64, "x9",         regclass_i},
        {64, "x10",        regclass_i},
        {64, "x11",        regclass_i},
        {64, "x12",        regclass_i},
        {64, "x13",        regclass_i},
        {64, "x14",        regclass_i},
        {64, "x15",        regclass_i},
        {64, "x16",        regclass_i},
        {64, "x17",        regclass_i},
        {64, "x18",        regclass_i},
        {64, "x19",        regclass_i},
        {64, "x20",        regclass_i},
        {64, "x21",        regclass_i},
        {64, "x22",        regclass_i},
        {64, "x23",        regclass_i},
        {64, "x24",        regclass_i},
        {64, "x25",        regclass_i},
        {64, "x26",        regclass_i},
        {64, "x27",        regclass_i},
        {64, "x28",        regclass_i},
        {64, "x29",        regclass_i},
        {64, "x30",        regclass_i},
        {64, "aarch64_sp", regclass_i},
        {64, "aarch64_pc", regclass_i},
        {32, "cpsr",       regclass_i},
};

const gdb_arch_t gdb_arch_aarch64 = {
        .name = "arm64",
        .arch_name = "aarch64",
        .help = {
                .target_flag = "aarch64-elf",
                .prompt_cmd = NULL,
        },
        .is_be = false,
        .regs = regs,
        .nregs = ALEN(regs)
};
