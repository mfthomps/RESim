/* This Software is part of Wind River Simics. The rights to copy, distribute,
   modify, or otherwise make use of this Software may be licensed only
   pursuant to the terms of an applicable Wind River license agreement.
 
   Copyright 2010-2017 Intel Corporation */

#include "gdb-remote.h"

static const regspec_t regs[] = {
        {64, "rax", regclass_i},
        {64, "rbx", regclass_i},
        {64, "rcx", regclass_i},
        {64, "rdx", regclass_i},
        {64, "rsi", regclass_i},
        {64, "rdi", regclass_i},
        {64, "rbp", regclass_i},
        {64, "rsp", regclass_i},
        {64, "r8", regclass_i},
        {64, "r9", regclass_i},
        {64, "r10", regclass_i},
        {64, "r11", regclass_i},
        {64, "r12", regclass_i},
        {64, "r13", regclass_i},
        {64, "r14", regclass_i},
        {64, "r15", regclass_i},
        {64, "rip", regclass_i},
        {32, "eflags", regclass_i},
        {32, "cs", regclass_i},
        {32, "ss", regclass_i},
        {32, "ds", regclass_i},
        {32, "es", regclass_i},
        {32, "fs", regclass_i},
        {32, "gs", regclass_i},
};

const gdb_arch_t gdb_arch_x86_64 = {
        .name = "x86-64",
        .arch_name = "i386:x86-64",
        .help = {
                .target_flag = "x86_64-pc-linux-gnu",
                .prompt_cmd = "set architecture i386:x86-64"
        },
        .is_be = false,
        .bit_extend = false,
        .regs = regs,
        .nregs = ALEN(regs)
};
