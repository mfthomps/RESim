/*
  © 2016 Intel Corporation

  This software and the related documents are Intel copyrighted materials, and
  your use of them is governed by the express license under which they were
  provided to you ("License"). Unless the License provides otherwise, you may
  not use, modify, copy, publish, distribute, disclose or transmit this software
  or the related documents without Intel's prior written permission.

  This software and the related documents are provided as is, with no express or
  implied warranties, other than those that are expressly stated in the License.
*/

#include "gdb-remote.h"

static const regspec_t regs[] = {
        {32, "zero",      regclass_i},
        {32, "at",        regclass_i},
        {32, "r2",        regclass_i},
        {32, "r3",        regclass_i},
        {32, "r4",        regclass_i},
        {32, "r5",        regclass_i},
        {32, "r6",        regclass_i},
        {32, "r7",        regclass_i},
        {32, "r8",        regclass_i},
        {32, "r9",        regclass_i},
        {32, "r10",       regclass_i},
        {32, "r11",       regclass_i},
        {32, "r12",       regclass_i},
        {32, "r13",       regclass_i},
        {32, "r14",       regclass_i},
        {32, "r15",       regclass_i},
        {32, "r16",       regclass_i},
        {32, "r17",       regclass_i},
        {32, "r18",       regclass_i},
        {32, "r19",       regclass_i},
        {32, "r20",       regclass_i},
        {32, "r21",       regclass_i},
        {32, "r22",       regclass_i},
        {32, "r23",       regclass_i},
        {32, "et",        regclass_i},
        {32, "bt",        regclass_i},
        {32, "gp",        regclass_i},
        {32, "sp",        regclass_i},
        {32, "fp",        regclass_i},
        {32, "ea",        regclass_i},
        {32, "ba",        regclass_i},
        {32, "ra",        regclass_i},
        {32, "pc",        regclass_i},
        {32, "status",    regclass_i},
        {32, "estatus",   regclass_i},
        {32, "bstatus",   regclass_i},
        {32, "ienable",   regclass_i},
        {32, "ipending",  regclass_i},
        {32, "cpuid",     regclass_i},
        {32, "ctl6",      regclass_i},
        {32, "exception", regclass_i},
        {32, "pteaddr",   regclass_i},
        {32, "tlbacc",    regclass_i},
        {32, "tlbmisc",   regclass_i},
        {32, "eccinj",    regclass_i},
        {32, "badaddr",   regclass_i},
        {32, "config",    regclass_i},
        {32, "mpubase",   regclass_i},
        {32, "mpuacc",    regclass_i},
};

const gdb_arch_t gdb_arch_nios2 = {
        .name = "nios2",
        .arch_name = "nios2",
        .help = {
                .target_flag = "nios2-elf",
                .prompt_cmd = NULL,
        },
        .is_be = false,
        .regs = regs,
        .nregs = ALEN(regs)
};

