/*
  © 2010 Intel Corporation

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
        {96, "f0",   regclass_unused},
        {96, "f1",   regclass_unused},
        {96, "f2",   regclass_unused},
        {96, "f3",   regclass_unused},
        {96, "f4",   regclass_unused},
        {96, "f5",   regclass_unused},
        {96, "f6",   regclass_unused},
        {96, "f7",   regclass_unused},
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
