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
        {32, "eax", regclass_i},
        {32, "ecx", regclass_i},
        {32, "edx", regclass_i},
        {32, "ebx", regclass_i},
        {32, "esp", regclass_i},
        {32, "ebp", regclass_i},
        {32, "esi", regclass_i},
        {32, "edi", regclass_i},
        {32, "eip", regclass_i},
        {32, "eflags", regclass_i},
        {32, "cs", regclass_i},
        {32, "ss", regclass_i},
        {32, "ds", regclass_i},
        {32, "es", regclass_i},
        {32, "fs", regclass_i},
        {32, "gs", regclass_i},
};

const gdb_arch_t gdb_arch_x86 = {
        .name = "x86",
        .arch_name = "i386",
        .help = {
                .target_flag = "x86_64-pc-linux-gnu",
                .prompt_cmd = "set architecture i386"
        },
        .is_be = false,
        .regs = regs,
        .nregs = ALEN(regs)
};
