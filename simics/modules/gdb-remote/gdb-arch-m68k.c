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
