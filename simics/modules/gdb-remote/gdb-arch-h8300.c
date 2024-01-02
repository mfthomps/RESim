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
