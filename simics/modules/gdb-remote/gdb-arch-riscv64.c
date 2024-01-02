/*
  © 2022 Intel Corporation

  This software and the related documents are Intel copyrighted materials, and
  your use of them is governed by the express license under which they were
  provided to you ("License"). Unless the License provides otherwise, you may
  not use, modify, copy, publish, distribute, disclose or transmit this software
  or the related documents without Intel's prior written permission.

  This software and the related documents are provided as is, with no express or
  implied warranties, other than those that are expressly stated in the License.
*/

#include "gdb-remote.h"

static const regspec_t regs64[] = {
        {64, "zero",       regclass_i},
        {64, "ra",         regclass_i},
        {64, "sp",         regclass_i},
        {64, "gp",         regclass_i},
        {64, "tp",         regclass_i},
        {64, "t0",         regclass_i},
        {64, "t1",         regclass_i},
        {64, "t2",         regclass_i},
        {64, "s0",         regclass_i},
        {64, "s1",         regclass_i},
        {64, "a0",         regclass_i},
        {64, "a1",         regclass_i},
        {64, "a2",         regclass_i},
        {64, "a3",         regclass_i},
        {64, "a4",         regclass_i},
        {64, "a5",         regclass_i},
        {64, "a6",         regclass_i},
        {64, "a7",         regclass_i},
        {64, "s2",         regclass_i},
        {64, "s3",         regclass_i},
        {64, "s4",         regclass_i},
        {64, "s5",         regclass_i},
        {64, "s6",         regclass_i},
        {64, "s7",         regclass_i},
        {64, "s8",         regclass_i},
        {64, "s9",         regclass_i},
        {64, "s10",        regclass_i},
        {64, "s11",        regclass_i},
        {64, "t3",         regclass_i},
        {64, "t4",         regclass_i},
        {64, "t5",         regclass_i},
        {64, "t6",         regclass_i},
        {64, "pc",         regclass_i},
};

const gdb_arch_t gdb_arch_riscv64 = {
        .name = "risc-v64",
        .arch_name = "riscv",
        .help = {
                .target_flag = "riscv64-linux-gnu",
                .prompt_cmd = "set architecture riscv",
        },
        .is_be = false,
        .regs = regs64,
        .nregs = ALEN(regs64)
};
