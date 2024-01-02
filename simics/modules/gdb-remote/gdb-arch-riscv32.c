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

static const regspec_t regs32[] = {
        {32, "zero",       regclass_i},
        {32, "ra",         regclass_i},
        {32, "sp",         regclass_i},
        {32, "gp",         regclass_i},
        {32, "tp",         regclass_i},
        {32, "t0",         regclass_i},
        {32, "t1",         regclass_i},
        {32, "t2",         regclass_i},
        {32, "s0",         regclass_i},
        {32, "s1",         regclass_i},
        {32, "a0",         regclass_i},
        {32, "a1",         regclass_i},
        {32, "a2",         regclass_i},
        {32, "a3",         regclass_i},
        {32, "a4",         regclass_i},
        {32, "a5",         regclass_i},
        {32, "a6",         regclass_i},
        {32, "a7",         regclass_i},
        {32, "s2",         regclass_i},
        {32, "s3",         regclass_i},
        {32, "s4",         regclass_i},
        {32, "s5",         regclass_i},
        {32, "s6",         regclass_i},
        {32, "s7",         regclass_i},
        {32, "s8",         regclass_i},
        {32, "s9",         regclass_i},
        {32, "s10",        regclass_i},
        {32, "s11",        regclass_i},
        {32, "t3",         regclass_i},
        {32, "t4",         regclass_i},
        {32, "t5",         regclass_i},
        {32, "t6",         regclass_i},
        {32, "pc",         regclass_i},
};

const gdb_arch_t gdb_arch_riscv32 = {
        .name = "risc-v32",
        .arch_name = "riscv:rv32",
        .help = {
                .target_flag = NULL,
                .prompt_cmd = "set architecture riscv:rv32",
        },
        .is_be = false,
        .regs = regs32,
        .nregs = ALEN(regs32)
};
