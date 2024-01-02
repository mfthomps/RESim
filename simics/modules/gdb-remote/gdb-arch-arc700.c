/*
  © 2012 Intel Corporation

  This software and the related documents are Intel copyrighted materials, and
  your use of them is governed by the express license under which they were
  provided to you ("License"). Unless the License provides otherwise, you may
  not use, modify, copy, publish, distribute, disclose or transmit this software
  or the related documents without Intel's prior written permission.

  This software and the related documents are provided as is, with no express or
  implied warranties, other than those that are expressly stated in the License.
*/

#include "gdb-remote.h"

/* When using arc-elf32-gdb, one must provide it with a file that describes the
auxiliary registers of the target (e.g. ARCangel 4, simulator) upon which the
application is being debugged.

By default, GDB will look for a file named arc-registers.xml; it will look first
in the current working directory, and then in the user's home directory. Default
specifications for the ARCtangent-A5, ARC 600, ARC 700 variants of the ARC
processor architecture can be found in the <source_directory>/gdb/features/
directory of the ARC_GCC package.
*/

static const regspec_t regs[] = {
        {32, "r0",               regclass_i},
        {32, "r1",               regclass_i},
        {32, "r2",               regclass_i},
        {32, "r3",               regclass_i},
        {32, "r4",               regclass_i},
        {32, "r5",               regclass_i},
        {32, "r6",               regclass_i},
        {32, "r7",               regclass_i},
        {32, "r8",               regclass_i},
        {32, "r9",               regclass_i},
        {32, "r10",              regclass_i},
        {32, "r11",              regclass_i},
        {32, "r12",              regclass_i},
        {32, "r13",              regclass_i},
        {32, "r14",              regclass_i},
        {32, "r15",              regclass_i},
        {32, "r16",              regclass_i},
        {32, "r17",              regclass_i},
        {32, "r18",              regclass_i},
        {32, "r19",              regclass_i},
        {32, "r20",              regclass_i},
        {32, "r21",              regclass_i},
        {32, "r22",              regclass_i},
        {32, "r23",              regclass_i},
        {32, "r24",              regclass_i},
        {32, "r25",              regclass_i},
        {32, "r26",              regclass_i},
        {32, "fp",               regclass_i},
        {32, "sp",               regclass_i},
        {32, "ilink1",           regclass_i},
        {32, "ilink2",           regclass_i},
        {32, "blink",            regclass_i},
        {32, "lp_count",         regclass_i},
        {32, "pcl",              regclass_i},

        {32, "status",           regclass_i_opt},
        {32, "semaphore",        regclass_i_opt},
        {32, "lp_start",         regclass_i},
        {32, "lp_end",           regclass_i},
        {32, "identity",         regclass_i},
        {32, "debug",            regclass_i},
        {32, "pc",               regclass_i},
        {32, "sr32",             regclass_i},
        {32, "sr32_l1",          regclass_i},
        {32, "sr32_l2",          regclass_i},
        {32, "count0",           regclass_i},
        {32, "control0",         regclass_i},
        {32, "limit0",           regclass_i},
        {32, "int_vector_base",  regclass_i},
        {32, "aux_macmode",      regclass_i},
        {32, "aux_irq_lv12",     regclass_i},
        {32, "count1",           regclass_i},
        {32, "control1",         regclass_i},
        {32, "limit1",           regclass_i},
        {32, "aux_irq_lev",      regclass_i},
        {32, "aux_irq_hint",     regclass_i},

        /* TODO unclear if exist in the Simics core */
        {32, "eret",                 regclass_i_opt},
        {32, "erbta",                regclass_i_opt},
        {32, "erstatus",             regclass_i_opt},
        {32, "ecr",                  regclass_i_opt},
        {32, "efa",                  regclass_i_opt},
        {32, "icause1",              regclass_i_opt},
        {32, "icause2",              regclass_i_opt},
        {32, "aux_ienable",          regclass_i_opt},
        {32, "aux_itrigger",         regclass_i_opt},
        {32, "xpu",                  regclass_i_opt},
        {32, "bta",                  regclass_i_opt},
        {32, "bta_l1",               regclass_i_opt},
        {32, "bta_l2",               regclass_i_opt},
        {32, "aux_irq_pulse_cancel", regclass_i_opt},
        {32, "aux_irq_pending",      regclass_i_opt},
        /* end TODO */

        {32, "ic_ivic",          regclass_i_opt},
        {32, "ic_ctrl",          regclass_i_opt},
        {32, "dc_ivdc",          regclass_i_opt},
        {32, "dc_ctrl",          regclass_i_opt},
        {32, "amv0",             regclass_i_opt},
        {32, "amm0",             regclass_i_opt},
        {32, "ac0",              regclass_i_opt},
        {32, "bcr_ver",          regclass_i},
        {32, "dccm_base_build",  regclass_i_opt},
        {32, "crc_base_build",   regclass_i_opt},
        {32, "dvbf_build",       regclass_i_opt},
        {32, "ea_build",         regclass_i},
        {32, "unused_66",        regclass_i_opt},
        {32, "memsubsys_build",  regclass_i_opt},
        {32, "vecbase_ac_build", regclass_i},
        {32, "p_base_address",   regclass_i_opt},
        {32, "unused_6a",        regclass_i_opt},
        {32, "unused_6b",        regclass_i_opt},
        {32, "unused_6c",        regclass_i_opt},
        {32, "unused_6d",        regclass_i_opt},
        {32, "rf_build",         regclass_i},
        {32, "mmu_build",        regclass_i_opt},
        {32, "arcangel_build",   regclass_i_opt},
        {32, "unused_71",        regclass_i_opt},
        {32, "dcache_build",     regclass_i_opt},
        {32, "madi_build",       regclass_i_opt},
        {32, "dccm_build",       regclass_i_opt},
        {32, "timer_build",      regclass_i},
        {32, "ap_build",         regclass_i_opt},
        {32, "icache_build",     regclass_i_opt},
        {32, "iccm_build",       regclass_i_opt},
        {32, "dspram_build",     regclass_i_opt},
        {32, "mac_build",        regclass_i_opt},
        {32, "multiply_build",   regclass_i},
        {32, "swap_build",       regclass_i},
        {32, "norm_build",       regclass_i},
        {32, "minmax_build",     regclass_i},
        {32, "barrel_build",     regclass_i}
};

const gdb_arch_t gdb_arch_arc700 = {
        .name = "arc700",
        .arch_name = "arc700",
        .help = {
                .target_flag = "arc-elf32",
                .prompt_cmd = "set architecture ARC700"
        },
        .is_be = false,
        .regs = regs,
        .nregs = ALEN(regs)
};
