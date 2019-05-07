/* This Software is part of Wind River Simics. The rights to copy, distribute,
   modify, or otherwise make use of this Software may be licensed only
   pursuant to the terms of an applicable Wind River license agreement.
 
   Copyright 2010-2017 Intel Corporation */

#include "gdb-remote.h"
#include <simics/model-iface/int-register.h>
#include <simics/arch/sparc.h>

static const regspec_t regs[] = {
        {64, "g0",         regclass_i},
        {64, "g1",         regclass_i},
        {64, "g2",         regclass_i},
        {64, "g3",         regclass_i},
        {64, "g4",         regclass_i},
        {64, "g5",         regclass_i},
        {64, "g6",         regclass_i},
        {64, "g7",         regclass_i},
        {64, "o0",         regclass_i},
        {64, "o1",         regclass_i},
        {64, "o2",         regclass_i},
        {64, "o3",         regclass_i},
        {64, "o4",         regclass_i},
        {64, "o5",         regclass_i},
        {64, "o6",         regclass_i},
        {64, "o7",         regclass_i},
        {64, "l0",         regclass_i},
        {64, "l1",         regclass_i},
        {64, "l2",         regclass_i},
        {64, "l3",         regclass_i},
        {64, "l4",         regclass_i},
        {64, "l5",         regclass_i},
        {64, "l6",         regclass_i},
        {64, "l7",         regclass_i},
        {64, "i0",         regclass_i},
        {64, "i1",         regclass_i},
        {64, "i2",         regclass_i},
        {64, "i3",         regclass_i},
        {64, "i4",         regclass_i},
        {64, "i5",         regclass_i},
        {64, "i6",         regclass_i},
        {64, "i7",         regclass_i},
        {32, "f0",         regclass_v9_f},
        {32, "f1",         regclass_v9_f},
        {32, "f2",         regclass_v9_f},
        {32, "f3",         regclass_v9_f},
        {32, "f4",         regclass_v9_f},
        {32, "f5",         regclass_v9_f},
        {32, "f6",         regclass_v9_f},
        {32, "f7",         regclass_v9_f},
        {32, "f8",         regclass_v9_f},
        {32, "f9",         regclass_v9_f},
        {32, "f10",        regclass_v9_f},
        {32, "f11",        regclass_v9_f},
        {32, "f12",        regclass_v9_f},
        {32, "f13",        regclass_v9_f},
        {32, "f14",        regclass_v9_f},
        {32, "f15",        regclass_v9_f},
        {32, "f16",        regclass_v9_f},
        {32, "f17",        regclass_v9_f},
        {32, "f18",        regclass_v9_f},
        {32, "f19",        regclass_v9_f},
        {32, "f20",        regclass_v9_f},
        {32, "f21",        regclass_v9_f},
        {32, "f22",        regclass_v9_f},
        {32, "f23",        regclass_v9_f},
        {32, "f24",        regclass_v9_f},
        {32, "f25",        regclass_v9_f},
        {32, "f26",        regclass_v9_f},
        {32, "f27",        regclass_v9_f},
        {32, "f28",        regclass_v9_f},
        {32, "f29",        regclass_v9_f},
        {32, "f30",        regclass_v9_f},
        {32, "f31",        regclass_v9_f},
        {64, "f32",        regclass_unused},
        {64, "f34",        regclass_unused},
        {64, "f36",        regclass_unused},
        {64, "f38",        regclass_unused},
        {64, "f40",        regclass_unused},
        {64, "f42",        regclass_unused},
        {64, "f44",        regclass_unused},
        {64, "f46",        regclass_unused},
        {64, "f48",        regclass_unused},
        {64, "f50",        regclass_unused},
        {64, "f52",        regclass_unused},
        {64, "f54",        regclass_unused},
        {64, "f56",        regclass_unused},
        {64, "f58",        regclass_unused},
        {64, "f60",        regclass_unused},
        {64, "f62",        regclass_unused},
        {64, "pc",         regclass_i},
        {64, "npc",        regclass_i},
        {64, "ccr",        regclass_i},
        {64, "fsr",        regclass_i},
        {64, "fprs",       regclass_i},
        {64, "y",          regclass_i},
#if 0 // not needed by remote-gdb
        {64, "asi",        regclass_i},
        {64, "ver",        regclass_i},
        {64, "tick",       regclass_i},
        {64, "pil",        regclass_i},
        {64, "pstate",     regclass_i},
        {64, "tstate1",    regclass_i},
        {64, "tba",        regclass_i},
        {64, "tl",         regclass_i},
        {64, "tt1",        regclass_i},
        {64, "tpc1",       regclass_i},
        {64, "tnpc1",      regclass_i},
        {64, "wstate",     regclass_i},
        {64, "cwp",        regclass_i},
        {64, "cansave",    regclass_i},
        {64, "canrestore", regclass_i},
        {64, "cleanwin",   regclass_i},
        {64, "otherwin",   regclass_i},
        {64, "pcr",        regclass_unused},
        {64, "pic",        regclass_unused},
        {64, "dcr",        regclass_unused},
        {64, "gsp",        regclass_unused},
        {64, "asr20",      regclass_unused},
        {64, "asr21",      regclass_unused},
        {64, "softint",    regclass_i},
        {64, "tick_cmpr",  regclass_i},
        {64, "asr24",      regclass_unused},
        {64, "asr25",      regclass_unused},
        {64, "asr26",      regclass_unused},
        {64, "asr27",      regclass_unused},
        {64, "asr28",      regclass_unused},
        {64, "asr29",      regclass_unused},
        {64, "asr30",      regclass_unused},
        {64, "asr31",      regclass_unused},
        {64, "icc",        regclass_unused},
        {64, "xcc",        regclass_unused},
        {64, "fcc0",       regclass_unused},
        {64, "fcc1",       regclass_unused},
        {64, "fcc2",       regclass_unused},
        {64, "fcc3",       regclass_unused},
#endif
};

struct v9_data {
        int nwindows;
};

#define GDB_NWINDOWS(gdb)    (((struct v9_data *)(gdb)->arch_data)->nwindows)

static bool
v9_init(gdb_remote_t *gdb, conf_object_t *cpu)
{
        struct v9_data *arch_data = MM_ZALLOC(1, struct v9_data);

        attr_value_t attr = SIM_get_attribute(cpu, "num_windows");
        if (!SIM_attr_is_integer(attr)) {
                SIM_LOG_ERROR(&gdb->obj, 0,
                              "failed reading number of windows from %s",
                              SIM_object_name(cpu));
                return false;
        }
        arch_data->nwindows = SIM_attr_integer(attr);

        gdb->arch_data = arch_data;

        return true;
}

static int
v9_read_register_window_shadow(gdb_remote_t *gdb, conf_object_t *cpu,
                               logical_address_t la,
                               logical_address_t len,
                               char *buf)
{
        const int_register_interface_t *const int_reg_iface = 
                SIM_c_get_interface(cpu, INT_REGISTER_INTERFACE);

        int canrestore = int_reg_iface->read(
                cpu, int_reg_iface->get_number(cpu, "canrestore"));
        int cwp = int_reg_iface->read(
                cpu, int_reg_iface->get_number(cpu, "cwp"));

        if ((la | len) & 7) {
                /* let's not worry about unaligned reads */
                return 0;
        }
        const sparc_v9_interface_t *iface = SIM_c_get_interface(
                cpu, SPARC_V9_INTERFACE);
        if (iface == NULL) {
                SIM_LOG_ERROR(&gdb->obj, 0,
                              "cannot get the " SPARC_V9_INTERFACE 
                              " interface from %s", SIM_object_name(cpu));
                return 0;
        }

        int o6_index = int_reg_iface->get_number(cpu, "o6");
        int l0_index = int_reg_iface->get_number(cpu, "l0");
        int i0_index = int_reg_iface->get_number(cpu, "i0");
        while (canrestore) {
                logical_address_t sp = iface->read_window_register(
                        cpu, cwp, o6_index);

                if (~sp & 1) {
                        /* this is a 32-bit window */
                        return 0;
                }

                sp += 2047;

                if (la >= sp && (la + len - 1) <= sp + 127) {
                        unsigned reg = (la - sp) / 8;

                        while (len) {
                                int idx = (reg < 8 ? l0_index + reg
                                                   : i0_index + reg - 8);
                                uint64 r = iface->read_window_register(
                                        cpu, cwp, idx);
                                gdb_print_hex64_be(buf, r);
                                buf += 16;
                                ++reg;
                                len -= 8;
                        }

                        return 1;
                }

                if (cwp == 0)
                        cwp = GDB_NWINDOWS(gdb);
                --cwp;
                --canrestore;
        }

        return 0;
}

const gdb_arch_t gdb_arch_sparc_v9 = {
        .name = "sparc-v9",
        .arch_name = "sparc:v9",
        .help = {
                .target_flag = "sparc64-sun-solaris2.8",
                .prompt_cmd = "set architecture sparc:v9"
        },
        .is_be = true,
        .read_register_window_shadow = v9_read_register_window_shadow,
        .init = v9_init,
        .regs = regs,
        .nregs = ALEN(regs)
};
