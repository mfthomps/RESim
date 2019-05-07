/* This Software is part of Wind River Simics. The rights to copy, distribute,
   modify, or otherwise make use of this Software may be licensed only
   pursuant to the terms of an applicable Wind River license agreement.
 
   Copyright 2010-2017 Intel Corporation */

#include "gdb-remote.h"
#include <simics/model-iface/int-register.h>
#include <simics/arch/sparc-v8.h>

static const regspec_t regs[] = {
        {32, "g0",         regclass_i},
        {32, "g1",         regclass_i},
        {32, "g2",         regclass_i},
        {32, "g3",         regclass_i},
        {32, "g4",         regclass_i},
        {32, "g5",         regclass_i},
        {32, "g6",         regclass_i},
        {32, "g7",         regclass_i},
        {32, "o0",         regclass_i},
        {32, "o1",         regclass_i},
        {32, "o2",         regclass_i},
        {32, "o3",         regclass_i},
        {32, "o4",         regclass_i},
        {32, "o5",         regclass_i},
        {32, "o6",         regclass_i},
        {32, "o7",         regclass_i},
        {32, "l0",         regclass_i},
        {32, "l1",         regclass_i},
        {32, "l2",         regclass_i},
        {32, "l3",         regclass_i},
        {32, "l4",         regclass_i},
        {32, "l5",         regclass_i},
        {32, "l6",         regclass_i},
        {32, "l7",         regclass_i},
        {32, "i0",         regclass_i},
        {32, "i1",         regclass_i},
        {32, "i2",         regclass_i},
        {32, "i3",         regclass_i},
        {32, "i4",         regclass_i},
        {32, "i5",         regclass_i},
        {32, "i6",         regclass_i},
        {32, "i7",         regclass_i},
        {32, "f0",         regclass_unused},
        {32, "f1",         regclass_unused},
        {32, "f2",         regclass_unused},
        {32, "f3",         regclass_unused},
        {32, "f4",         regclass_unused},
        {32, "f5",         regclass_unused},
        {32, "f6",         regclass_unused},
        {32, "f7",         regclass_unused},
        {32, "f8",         regclass_unused},
        {32, "f9",         regclass_unused},
        {32, "f10",        regclass_unused},
        {32, "f11",        regclass_unused},
        {32, "f12",        regclass_unused},
        {32, "f13",        regclass_unused},
        {32, "f14",        regclass_unused},
        {32, "f15",        regclass_unused},
        {32, "f16",        regclass_unused},
        {32, "f17",        regclass_unused},
        {32, "f18",        regclass_unused},
        {32, "f19",        regclass_unused},
        {32, "f20",        regclass_unused},
        {32, "f21",        regclass_unused},
        {32, "f22",        regclass_unused},
        {32, "f23",        regclass_unused},
        {32, "f24",        regclass_unused},
        {32, "f25",        regclass_unused},
        {32, "f26",        regclass_unused},
        {32, "f27",        regclass_unused},
        {32, "f28",        regclass_unused},
        {32, "f29",        regclass_unused},
        {32, "f30",        regclass_unused},
        {32, "f31",        regclass_unused},
        {32, "y",          regclass_i},
        {32, "psr",        regclass_i},
        {32, "wim",        regclass_i},
        {32, "tbr",        regclass_i},
        {32, "pc",         regclass_i},
        {32, "npc",        regclass_i},
        {32, "fsr",        regclass_i},
        {32, "csr",        regclass_i},
};

struct v8_data {
        int nwindows;
};

#define GDB_NWINDOWS(gdb)    (((struct v8_data *)(gdb)->arch_data)->nwindows)

static bool
v8_init(gdb_remote_t *gdb, conf_object_t *cpu)
{
        struct v8_data *arch_data = MM_ZALLOC(1, struct v8_data);

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

/* v8_read_register_window_shadow reads memory that has allocated stack space
   but hasn't been pushed out in memory due to window overflows */
static int
v8_read_register_window_shadow(gdb_remote_t *gdb, conf_object_t *cpu,
                               logical_address_t la,
                               logical_address_t len,
                               char *buf)
{
        const int_register_interface_t *const int_reg_iface =
                SIM_c_get_interface(cpu, INT_REGISTER_INTERFACE);
        ASSERT(int_reg_iface != NULL);

        uint32 wim = int_reg_iface->read(
                cpu, int_reg_iface->get_number(cpu, "wim"));
        uint32 psr = int_reg_iface->read(
                cpu, int_reg_iface->get_number(cpu, "psr"));
        uint32 nwin = SIM_attr_integer(SIM_get_attribute(cpu, "num_windows"));
        uint32 cwp = psr & (nwin - 1);
        
        if ((la | len) & 3) {
                /* let's not worry about unaligned reads */
                return 0;
        }

        const sparc_v8_interface_t *iface = SIM_c_get_interface(
                cpu, SPARC_V8_INTERFACE);
        if (iface  == NULL) {
                SIM_LOG_ERROR(&gdb->obj, 0,
                              "cannot get the " SPARC_V8_INTERFACE 
                              " interface from %s", SIM_object_name(cpu));
                return 0;
        }

        int o6_index = int_reg_iface->get_number(cpu, "o6");
        int l0_index = int_reg_iface->get_number(cpu, "l0");
        int i0_index = int_reg_iface->get_number(cpu, "i0");

        // Loops through all windows prior to the current one
        // i prevents us from looping forever should no windows be invalidated
        int i = 0; 
        while ((!(wim & (1 << cwp))) && (i < nwin)) {
                logical_address_t sp = iface->read_window_register(
                        cpu, cwp, o6_index);

                if (la >= sp && (la + len - 1) <= sp + 63) {
                        unsigned reg = (la - sp) / 4;

                        while (len) {
                                int idx = (reg < 8
                                           ? l0_index + reg
                                           : i0_index + reg - 8);
                                uint32 r = iface->read_window_register(
                                        cpu, cwp, idx);
                                gdb_print_hex32_be(buf, r);
                                buf += 8;
                                ++reg;
                                len -= 4;
                        }

                        return 1;
                }
                
                // assumes 2**n windows
                cwp = (cwp + 1) & (nwin - 1);
                i ++;
        }
        return 0;
}

const gdb_arch_t gdb_arch_sparc_v8 = {
        .name = "sparc-v8",
        .arch_name = "sparc:v8plus",
        .help = {
                .target_flag = "sparc-unknown-linux-gnu",
                .prompt_cmd = "set architecture sparc:v8plus"
        },
        .is_be = true,
        .read_register_window_shadow = v8_read_register_window_shadow,
        .init = v8_init,
        .regs = regs,
        .nregs = ALEN(regs)
};
