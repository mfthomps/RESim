/*
  gdb-remote.c - Remote GDB connectivity via TCP/IP

  © 2010 Intel Corporation

  This software and the related documents are Intel copyrighted materials, and
  your use of them is governed by the express license under which they were
  provided to you ("License"). Unless the License provides otherwise, you may
  not use, modify, copy, publish, distribute, disclose or transmit this software
  or the related documents without Intel's prior written permission.

  This software and the related documents are provided as is, with no express or
  implied warranties, other than those that are expressly stated in the License.
*/

#include <ctype.h>
#include <errno.h>

#include <simics/simulator-api.h>
#include <simics/util/os.h>
#include <simics/model-iface/int-register.h>
#include <simics/simulator-iface/context-tracker.h>
#include <simics/arch/x86.h>

#include "gdb-remote.h"
#include "gdb-recording.h"
#include "communication.h"

enum { Sig_int = 2, Sig_trap = 5 };

#define DEVICE_NAME "gdb-remote"

static event_class_t *step_event;

#define HEXVAL(c) (isdigit((unsigned char)(c))          \
                   ? (c) - '0'                          \
                   : (isupper((unsigned char)(c))       \
                      ? (c) - 'A' + 10                  \
                      : (c) - 'a' + 10))

static const char hexchar[] = "0123456789abcdef";

// Will write 2 chars at p, so p must be at least 2 bytes allocated.
static void
write_byte_as_hex(char *p, uint8 byteval)
{
        *p = hexchar[byteval >> 4];
        *(p + 1) = hexchar[byteval & 0xf];
}

static uint64
gdb_read_hex_le(const char *_p, uint8 bits)
{
        const unsigned char *p = (const unsigned char *)_p;
        uint64 res = 0;
        for (int i = 0; i < bits / 8; ++i, p += 2) {
                uint8 v = (HEXVAL(*p) << 4) | HEXVAL(*(p + 1));
                uint16 bitpos = i * 8;
                res |= (uint64)v << bitpos;
        }
        return res;
}

static uint64
gdb_read_hex_be(const char *_p, uint8 bits)
{
        const unsigned char *p = (const unsigned char *)_p;
        uint64 res = 0;
        for (int i = 0; i < bits / 8; ++i, p += 2) {
                uint8 v = (HEXVAL(*p) << 4) | HEXVAL(*(p + 1));
                uint16 bitpos = bits - (i + 1) * 8;
                res |= (uint64)v << bitpos;
        }
        return res;
}

static void
advance_buffer(const char **buf, uint8 bits)
{
        *buf += bits / 4;
}

static uint64
gdb_read_hex(const char **buf, bool is_be, uint8 bits)
{
        ASSERT(bits % 8 == 0);
        ASSERT(bits <= 64);
        uint64 v;
        if (is_be) {
                v = gdb_read_hex_be(*buf, bits);
        } else {
                v = gdb_read_hex_le(*buf, bits);
        }
        advance_buffer(buf, bits);
        return v;
}

static void
gdb_print_hex_le(char *p, uint64 value, uint8 bits)
{
        for (int i = 0; i < bits / 8; i++) {
                uint8 byteval = (value >> (i * 8)) & 0xff;
                write_byte_as_hex(p + i * 2, byteval);
        }
}

static void
gdb_print_hex_be(char *p, uint64 value, uint8 bits)
{
        for (int i = 0; i < bits / 8; i++) {
                uint8 byteval = value >> (i * 8);
                write_byte_as_hex(p + bits / 4 - 2 * (i + 1), byteval);
        }
}

void
gdb_print_hex(char *buf, uint64 val, bool is_be, uint8 bits)
{
        ASSERT(bits % 8 == 0);
        if (bits > 64) {
                ASSERT(val == 0);
        }
        if (is_be) {
                gdb_print_hex_be(buf, val, bits);
        } else {
                gdb_print_hex_le(buf, val, bits);
        }
}

static void
gdb_write_hex(strbuf_t *buf, uint64 val, bool is_be, uint8 bits)
{
        if (bits > 64) {
                ASSERT(val == 0);
        }
        char b[(bits / 4) + 1];
        memset(b, 0, sizeof(b));
        gdb_print_hex(b, val, is_be, bits);
        sb_addstr(buf, b);
}

static int64
hexstrtoll(const char *adr, const char **endp)
{
        /* this is not entirely correct; an invalid string that starts
           with "0x" will incorrectly be accepted. */

        /* strtoll does not modify **endp (only *endp) and should really have
           'const char **' as second argument instead. */
        return strtoll(adr, (char **)endp, 16);
}

/* Convert a string containing a hex number into a 64 bit unsigned integer.
   If bit_extend is true and there is a 32 bit hex number in the string then
   the returned value will be sign-extended.
   If endp is not NULL it will be set to the first position in the string that
   does not contain a hex number character.
   If the string does not intially contain a hex number then 0 will be
   returned. */
static uint64
hexstrtoull(const char *buf, const char **endp, bool bit_extend)
{
        uint64 hex_number = 0;
        const char *adr = buf;

        for (;;) {
                int next_char = (unsigned char)*adr;

                if (!isxdigit(next_char))
                        break;

                ++adr;

                hex_number <<= 4;
                hex_number |= HEXVAL(next_char);
        }

        if (bit_extend && adr - buf == 8)
                hex_number = (int32)hex_number;

        if (endp)
                *endp = adr;

        return hex_number;
}

static uint64
reg_read_zero(conf_object_t *cpu, register_description_t *rd)
{
        return 0;
}

static uint64
reg_read_int(conf_object_t *cpu, register_description_t *rd)
{
        const int_register_interface_t *const iface =
                SIM_c_get_interface(cpu, INT_REGISTER_INTERFACE);
        ASSERT(iface);
        return iface->read(cpu, rd->regnum);
}

static uint64
reg_read_int32l(conf_object_t *cpu, register_description_t *rd)
{
        return (uint32)reg_read_int(cpu, rd);
}

static uint64
reg_read_int32h(conf_object_t *cpu, register_description_t *rd)
{
        return reg_read_int(cpu, rd) >> 32;
}

static bool
reg_write_ignore(conf_object_t *cpu, register_description_t *rd, uint64 val)
{
        return false;
}

static bool
reg_write_int(conf_object_t *cpu, register_description_t *rd, uint64 val)
{
        const int_register_interface_t *const iface =
                SIM_c_get_interface(cpu, INT_REGISTER_INTERFACE);
        ASSERT(iface);
        iface->write(cpu, rd->regnum, val);
        return true;
}

static bool
reg_write_int32l(conf_object_t *cpu, register_description_t *rd, uint64 val)
{
        return reg_write_int(cpu, rd,
                             reg_read_int32h(cpu, rd) << 32 | (uint32)val);
}

static bool
reg_write_int32h(conf_object_t *cpu, register_description_t *rd, uint64 val)
{
        return reg_write_int(cpu, rd,
                             val << 32 | reg_read_int32l(cpu, rd));
}

static bool
stopped_by_watchpoint(gdb_remote_t *gdb)
{
        struct gdb_breakpoint *bp = gdb->bp;
        if (bp) {
                return (bp->type == Gdb_Bp_Read || bp->type == Gdb_Bp_Write
                        || bp->type == Gdb_Bp_Access);
        }

        return false;
}

static const processor_info_interface_t *
processor_iface(const conf_object_t *cpu)
{
        return SIM_c_get_interface(cpu, PROCESSOR_INFO_INTERFACE);
}

static const x86_interface_t *
x86_iface(const conf_object_t *cpu)
{
        return SIM_c_get_interface(cpu, X86_INTERFACE);
}

static const context_handler_interface_t *
context_handler_iface(const conf_object_t *cpu)
{
        return SIM_c_get_interface(cpu, CONTEXT_HANDLER_INTERFACE);
}

static const int64 default_thread_id = 0;
static const char * const default_thread_name = "main thread";

static attr_value_t
default_processor_list(conf_object_t *_gdb)
{
        struct gdb_remote *gdb = (struct gdb_remote *)_gdb;
        if (gdb->processor)
                return SIM_make_attr_list(1, SIM_make_attr_object(gdb->processor));
        else
                return SIM_get_all_processors();
}

static bool
is_current_thread(gdb_remote_t *gdb, int64 thread, conf_object_t *cpu)
{
        return thread == -1 || thread == default_thread_id;
}

/* NULL-terminated array of all processors known to gdb-remote. */
static conf_object_t **
gdb_all_processors(gdb_remote_t *gdb)
{
        attr_value_t cpus = default_processor_list(to_obj(gdb));
        conf_object_t **result = MM_MALLOC(SIM_attr_list_size(cpus) + 1,
                                           conf_object_t *);
        for (int i = 0; i < SIM_attr_list_size(cpus); i++)
                result[i] = SIM_attr_object(SIM_attr_list_item(cpus, i));
        result[SIM_attr_list_size(cpus)] = NULL;
        SIM_attr_free(&cpus);
        return result;
}

/* Return a processor known to gdb-remote, or NULL if no processor is known. */
static conf_object_t *
gdb_any_processor(gdb_remote_t *gdb)
{
        conf_object_t **cpus = gdb_all_processors(gdb);
        conf_object_t *cpu = cpus[0];
        MM_FREE(cpus);
        return cpu;
}

static conf_object_t *
cpu_context_obj(gdb_remote_t *gdb, conf_object_t *cpu)
{
        conf_object_t *ctx =
                context_handler_iface(cpu)->get_current_context(cpu);
        if (!ctx) {
                SIM_LOG_ERROR(to_obj(gdb), 0,
                              "Failed reading the current context of %s",
                              SIM_object_name(cpu));
        }
        return ctx;
}

static conf_object_t *
gdb_context_object(gdb_remote_t *gdb)
{
        if (gdb->context_object)
                return gdb->context_object;
        return NULL;
}

/* Return the processor where the given thread is currently active, or NULL if
   it isn't active on any processor right now. */
static conf_object_t *
find_cpu_for_active_thread(gdb_remote_t *gdb, int64 thread)
{
        if (gdb->processor) {
                return is_current_thread(gdb, thread, gdb->processor) ?
                        gdb->processor : NULL;
        }
        conf_object_t **cpus = gdb_all_processors(gdb);
        conf_object_t *result = NULL;
        for (int i = 0; cpus[i]; i++) {
                if (cpu_context_obj(gdb, cpus[i]) == gdb_context_object(gdb)
                    && is_current_thread(gdb, thread, cpus[i])) {
                        result = cpus[i];
                        break;
                }
        }
        MM_FREE(cpus);
        return result;
}

/* Call VT_get_current_processor(), hiding any Simics exception triggered by the
   call. */
static conf_object_t *
simics_current_processor(void)
{
        return VT_get_current_processor();
}

/* Find an arbitrary processor that is executing in a context we are interested
   in. If the current processor is in the set of such processors, prefer it. */
static conf_object_t *
gdb_current_processor(gdb_remote_t *gdb)
{
        if (gdb->processor)
                return gdb->processor;

        conf_object_t *result = NULL;
        conf_object_t **cpus = gdb_all_processors(gdb);
        conf_object_t *scp = simics_current_processor();

  again:
        for (int i = 0; cpus[i]; i++) {
                if (cpu_context_obj(gdb, cpus[i]) == gdb_context_object(gdb)
                    && (!scp || scp == cpus[i])) {
                        result = cpus[i];
                        goto done;
                }
        }
        if (scp) {
                /* Failed to use scp as result. Try again, this time without
                   attempting to select scp. */
                scp = NULL;
                goto again;
        }
  done:
        MM_FREE(cpus);
        return result;
}

typedef struct {
        conf_object_t *cpu;
        int64 thread;
} cpu_thread_t;

static cpu_thread_t
gdb_cpu_thread(gdb_remote_t *gdb, int64 thread)
{
        cpu_thread_t ct;
        if (thread == -1) {
                ct.cpu = gdb_current_processor(gdb);
                ct.thread = ct.cpu ? default_thread_id : -1;
        } else {
                ct.cpu = find_cpu_for_active_thread(gdb, thread);
                ct.thread = thread;
        }
        return ct;
}

/* Return the processor that's currently executing the "cont" thread, and the
   thread ID of that thread. If no processor is executing that thread, .cpu is
   NULL. Thread ID -1 is resolved to an actual thread ID unless .cpu is
   NULL. */
static cpu_thread_t
gdb_cont(gdb_remote_t *gdb)
{
        return gdb_cpu_thread(gdb, gdb->cont_thread);
}

/* Same as gdb_cont(), but for the "other" thread. */
static cpu_thread_t
gdb_other(gdb_remote_t *gdb)
{
        return gdb_cpu_thread(gdb, gdb->other_thread);
}

static void
stop_reply_packet(gdb_remote_t *gdb, strbuf_t *buf, int sig)
{
        sb_addfmt(buf, "T%2.2xthread:%llx;", sig, gdb_cont(gdb).thread);
}

static void
send_signal(gdb_remote_t *gdb, int sig, struct gdb_breakpoint *bp)
{
        strbuf_t buf = SB_INIT;
        stop_reply_packet(gdb, &buf, sig);

        if (sig == Sig_trap && stopped_by_watchpoint(gdb)) {
                const char *type_str;

                switch (bp->type) {
                case Gdb_Bp_Read:
                        type_str = "rwatch";
                        break;
                case Gdb_Bp_Write:
                        type_str = "watch";
                        break;
                case Gdb_Bp_Access:
                        type_str = "awatch";
                        break;
                default:
                        ASSERT(0);
                }

                /* The gdb-remote protocol changed slightly in GDB 7.1. The
                   client expects the awatch stop response to contain the
                   address of the location the HW breakpoint was watching and
                   not where the target stops. Older versions do not care. */
                sb_addfmt(&buf, "%s:%llx;", type_str, bp->la);
        }

        send_packet(gdb, sb_str(&buf));
        sb_free(&buf);
}

static void
do_signal(gdb_remote_t *gdb, int sig)
{
        SIM_LOG_INFO(3, to_obj(gdb), 0, "do_signal(sig = %d), is running %d",
                     sig, gdb->is_running);

        /* GDB expects that the stopping thread becomes current */
        gdb->cont_thread = gdb->other_thread = -1;

        send_signal(gdb, sig, gdb->bp);
}

static void
send_sigtrap(void *data)
{
        gdb_remote_t *gdb = (gdb_remote_t *)data;
        do_signal(gdb, Sig_trap);
}

static void
send_sigint(void *data)
{
        gdb_remote_t *gdb = (gdb_remote_t *)data;
        do_signal(gdb, Sig_int);
}

static void
send_ok(gdb_remote_t *gdb) {
        send_packet(gdb, "OK");
}

static void
send_unsupported(gdb_remote_t *gdb)
{
        send_packet(gdb, "");
}

static void
send_unsupported_with_args(gdb_remote_t *gdb, const char *suffix)
{
        send_packet(gdb, "");
}

static void
send_error(gdb_remote_t *gdb, int eno)
{
        char buf[8];
        sprintf(buf, "E%2.2x", eno);
        send_packet(gdb, buf);
}

static physical_address_t
logical_to_physical(conf_object_t *cpu, data_or_instr_t data_or_instr,
                    logical_address_t vaddr, bool *error_flag)
{
        *error_flag = false;
        const x86_interface_t *x86_if = x86_iface(cpu);
        if (x86_if) {
                physical_address_t pa =
                        x86_if->linear_to_physical(cpu, data_or_instr, vaddr);
                if (pa == (physical_address_t)-1) {
                        *error_flag = true;
                        return 0;
                } else {
                        return pa;
                }
        } else {
                const physical_block_t res =
                        processor_iface(cpu)->logical_to_physical(
                                cpu, vaddr,
                                data_or_instr == Sim_DI_Data ? Sim_Access_Read
                                : Sim_Access_Execute);
                if (!res.valid) {
                        *error_flag = true;
                        return 0;
                }
                return res.address;
        }
}


static int
lookup_address(gdb_remote_t *gdb, conf_object_t *cpu,
               logical_address_t la, physical_address_t *pa)
{
        bool error_flag;

        /* FIXME: there's no way to tell if we want to load Data or
           Instruction, right? */
        *pa = logical_to_physical(cpu, Sim_DI_Data, la, &error_flag);
        if (error_flag) {
                *pa = logical_to_physical(cpu, Sim_DI_Instruction,
                                          la, &error_flag);
                if (error_flag) {
                        SIM_LOG_INFO(3, to_obj(gdb), 0,
                                     "Failed looking up address %#llx", la);
                        return 1;
                }
        }
        return 0;
}

static void
write_memory(gdb_remote_t *gdb, const char *adr)
{
        conf_object_t *cpu = gdb_other(gdb).cpu;
        logical_address_t la, len;
        const char *endp;

        la = hexstrtoull(adr, &endp, gdb->arch->bit_extend);
        if (*endp != ',' || *(endp + 1) == 0) {
                SIM_LOG_ERROR(to_obj(gdb), 0,
                              "Badly formatted memory address/length/data: %s",
                              adr);
                send_error(gdb, EINVAL);
                return;
        }
        la += gdb->segment_linear_base;

        len = hexstrtoull(endp + 1, &endp, gdb->arch->bit_extend);
        if (*endp != ':') {
                SIM_LOG_ERROR(to_obj(gdb), 0,
                              "Badly formatted memory address/length/data: %s",
                              adr);
                send_error(gdb, EINVAL);
                return;
        }

        if (!cpu) {
                SIM_LOG_INFO(3, to_obj(gdb), 0,
                             "Cannot write memory, because process is"
                             " not active");
                send_error(gdb, EACCES);
                return;
        }

        ++endp;

        if (gdb->large_operations
            && (len == 1 || len == 2 || len == 4 || len == 8)
            && !(la & (len - 1))) {
                physical_address_t pa;
                char buf[8];
                uint64 data = 0;

                for (int i = 0; i < len; ++i) {
                        if (*endp == 0) {
                                SIM_LOG_ERROR(to_obj(gdb), 0,
                                              "Not enough data for memory "
                                              "write: %s", adr);
                                send_error(gdb, EINVAL);
                                return;
                        }
                        buf[i] = (HEXVAL(*(unsigned char *)endp) << 4) |
                                HEXVAL(*(unsigned char *)(endp+1));
                        endp += 2;
                }

                /*
                 * Since the hex string is read into data bigendian,
                 * we need to byteswap if the host isn't
                 */
                switch (len) {
                case 1: data = UNALIGNED_LOAD_BE8(buf); break;
                case 2: data = UNALIGNED_LOAD_BE16(buf); break;
                case 4: data = UNALIGNED_LOAD_BE32(buf); break;
                case 8: data = UNALIGNED_LOAD_BE64(buf); break;
                }

                if (lookup_address(gdb, cpu, la, &pa)) {
                        send_error(gdb, EACCES);
                        return;
                }

                SIM_write_phys_memory(cpu, pa, data, len);
                if (SIM_clear_exception()) {
                        SIM_LOG_ERROR(
                                to_obj(gdb), 0,
                                "Failed writing memory to la: %#llx  pa: %#llx "
                                "len: %lld", la, pa, len);
                        send_error(gdb, EACCES);
                        return;
                }

                goto done;
        }

        for (; len; --len, ++la) {
                physical_address_t pa;
                uint8 data;

                if (*endp == 0 || *(endp + 1) == 0) {
                        SIM_LOG_ERROR(
                                to_obj(gdb), 0,
                                "Not enough data for memory write: %s", adr);
                        send_error(gdb, EINVAL);
                        return;
                }

                data = (HEXVAL(*(unsigned char *)endp) << 4)
                        | HEXVAL(*((unsigned char *)endp + 1));

                if (lookup_address(gdb, cpu, la, &pa)) {
                        send_error(gdb, EACCES);
                        return;
                }

                SIM_write_phys_memory(cpu, pa, data, 1);
                if (SIM_clear_exception()) {
                        SIM_LOG_ERROR(to_obj(gdb), 0,
                                      "Failed writing memory to la: "
                                      "%#llx  pa: %#llx", la, pa);
                        send_error(gdb, EACCES);
                        return;
                }

                endp += 2;
        }

        if (*endp) {
                SIM_LOG_ERROR(to_obj(gdb), 0,
                              "Too much data in memory write: adr");
        }

 done:
        send_ok(gdb);
}

/* Read memory and send a response back to the remote gdb process. If there is
   an error, say so to gdb---EXCEPT if there is an address lookup error or when
   we don't have a CPU because the process to be stepped isn't active. In that
   case, pretend that the memory contained zeros instead of telling gdb that
   something went wrong, because otherwise even such simple stepping commands
   as "si" will not work (though why gdb should need to read memory in order to
   single-step is beyond me); and if we can't step, we can never get to a point
   where the context _is_ active! */
static void
send_memory(gdb_remote_t *gdb, const char *adr)
{
        conf_object_t *cpu = gdb_other(gdb).cpu;
        logical_address_t la, len;
        const char *endp;

        la = hexstrtoull(adr, &endp, gdb->arch->bit_extend);
        if (*endp != ',' || *(endp + 1) == 0) {
                SIM_LOG_ERROR(to_obj(gdb), 0,
                              "Badly formatted memory address/length: %s",
                              adr);
                send_error(gdb, EINVAL);
                return;
        }
        la += gdb->segment_linear_base;

        len = hexstrtoull(endp + 1, &endp, gdb->arch->bit_extend);
        if (*endp) {
                SIM_LOG_ERROR(to_obj(gdb), 0,
                              "Badly formatted memory address/length: %s",
                              adr);
                send_error(gdb, EINVAL);
                return;
        }

        char buf[len * 2 + 1];
        char *p = buf;
        if (!cpu) {
                SIM_LOG_INFO(3, to_obj(gdb), 0,
                             "Cannot read memory, because process is"
                             " not active");
                /* coverity[bad_memset] */
                memset(p, '0', len * 2);
                p += len * 2;
                goto done;
        }

        if (gdb->arch->read_register_window_shadow
            && gdb->arch->read_register_window_shadow(gdb, cpu, la, len, buf)) {
                p = buf + len * 2;
                goto do_send;
        }

        if (gdb->large_operations
            && (len == 1 || len == 2 || len == 4 || len == 8)
            && !(la & (len - 1))) {
                physical_address_t pa;
                uint64 value;

                if (lookup_address(gdb, cpu, la, &pa)) {
                        value = 0;
                } else {
                        value = SIM_read_phys_memory(cpu, pa, len);
                        if (SIM_clear_exception()) {
                                SIM_LOG_INFO(1, to_obj(gdb), 0,
                                             "Failed reading from la: %#llx"
                                             " pa: %#llx len: %lld",
                                             la, pa, len);
                                goto done;
                        }
                }

                if (gdb->arch->is_be) {
                        for (int i = len-1; i >= 0; i--) {
                                gdb_print_hex(p, value >> (i*8) & 0xff,
                                              true, 8);
                                p += 2;
                        }
                } else {
                        for (int i = 0; i < len; i++) {
                                gdb_print_hex(p, value >> (i*8) & 0xff,
                                              false, 8);
                                p += 2;
                        }
                }

                goto done;
        }

        while (len) {
                physical_address_t pa;
                uint8 value;

                if (lookup_address(gdb, cpu, la, &pa)) {
                        value = 0;
                } else {
                        value = SIM_read_phys_memory(cpu, pa, 1);
                        if (SIM_clear_exception()) {
                                SIM_LOG_INFO(1, to_obj(gdb), 0,
                                             "Failed reading from la:"
                                             " %#llx  pa: %#llx",
                                             la, pa);
                                break;
                        }
                }
                gdb_print_hex(p, value, false, 8);
                p += 2;
                --len;
                ++la;
        }

 done:
        if (p == buf) {
                /* failed to read anything */
                send_error(gdb, EACCES);
                return;
        }

 do_send:
        *p = 0;
        send_packet(gdb, buf);
}

/* Disable reception of further gdb commands until the simulation really has
   stopped. This is to avoid receiving gdb requests for actions that are
   disallowed during simulation. The caller is expected to have stopped the
   simulation immediately prior to calling this function. */
static void
stop_simulation(gdb_remote_t *gdb)
{
        SIM_LOG_INFO(3, to_obj(gdb), 0, "breaking simulation");
        if (gdb->is_running && !gdb->stop_in_progress) {
                SIM_LOG_INFO(3, to_obj(gdb), 0, "setting stop in progress");
                deactivate_gdb_notifier(gdb);
                gdb->stop_in_progress = true;
        }
}

static struct gdb_breakpoint *
breakpoint_get_by_id(gdb_remote_t *gdb, int bp_number)
{
        int i;
        for (i = 0; i < gdb->breakpoints.used; ++i) {
                struct gdb_breakpoint *bp = gdb->breakpoints.entries + i;
                if (bp->bp_data.bp_type != Simics_Gdb_Bp_Hap)
                        continue;
                if (bp->bp_data.bp_id == bp_number)
                        return bp;
        }
        return NULL;
}

static void
bp_handler_common(gdb_remote_t *gdb, logical_address_t addr,
                 struct gdb_breakpoint *bp)
{
        VT_stop_message(to_obj(gdb), "Hit breakpoint set by remote gdb");
        stop_simulation(gdb);

        gdb->bp = bp;
        if (bp)
                gdb->access_address = addr;

        if (VT_is_reversing()) {
                return;
        }

        if (gdb->step_handler_cpu)
                SIM_event_cancel_step(gdb->step_handler_cpu, step_event,
                                      to_obj(gdb), 0, NULL);

        SIM_register_work(send_sigtrap, gdb);
}

static void
ordered_breakpoint_handler(conf_object_t *obj, int64 bp_number, void *data)
{
        gdb_remote_t *gdb = gdb_of_obj(obj);
        generic_transaction_t *memop = (generic_transaction_t *)data;
        logical_address_t addr = SIM_get_mem_op_virtual_address(memop);
        struct gdb_breakpoint *bp = breakpoint_get_by_id(gdb, bp_number);

        SIM_LOG_INFO(3, to_obj(gdb), 0, "inside breakpoint handler %d",
                     (int)bp_number);

        bp_handler_common(gdb, addr, bp);
}


static void
gdb_breakpoint_handler(void *_gdb, conf_object_t *obj,
                       int64 bp_number, generic_transaction_t *memop)
{
        VT_c_in_time_order(_gdb, ordered_breakpoint_handler, bp_number,
                           memop, sizeof *memop);
}

static void
post_continue2(void *data)
{
        gdb_remote_t *gdb = (gdb_remote_t *) data;
        int err;

        gdb->bp = NULL;

        if (SIM_simics_is_running()) {
                SIM_LOG_ERROR(
                        to_obj(gdb), 0,
                        "About to call SIM_continue() but Simics is already"
                        " running");
                // TODO: if running in wrong direction?
                return;
        }

        /* Ugly hack to remove multiple simics prompts,
           should be fixed in Simics instead... */
        if (gdb->next_reverse_direction) {
                gdb->next_reverse_direction = false;
                err = VT_reverse(0);
                if (err) {
                        send_error (gdb, 6);
                } else {
                        if (stopped_by_watchpoint(gdb)) {
                                pc_step_t count =
                                       SIM_step_count(VT_get_current_processor_old());
                                if (count)
                                        VT_rewind(VT_get_current_processor_old(),
                                                  count - 1);
                        }

                        do_signal(gdb, Sig_trap);
                }
        } else {
                SIM_continue(0);
                sim_exception_t ex = SIM_clear_exception();
                if (ex != SimExc_No_Exception && ex != SimExc_Break) {
                        SIM_LOG_ERROR(
                                to_obj(gdb), 0,
                                "Unexpected exception from SIM_continue(). "
                                "Error message: %s", SIM_last_error());
                }
        }
}

static void
post_continue(gdb_remote_t *gdb)
{
        SIM_register_work(post_continue2,gdb);
}

static bool
follow_context(gdb_remote_t *gdb)
{
        if (gdb->processor)
                return false;

        /* If the user has explicitly given us a context, follow it. */
        if (gdb->context_object)
                return true;

        /* If a tracker is connected, we may be following multiple
           threads.  Then we must follow the same thread when
           stepping, in order not to confuse GDB.  And following
           threads necessarily implies following contexts as well. */
        return 0;
}

static void
gdb_step_handler(conf_object_t *gdb_obj, void *_gdb)
{
        gdb_remote_t *gdb = (gdb_remote_t *)_gdb;

        gdb->step_handler_cpu = NULL;
        SIM_LOG_INFO(3, to_obj(gdb), 0, "gdb_step_handler()");

        if (follow_context(gdb)
            && !find_cpu_for_active_thread(gdb, gdb->cont_thread)) {
                /* We need to wait for cont_thread to become scheduled on a
                   processor. */
                gdb->on_thread_change = OTC_Stop;
                return;
        }

        VT_stop_finished(NULL);
        stop_simulation(gdb);
        SIM_register_work(send_sigtrap, gdb);
}

static void
do_step(gdb_remote_t *gdb, conf_object_t *cpu)
{
        if (gdb->step_handler_cpu)
                SIM_event_cancel_step(gdb->step_handler_cpu, step_event,
                                      to_obj(gdb), 0, NULL);
        gdb->step_handler_cpu = cpu;
        SIM_event_post_step(gdb->step_handler_cpu, step_event,
                            to_obj(gdb), 1, gdb);
        post_continue(gdb);
}

static void
post_reverse2(void *data)
{
        int err;
        gdb_remote_t *gdb = data;

        gdb->bp = NULL;
        err = VT_reverse(1);

        if (err) {
                send_error (gdb, 6);
        } else {
                if (stopped_by_watchpoint(gdb)) {
                        pc_step_t count =
                                SIM_step_count(VT_get_current_processor_old());
                        if (count)
                                VT_rewind(VT_get_current_processor_old(), count - 1);
                }

                do_signal(gdb, Sig_trap);
        }
}

static void
do_reverse(gdb_remote_t *gdb)
{
        SIM_register_work(post_reverse2, gdb);
}

static int
breakpoint_lookup(gdb_remote_t *gdb, logical_address_t la,
                  logical_address_t len, gdb_breakpoint_type_t type)
{
        for (int i = 0; i < gdb->breakpoints.used; ++i) {
                struct gdb_breakpoint *bp = gdb->breakpoints.entries + i;

                if (bp->la == la && bp->len == len && bp->type == type)
                        return i;
        }

        return -1;
}

typedef struct {
        logical_address_t la;
        logical_address_t len;
        gdb_breakpoint_type_t type;
        bool valid;
} bp_args_t;

static access_t
type_to_access(gdb_breakpoint_type_t type)
{
        switch (type) {
        case Gdb_Bp_Software:
                return Sim_Access_Execute;
        case Gdb_Bp_Hardware:
                return Sim_Access_Execute;
        case Gdb_Bp_Write:
                return Sim_Access_Write;
        case Gdb_Bp_Read:
                return Sim_Access_Read;
        case Gdb_Bp_Access:
                return Sim_Access_Read | Sim_Access_Write;
        }
        ASSERT(0);
}

static bp_args_t
parse_breakpoint_args(gdb_remote_t *gdb, const char *args)
{
        bp_args_t invalid_args = {.valid = false};
        if (args[0] < '0' || args[0] > '0' + Gdb_Bp_Access || args[1] != ',')
                return invalid_args;

        gdb_breakpoint_type_t type = args[0] - '0';

        const char *endp;
        logical_address_t la = hexstrtoull(args + 2, &endp,
                                           gdb->arch->bit_extend);
        if (endp[0] != ',' || endp[1] == 0)
                return invalid_args;

        /* Add an offset which was set by the custom 'segment' command. */
        la += gdb->segment_linear_base;

        logical_address_t len = hexstrtoull(endp + 1, &endp, false);
        if (endp[0])
                return invalid_args;

        return (bp_args_t){.la = la, .len = len, .type = type, .valid = true};
}

static void
cancel_virtual_insn_bp(struct gdb_breakpoint *bp)
{
        gdb_remote_t *gdb = bp->gdb;
        ASSERT(gdb->processor);
        const virtual_instruction_breakpoint_interface_t *virt_insn_iface =
                SIM_C_GET_INTERFACE(gdb->processor,
                                    virtual_instruction_breakpoint);
        ASSERT(virt_insn_iface);
        ASSERT(bp->bp_data.valid);
        virt_insn_iface->remove(gdb->processor, bp->bp_data.virt_insn);
        bp->bp_data.valid = false;
}

static void
cancel_virtual_data_bp(struct gdb_breakpoint *bp)
{
        gdb_remote_t *gdb = bp->gdb;
        ASSERT(gdb->processor);
        const virtual_data_breakpoint_interface_t *virt_data_iface =
                SIM_C_GET_INTERFACE(gdb->processor, virtual_data_breakpoint);
        ASSERT(virt_data_iface);
        ASSERT(bp->bp_data.valid);
        if (bp->bp_data.virt_data_read) {
                SIM_LOG_INFO(4, to_obj(gdb), 0,
                             "Cancelling virtual data read breakpoint %p",
                             bp->bp_data.virt_data_read);
                virt_data_iface->remove(gdb->processor,
                                        bp->bp_data.virt_data_read);
        }
        if (bp->bp_data.virt_data_write) {
                SIM_LOG_INFO(4, to_obj(gdb), 0,
                             "Cancelling virtual data write breakpoint %p",
                             bp->bp_data.virt_data_write);
                virt_data_iface->remove(gdb->processor,
                                        bp->bp_data.virt_data_write);
        }
        bp->bp_data.valid = false;
}

static void
cancel_sim_breakpoint(struct gdb_breakpoint *bp)
{
        SIM_delete_breakpoint(bp->bp_data.bp_id);
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", bp->bp_data.hap_id);
}

static void
cancel_breakpoint(struct gdb_breakpoint *bp)
{
        switch (bp->bp_data.bp_type) {
        case Simics_Gdb_Bp_Hap:
                cancel_sim_breakpoint(bp);
                break;
        case Simics_Gdb_Virt_Insn:
                cancel_virtual_insn_bp(bp);
                break;
        case Simics_Gdb_Virt_Data:
                cancel_virtual_data_bp(bp);
                break;
        }
}

static bool
use_virtual_bp_iface(gdb_remote_t *gdb)
{
        return !gdb->context_object;
}

static void
virtual_insn_bp_cb(cbdata_call_t cb_data, conf_object_t *cpu,
                   generic_address_t addr, unsigned size)
{
        struct gdb_breakpoint *bp = SIM_cbdata_data(&cb_data);
        SIM_LOG_INFO(4, to_obj(bp->gdb), 0,
                     "Virtual insn breakpoint hit at 0x%llx on '%s', data: %p",
                     addr, SIM_object_name(cpu), bp);
        bp_handler_common(bp->gdb, addr, bp);
}

static void
virtual_data_read_bp_cb(cbdata_call_t cb_data, conf_object_t *cpu,
                        generic_address_t addr, unsigned size)
{
        struct gdb_breakpoint *bp = SIM_cbdata_data(&cb_data);
        SIM_LOG_INFO(4, to_obj(bp->gdb), 0,
                     "Virtual data read breakpoint hit at 0x%llx on '%s',"
                     " data: %p", addr, SIM_object_name(cpu), bp);
        bp_handler_common(bp->gdb, addr, bp);
}

static void
virtual_data_write_bp_cb(cbdata_call_t cb_data, conf_object_t *cpu,
                        generic_address_t addr, bytes_t value)
{
        struct gdb_breakpoint *bp = SIM_cbdata_data(&cb_data);
        SIM_LOG_INFO(4, to_obj(bp->gdb), 0,
                     "Virtual data write breakpoint hit at 0x%llx on '%s',"
                     " data: %p", addr, SIM_object_name(cpu), bp);
        bp_handler_common(bp->gdb, addr, bp);
}

static bool
is_x86(conf_object_t *cpu)
{
        return !!SIM_C_GET_INTERFACE(cpu, x86);
}

static bool
virt_bp_planter_error_checker(gdb_remote_t *gdb, bp_args_t *bp_args,
                              bool iface_exists, const char *bp_type)
{
        if (!iface_exists) {
                SIM_LOG_ERROR(to_obj(gdb), 0,
                              "cpu '%s' lacks virtual %s breakpoint interface",
                              SIM_object_name(gdb->processor), bp_type);
                return false;
        }
        if (bp_args->len == 0) {
                SIM_LOG_ERROR(to_obj(gdb), 0,
                              "Failed setting virtual %s breakpoint: zero"
                              " length", bp_type);
                return false;
        }
        if (bp_args->la + bp_args->len - 1 < bp_args->la) {
                SIM_LOG_ERROR(to_obj(gdb), 0,
                              "Failed setting virtual %s breakpoint: range"
                              " wraps", bp_type);
                return false;
        }
        return true;
}

static installed_bp_data_t
plant_virtual_insn_bp(gdb_remote_t *gdb, bp_args_t *bp_args,
                      void *bp_data)
{
        const virtual_instruction_breakpoint_interface_t *virt_insn_iface =
                SIM_C_GET_INTERFACE(gdb->processor,
                                    virtual_instruction_breakpoint);
        if (!virt_bp_planter_error_checker(gdb, bp_args, !!virt_insn_iface,
                                           "instruction")) {
                return (installed_bp_data_t){.valid = false};
        }
        uint32 linear_flag = is_x86(gdb->processor) ?
                Virtual_Breakpoint_Flag_Linear : 0;
        virtual_instr_bp_handle_t *bp_handle = virt_insn_iface->add(
                gdb->processor,
                bp_args->la, bp_args->la + bp_args->len - 1, NULL,
                SIM_make_simple_cbdata(NULL), virtual_insn_bp_cb,
                SIM_make_simple_cbdata(bp_data), linear_flag);
        if (!bp_handle) {
                SIM_LOG_ERROR(to_obj(gdb), 0,
                              "Failed adding virtual instruction breakpoint");
                return (installed_bp_data_t){.valid = false};
        }
        SIM_LOG_INFO(4, to_obj(gdb), 0,
                     "Virtual insn breakpoint installed on '%s', handle: %p, "
                     " data: %p",
                     SIM_object_name(gdb->processor), bp_handle, bp_data);
        return (installed_bp_data_t){
                .virt_insn = bp_handle,
                .bp_type = Simics_Gdb_Virt_Insn,
                .valid = true,
        };
}

static installed_bp_data_t
plant_virtual_data_bp(gdb_remote_t *gdb, bp_args_t *bp_args,
                      void *bp_data)
{
        const virtual_data_breakpoint_interface_t *virt_data_iface =
                SIM_C_GET_INTERFACE(gdb->processor,
                                    virtual_data_breakpoint);
        if (!virt_bp_planter_error_checker(gdb, bp_args, !!virt_data_iface,
                                           "data")) {
                return (installed_bp_data_t){.valid = false};
        }
        uint32 linear_flag = is_x86(gdb->processor) ?
                Virtual_Breakpoint_Flag_Linear : 0;
        virtual_data_bp_handle_t *read_bp_handle = NULL;
        virtual_data_bp_handle_t *write_bp_handle = NULL;

        bool is_write = false;
        bool is_read = false;
        switch(bp_args->type) {
        case Gdb_Bp_Write:
                is_write = true;
                break;
        case Gdb_Bp_Read:
                is_read = true;
                break;
        case Gdb_Bp_Access:
                is_read = true;
                is_write = true;
                break;
        default:
                ASSERT_FMT(0, "Bad virt data breakpoint type: %d",
                           bp_args->type);
        }
        if (is_read) {
                read_bp_handle = virt_data_iface->add_read(
                        gdb->processor, bp_args->la,
                        bp_args->la + bp_args->len - 1,
                        virtual_data_read_bp_cb,
                        SIM_make_simple_cbdata(bp_data), linear_flag);
                if (!read_bp_handle) {
                        SIM_LOG_ERROR(to_obj(gdb), 0,
                                      "Failed adding virtual data read"
                                      " breakpoint");
                        return (installed_bp_data_t){.valid = false};
                }
                SIM_LOG_INFO(4, to_obj(gdb), 0,
                             "Installed virtual data read breakpoint, handle:"
                             " %p, data: %p", read_bp_handle, bp_data);
        }
        if (is_write) {
                write_bp_handle = virt_data_iface->add_write(
                        gdb->processor, bp_args->la,
                        bp_args->la + bp_args->len - 1,
                        virtual_data_write_bp_cb,
                        SIM_make_simple_cbdata(bp_data), linear_flag);
                if (!write_bp_handle) {
                        SIM_LOG_ERROR(to_obj(gdb), 0,
                                      "Failed adding virtual data write"
                                      " breakpoint");
                        if (read_bp_handle) {
                                virt_data_iface->remove(gdb->processor,
                                                        read_bp_handle);
                        }
                        return (installed_bp_data_t){.valid = false};
                }
                SIM_LOG_INFO(4, to_obj(gdb), 0,
                             "Installed virtual data write breakpoint,"
                             " handle: %p, data: %p", write_bp_handle, bp_data);
        }
        return (installed_bp_data_t){
                .virt_data_read = read_bp_handle,
                .virt_data_write = write_bp_handle,
                .bp_type = Simics_Gdb_Virt_Data,
                .valid = true,
        };
}

static installed_bp_data_t
plant_virtual_bp(gdb_remote_t *gdb, bp_args_t *bp_args, void *bp_data)
{
        ASSERT(gdb->processor);
        switch (bp_args->type) {
        case Gdb_Bp_Software:
        case Gdb_Bp_Hardware:
                return plant_virtual_insn_bp(gdb, bp_args, bp_data);
        case Gdb_Bp_Write:
        case Gdb_Bp_Read:
        case Gdb_Bp_Access:
                return plant_virtual_data_bp(gdb, bp_args, bp_data);
        }
        ASSERT_FMT(0, "Bad breakpoint type %d", bp_args->type);
}

static installed_bp_data_t
plant_sim_breakpoint(gdb_remote_t *gdb, bp_args_t bp_args)
{
        breakpoint_id_t bp_id = SIM_breakpoint(
                gdb_context_object(gdb), Sim_Break_Virtual,
                type_to_access(bp_args.type), bp_args.la, bp_args.len,
                Sim_Breakpoint_Simulation);
        if (SIM_clear_exception()) {
                SIM_LOG_ERROR(to_obj(gdb), 0,
                              "Failed setting breakpoint: %s",
                              SIM_last_error());
                send_error(gdb, EINVAL);
                return (installed_bp_data_t){.valid = false};
        }

        SIM_LOG_INFO(3, to_obj(gdb), 0, "Set breakpoint id %d at %#llx",
                     bp_id, bp_args.la);

        hap_handle_t hap_id = SIM_hap_add_callback_index(
                "Core_Breakpoint_Memop", gdb_breakpoint_handler,
                gdb, bp_id);
        return (installed_bp_data_t){
                .bp_id = bp_id,
                .bp_type = Simics_Gdb_Bp_Hap,
                .hap_id = hap_id,
                .valid = true,
        };
}

static const char *
describe_bp_type(gdb_breakpoint_type_t type)
{
        switch (type) {
        case Gdb_Bp_Software:
                return "software";
        case Gdb_Bp_Hardware:
                return "hardware";
        case Gdb_Bp_Write:
                return "write";
        case Gdb_Bp_Read:
                return "read";
        case Gdb_Bp_Access:
                return "access";
        }
        return "<unknown>";
}

static void
do_handle_breakpoint(gdb_remote_t *gdb, const char *args, bool shall_set)
{
        bp_args_t bp_args = parse_breakpoint_args(gdb, args);
        if (!bp_args.valid) {
                SIM_LOG_ERROR(to_obj(gdb), 0,
                              "Badly formatted breakpoint: \"%s\"", args);
                send_error(gdb, EINVAL);
                return;
        }
        SIM_LOG_INFO(4, to_obj(gdb), 0, "Breakpoint 0x%llx-0x%llx type: %s",
                     (uint64)bp_args.la, (uint64)bp_args.la + bp_args.len - 1,
                     describe_bp_type(bp_args.type));
        int bp_idx = breakpoint_lookup(gdb, bp_args.la, bp_args.len,
                                       bp_args.type);

        struct gdb_breakpoints *b = &gdb->breakpoints;
        if (shall_set) {
                if (bp_idx >= 0) {
                        SIM_LOG_INFO(3, to_obj(gdb), 0,
                                     "Setting identical breakpoint");
                        ++b->entries[bp_idx].count;
                        send_ok(gdb);
                        return;
                }

                if (b->used >= b->size) {
                        b->size = b->size ? b->size * 2 : 16;
                        b->entries = MM_REALLOC(b->entries, b->size,
                                                struct gdb_breakpoint);
                }

                installed_bp_data_t bp_data;
                if (use_virtual_bp_iface(gdb)) {
                        bp_data = plant_virtual_bp(gdb, &bp_args,
                                                   &b->entries[b->used]);
                } else {
                        bp_data = plant_sim_breakpoint(gdb, bp_args);
                }
                if (!bp_data.valid)
                        return;

                b->entries[b->used].gdb = gdb;
                b->entries[b->used].la = bp_args.la;
                b->entries[b->used].len = bp_args.len;
                b->entries[b->used].type = bp_args.type;
                b->entries[b->used].bp_data = bp_data;
                b->entries[b->used].count = 1;
                b->used++;

        } else {
                if (bp_idx < 0) {
                        SIM_LOG_ERROR(to_obj(gdb), 0,
                                      "Could not find breakpoint to remove");
                        send_error(gdb, EINVAL);
                        return;
                }

                if (--b->entries[bp_idx].count) {
                        SIM_LOG_INFO(3, to_obj(gdb), 0,
                                     "removing multibreakpoint");
                        send_ok(gdb);
                        return;
                }

                cancel_breakpoint(&b->entries[bp_idx]);

                if (--b->used > 0) {
                        b->entries[bp_idx] = b->entries[b->used];
                }
        }

        send_ok(gdb);
        return;
}

static void
gdb_simulation_stopped_hap(void *_gdb, conf_object_t *obj)
{
        gdb_remote_t *gdb = (gdb_remote_t *)_gdb;

        SIM_LOG_INFO(3, to_obj(gdb), 0,
                     "Core_Simulation_Stopped hap; running %d",
                     gdb->is_running);

        gdb->is_running = false;

        if (gdb->stop_in_progress) {
                /* re-enable requests from gdb now that we have stopped */
                SIM_LOG_INFO(3, to_obj(gdb), 0, "clearing stop in progress");
                gdb->stop_in_progress = false;
                activate_gdb_notifier(gdb);
        } else {
                /* Stop that wasn't requested by GDB, notify it */
                do_signal(gdb, Sig_trap);
        }
}

static void
gdb_continuation_hap(void *_gdb, conf_object_t *obj)
{
        gdb_remote_t *gdb = (gdb_remote_t *)_gdb;

        SIM_LOG_INFO(3, to_obj(gdb), 0,
                     "Core_Continuation hap; running %d", gdb->is_running);
        gdb->is_running = true;
}

static const char *
vcont_parse(gdb_remote_t *gdb, const char *buffer, const char *rest,
            bool *c_found, int64 *c_thread,
            bool *s_found, int64 *s_thread)
{
        if (rest[0] != ';')
                return NULL;
        rest++;
        if (isupper((unsigned char)rest[0])) {
                SIM_LOG_UNIMPLEMENTED(
                        1, to_obj(gdb), 0,
                        "vCont: step or continue with signal: \"%s\"."
                        " Ignoring the signal part.",
                        buffer);
        }
        char action = tolower(rest[0]);
        rest++;
        if (action == 'c') {
                if (*c_found) {
                        SIM_LOG_UNIMPLEMENTED(
                                1, to_obj(gdb), 0,
                                "vCont packet with multiple continue actions,"
                                " ignoring all but the first action: \"%s\"",
                                buffer);
                }
                *c_found = true;
        } else if (action == 's') {
                if (*s_found) {
                        SIM_LOG_UNIMPLEMENTED(
                                1, to_obj(gdb), 0,
                                "vCont packet with multiple step actions,"
                                " ignoring all but the last action: \"%s\"",
                                buffer);
                }
                *s_found = true;
        } else {
                return NULL;
        }
        *(*c_found ? c_thread : s_thread)
                = (rest[0] == ':' ? hexstrtoll(rest + 1, &rest) : -1);
        return rest;
}

static void
handle_vcont(gdb_remote_t *gdb, const char *buffer)
{
        if (strcmp(buffer, "?") == 0) {
                send_packet(gdb, "vCont;c;C;s;S");
                return;
        }
        bool s_found = false, c_found = false;
        int64 c_thread = -1, s_thread = -1;
        const char *rest = buffer;
        while (rest[0] != '\0') {
                rest = vcont_parse(gdb, buffer, rest, &c_found,
                                   &c_thread, &s_found, &s_thread);
                if (rest == NULL) {
                        SIM_LOG_ERROR(to_obj(gdb), 0,
                                      "Malformed vCont packet \"%s\", ignoring",
                                      buffer);
                        return;
                }
        }

        if (s_found) {
                gdb->cont_thread = s_thread;
                conf_object_t *cpu = find_cpu_for_active_thread(
                        gdb, gdb->cont_thread);
                if (cpu) {
                        do_step(gdb, cpu);
                } else if (gdb->processor) {
                        SIM_LOG_ERROR(to_obj(gdb), 0,
                                      "Step on thread %lld which is not active"
                                      " on %s", s_thread,
                                      SIM_object_name(gdb->processor));
                } else {
                        gdb->on_thread_change = OTC_Single_Step;
                        post_continue(gdb);
                }
        } else if (c_found) {
                gdb->cont_thread = c_thread;
                post_continue(gdb);
        } else {
                SIM_LOG_ERROR(to_obj(gdb), 0,
                              "vCont packet without action, ignoring");
        }
}

static void
handle_verbose_packet(gdb_remote_t *gdb, const char *buffer)
{
        if (strncmp(buffer + 1, "Cont", 4) == 0) {
                handle_vcont(gdb, buffer + 5);
        } else if (strncmp(buffer + 1, "MustReplyEmpty", 14) == 0) {
                send_packet(gdb, "");
        } else {
                SIM_LOG_UNIMPLEMENTED(1, to_obj(gdb), 0,
                                      "verbose packet: [%s]\n",
                                      buffer);
        }
}

void
gdb_disconnect(gdb_remote_t *gdb)
{
        if (gdb->connected) {
                deactivate_gdb_notifier(gdb);
                CALL(gdb->server, close)(gdb);
                gdb->connected = false;
        }

        if (gdb->sim_stopped_hap_handle >= 0)
                SIM_hap_delete_callback_id("Core_Simulation_Stopped",
                                           gdb->sim_stopped_hap_handle);
        if (gdb->continuation_hap_handle >= 0)
                SIM_hap_delete_callback_id("Core_Continuation",
                                           gdb->continuation_hap_handle);

        for (int i = 0; i < gdb->breakpoints.used; ++i) {
                cancel_breakpoint(&gdb->breakpoints.entries[i]);
        }

        gdb->breakpoints.used = 0;

        SIM_LOG_INFO(2, to_obj(gdb), 0, "Disconnected");
}

static void
gdb_output_handler(void *_gdb, const char *src, size_t length)
{
        gdb_remote_t *gdb = _gdb;
        char buf[length * 2 + 2];
        char *p = buf;

        *p++ = 'O';

        for (int i = 0; i < length; ++i) {
                unsigned char c = src[i];
                *p++ = hexchar[c >> 4];
                *p++ = hexchar[c & 0xf];
        }
        *p = 0;

        send_packet_no_log(gdb, buf);
}

/* Run a CLI command, and send any output to gdb. */
static void
run_cli_command(gdb_remote_t *gdb, const char *cmd)
{
        SIM_add_output_handler(gdb_output_handler, gdb);
        attr_value_t ret = SIM_run_command(cmd);
        if (SIM_clear_exception() != SimExc_No_Exception) {
                strbuf_t error_msg = sb_newf("%s\n", SIM_last_error());
                gdb_output_handler(gdb, sb_str(&error_msg), sb_len(&error_msg));
                sb_free(&error_msg);
        }
        /* Use Python to format an attr_value_t in a readable way */
        if (!SIM_attr_is_invalid(ret)) {
                attr_value_t arg = SIM_make_attr_list(1, ret);
                attr_value_t pret = SIM_call_python_function(
                        "getattr(__builtins__, 'print')", &arg);
                SIM_attr_free(&pret);
                SIM_attr_free(&arg);
        }
        SIM_remove_output_handler(gdb_output_handler, gdb);
}

static void
handle_simics_command(gdb_remote_t *gdb, const char *cmd)
{
        if (!gdb->allow_remote_commands) {
                send_unsupported(gdb);
                return;
        }
        char str[strlen(cmd) / 2 + 1];
        int i = 0;

        while (isxdigit((unsigned char)cmd[i * 2])
               && isxdigit((unsigned char)cmd[i * 2 + 1])) {
                str[i] = (HEXVAL(cmd[i * 2]) << 4) + HEXVAL(cmd[i * 2 + 1]);
                ++i;
        }
        str[i] = 0;

        if (strcmp (str, "next-reverse-direction") == 0)
                gdb->next_reverse_direction = true;
        else
                run_cli_command(gdb, str);

        send_ok(gdb);
}

static bool
target_is_ppc64(gdb_remote_t *gdb)
{
        return strcmp(gdb->architecture, "ppc64") == 0;
}

static char *
gdb_arch_name(gdb_remote_t *gdb)
{
        attr_value_t attr;
        const char *attr_name = target_is_ppc64(gdb)
                ? "gdb_remote_architecture_64" : "gdb_remote_architecture";
        conf_object_t *cpu = gdb_any_processor(gdb);
        if (read_opt_attr(to_obj(gdb), cpu, attr_name, &attr)) {
                if (SIM_attr_is_string(attr)) {
                        return SIM_attr_string_detach(&attr);
                }
                SIM_LOG_ERROR(to_obj(gdb), 0, "Illegal type for attribute '%s'"
                              " in object '%s'", attr_name,
                              SIM_object_name(cpu));
                SIM_attr_free(&attr);
                return NULL;
        } else if (gdb->send_target_xml) {
                return MM_STRDUP(gdb->arch->arch_name);
        }

        return NULL;
}

static char *
target_xml(gdb_remote_t *gdb)
{
        char *arch_name = gdb_arch_name(gdb);
        SIM_LOG_INFO(3, to_obj(gdb), 0, "arch name is %s",
                     arch_name ? arch_name : "NULL");
        if (arch_name == NULL)
                return NULL;

        strbuf_t desc = sb_newf(
                "<target version=\"1.0\">\n"
                "  <architecture>%s</architecture>\n", arch_name);
        MM_FREE(arch_name);

        if (VLEN(gdb->register_descriptions) > 0) {
                register_section_t *rs;
                int base = 0;
                VFOREACH(gdb->register_sections, rs) {
                        sb_addfmt(&desc, "  <feature name=\"%s\">\n", rs->name);
                        for (int i = base; i < base + rs->length; i++) {
                                register_description_t *rd = &VGET(
                                        gdb->register_descriptions, i);
                                if (target_is_ppc64(gdb)) {
                                        if (rd->size == 32)
                                                rd->size = 64;
                                }
                                sb_addfmt(&desc, "    <reg name=\"%s\""
                                          " bitsize=\"%d\" type=\"%s\"/>\n",
                                          rd->name, rd->size, rd->type);
                        }
                        sb_addstr(&desc, "  </feature>\n");
                        base += rs->length;
                }
        }
        sb_addstr(&desc, "</target>\n");
        return sb_detach(&desc);
}

typedef VECT(char *) vect_str_t;

static void
free_vect_str(vect_str_t strings)
{
        char **str;
        VFOREACH(strings, str) {
                MM_FREE(*str);
        }
}

static vect_str_t
split_string(const char *str, char split_on) {
        vect_str_t result = VNULL;
        strbuf_t current = SB_INIT;
        for (const char *p = str; *p != '\0'; p++) {
                if (*p == split_on)
                        VADD(result, sb_detach(&current));
                else
                        sb_addc(&current, *p);
        }
        VADD(result, sb_detach(&current));
        return result;
}

static void
get_register_descriptions(gdb_remote_t *gdb, conf_object_t *cpu)
{
        attr_value_t attr;
        if (!read_opt_attr(to_obj(gdb), cpu, "gdb_remote_registers", &attr)) {
                return;
        }
        if (DBG_check_typing_system("[[s[[siisb]*]]*]", &attr) != Sim_Set_Ok) {
                SIM_LOG_ERROR(to_obj(gdb), 0, "bad gdb_remote_registers value");
                goto end;
        }
        for (unsigned i = 0; i < SIM_attr_list_size(attr); i++) {
                attr_value_t sv = SIM_attr_list_item(attr, i);
                const char *svvn = SIM_attr_string(SIM_attr_list_item(sv, 0));
                attr_value_t svv = SIM_attr_list_item(sv, 1);
                
                register_section_t rs = { .name = MM_STRDUP(svvn),
                                          .length = SIM_attr_list_size(svv) };

                VADD(gdb->register_sections, rs);
                for (unsigned j = 0; j < SIM_attr_list_size(svv); j++) {
                    attr_value_t reg = SIM_attr_list_item(svv, j);

                    register_description_t rd = {
                        .name = MM_STRDUP(
                                SIM_attr_string(SIM_attr_list_item(reg, 0))),
                        .size = SIM_attr_integer(SIM_attr_list_item(reg, 1)),
                        .regnum = SIM_attr_integer(SIM_attr_list_item(reg, 2)),
                        .type = MM_STRDUP(
                                SIM_attr_string(SIM_attr_list_item(reg, 3))),
                        .read = reg_read_int,
                        .write = SIM_attr_boolean(SIM_attr_list_item(reg, 4))
                        ? reg_write_ignore
                        : reg_write_int };
                    if (rd.size > 64) {
                            SIM_LOG_ERROR(to_obj(gdb), 0, "Register '%s' from"
                                          "'gdb_remote_registers' attribute has"
                                          " size > 64. Changing class so that"
                                          " reads and writes are ignored.",
                                          rd.name);
                            rd.read = reg_read_zero;
                            rd.write = reg_write_ignore;
                    }
                    if (rd.size % 8 != 0) {
                            int new_size = (rd.size + 7) / 8;
                            SIM_LOG_ERROR(to_obj(gdb), 0,
                                          "Register '%s' size (%d) from"
                                          " 'gdb_remote_registers' is not 8"
                                          " bits aligned, changing size to %d",
                                          rd.name, rd.size, new_size);
                            rd.size = new_size;
                    }

                    VADD(gdb->register_descriptions, rd);
                }
        }
  end:
        SIM_free_attribute(attr);
}

static void
read_query(gdb_remote_t *gdb, const char *buffer, const char *object,
           const char *annex, size_t offset, size_t length)
{
        if (strcmp(object, "features") != 0
            && strcmp(annex, "target.xml") != 0) {
                SIM_LOG_UNIMPLEMENTED(1, to_obj(gdb), 0,
                                      "unsupported read query: \"%s\"",
                                      buffer);
                send_unsupported(gdb);
                return;
        }
        char *repl = target_xml(gdb);
        size_t len = strlen(repl);
        size_t real_offset = MIN(offset, len);
        size_t real_length = MIN(length, len - real_offset);
        if (real_length == 0) {
                send_packet(gdb, "l"); /* no more data */
        } else {
                strbuf_t part = sb_new("m"); /* we have more data */
                sb_addmem(&part, repl + real_offset, real_length);
                send_packet(gdb, sb_str(&part));
                sb_free(&part);
        }
        MM_FREE(repl);
}

static void
parse_read_query(gdb_remote_t *gdb, const char *buffer,
                 const char *object, const char *annex,
                 const char *offset_length)
{
        vect_str_t offs_len = split_string(offset_length, ',');
        if (VLEN(offs_len) != 2)
                goto error;
        const char *endp;
        size_t offs = hexstrtoull(VGET(offs_len, 0), &endp, false);
        if (*endp != '\0')
                goto error;
        size_t len = hexstrtoull(VGET(offs_len, 1), &endp, false);
        if (*endp != '\0')
                goto error;
        read_query(gdb, buffer, object, annex, offs, len);
        goto end;
  error:
        SIM_LOG_ERROR(to_obj(gdb), 0, "malformed offset,length specification"
                      " in read query: \"%s\"", buffer);
        send_unsupported(gdb);
  end:
        free_vect_str(offs_len);
}

static void
handle_qxfer(gdb_remote_t *gdb, const char *cmd) {
        vect_str_t strings = split_string(cmd, ':');
        if (VLEN(strings) == 4
            && strcmp(VGET(strings, 1), "read") == 0) {
                parse_read_query(gdb, cmd, VGET(strings, 0),
                                 VGET(strings, 2), VGET(strings, 3));
        } else {
                SIM_LOG_UNIMPLEMENTED(1, to_obj(gdb), 0,
                                      "qXfer query \"%s\"",
                                      cmd);
                send_unsupported(gdb);
        }
        free_vect_str(strings);
}

static void
handle_get_tib_addr(gdb_remote_t *gdb, const char *cmd) {
        const char *endp;
        int64 tid = hexstrtoull(cmd, &endp, false);
        if (*endp != '\0')
                goto error;
        attr_value_t tib = SIM_run_command("@cgc.getTIB()");
        int64 ival = SIM_attr_integer(tib);
        char buf[8];
        sprintf(buf, "0x%x", ival);
        send_packet(gdb, buf);
        //send_packet(gdb, "0xdeadbeef");
        goto end;
  error:
        SIM_LOG_ERROR(to_obj(gdb), 0, "bad get_tib_addr specification"
                      " in get_tib_addr query: \"%s\"", cmd);
        send_unsupported(gdb);
  end:
}


static void
supported_query_arg(gdb_remote_t *gdb, const char *args)
{
        /*
         * GDB may send a semi-colon separated list of features it supports.
         * The currently defined GDB features (as of GDB 7.1.50) is:
         *   - multiprocess
         *   - xmlRegisters
         *   - qRelocInsn
         *
         * gdb-remote currently doesn't make use of this knowledge (i.e. we
         * currently don't care, don't _need_ to care, about whether GDB
         * supports the above features or not. The GDB manual states that
         * stubs should simply ignore unrecognized GDB features. So that's
         * exactly what we do.
         *
         * Note that we do support XML TDs, but we don't support the
         * xmlRegisters feature. I.e. we only support sending the XML TD
         * as a response to a qXfer request.
         */

        char *args_copy = MM_STRDUP(args);

        for (char *arg = strtok(args_copy, ";"); arg != NULL;
             arg = strtok(NULL, ";")) {
                SIM_LOG_UNIMPLEMENTED(
                        3, to_obj(gdb), 0,
                        "qSupported GDB feature: \"%s\" (ignoring)", arg);
        }
        MM_FREE(args_copy);

        strbuf_t reply = sb_new("ReverseStep+;ReverseContinue+");
        char *xml = target_xml(gdb);
        if (xml) {
                sb_addstr(&reply, ";qXfer:features:read+");
                MM_FREE(xml);
        }
        send_packet(gdb, sb_str(&reply));
}

static void
supported_query(gdb_remote_t *gdb)
{
        supported_query_arg(gdb, "");
}

static void
handle_qf_thread_info(gdb_remote_t *gdb)
{
        strbuf_t reply = sb_newf("m%llx", default_thread_id);
        send_packet(gdb, sb_str(&reply));
        sb_free(&reply);
}

static void
handle_qs_thread_info(gdb_remote_t *gdb)
{
        send_packet(gdb, "l");
}

static void
handle_thread_extra_info(gdb_remote_t *gdb, const char *thread_str)
{
        const char *desc = default_thread_name;

        strbuf_t buf = SB_INIT;
        for (int i = 0; desc[i]; i++) {
                gdb_write_hex(&buf, desc[i], false, 8);
        }
        send_packet(gdb, sb_str(&buf));
        sb_free(&buf);
}

static void
handle_qp(gdb_remote_t *gdb, const char *arg)
{
        enum modes { TAG_THREADID = 1,
                     TAG_EXISTS = 2,
                     TAG_DISPLAY = 4,
                     TAG_THREADNAME = 8,
                     TAG_MOREDISPLAY = 16 };

        if (strlen(arg) <= 8) {
                SIM_LOG_ERROR(to_obj(gdb), 0, "Too short qP packet");
                send_error(gdb, EINVAL);
        }

        char mode_str[8 + 1];
        memcpy(mode_str, arg, 8);
        mode_str[8] = '\n';
        uint32 mode = hexstrtoull(mode_str, NULL, false);
        int64 tid = hexstrtoull(arg + 8, NULL, false);

        bool thread_exists = tid == default_thread_id;

        const char *desc = NULL;
        if (thread_exists) {
                desc = default_thread_name;
        }

        strbuf_t buf = SB_INIT;
        gdb_write_hex(&buf, mode, false, 32);
        gdb_write_hex(&buf, tid, false, 64);
        if (mode & TAG_THREADID) {
                gdb_write_hex(&buf, TAG_THREADID, false, 32);
                gdb_write_hex(&buf, 16, false, 8);
                gdb_write_hex(&buf, tid, false, 64);
        }
        if (mode & TAG_EXISTS) {
                gdb_write_hex(&buf, TAG_EXISTS, false, 32);
                gdb_write_hex(&buf, 8, false, 8);
                gdb_write_hex(&buf, thread_exists, false, 32);
        }
        static const int name_modes[] = {
                TAG_DISPLAY, TAG_THREADNAME, TAG_MOREDISPLAY };
        for (int i = 0; i < ALEN(name_modes); i++) {
                if (thread_exists && (mode & name_modes[i])) {
                        gdb_write_hex(&buf, name_modes[i], false, 32);
                        gdb_write_hex(&buf, strlen(desc), false, 8);
                        sb_addstr(&buf, desc);
                }
        }
        send_packet(gdb, sb_str(&buf));
        sb_free(&buf);
}

static void
handle_qc(gdb_remote_t *gdb)
{
        /* current thread (?) */
        strbuf_t buf = sb_newf("QC%llx", gdb_cont(gdb).thread);
        send_packet(gdb, sb_str(&buf));
        sb_free(&buf);
}

static void
handle_qoffsets(gdb_remote_t *gdb)
{
        send_packet(gdb, "Text=0;Data=0;Bss=0");
}

static void
handle_qattached(gdb_remote_t *gdb)
{
        send_packet(gdb, "1"); // remote server attached to the process
}

static void
goto_bookmark(gdb_remote_t *gdb, const char *bookmark)
{
        SIM_LOG_INFO(2, to_obj(gdb), 0, "Skipping to bookmark %s", bookmark);

        strbuf_t cmd = sb_newf("skip-to %s", bookmark);
        SIM_run_command(sb_str(&cmd));
        sb_free(&cmd);

        if (SIM_clear_exception()) {
                SIM_LOG_ERROR(to_obj(gdb), 0,
                              "Failed skipping to bookmark %s",
                              SIM_last_error());
                send_error(gdb, EINVAL);
        } else {
                send_ok(gdb);
        }
}

static void
create_bookmark(void *arg)
{
        gdb_remote_t *gdb = arg;
        /* GDB starts counting at 1, lets do that here as well */
        static int bookmark_id = 1;

        // There is no good rev-exec API to use
        strbuf_t cmd = sb_newf("set-bookmark gdb_bookmark%d", bookmark_id++);
        attr_value_t ret = SIM_run_command(sb_str(&cmd));
        sb_free(&cmd);

        if (SIM_clear_exception()) {
                SIM_LOG_ERROR(to_obj(gdb), 0, "Failed creating bookmark: %s",
                              SIM_last_error());
                send_error(gdb, EINVAL);
        } else if (!SIM_attr_is_string(ret)) {
                SIM_LOG_ERROR(to_obj(gdb), 0, "Non-string value returned from"
                              " set-bookmark command.");
                send_error(gdb, EINVAL);
        } else {
                strbuf_t buf = sb_newf("QB%s", SIM_attr_string(ret));
                send_packet(gdb, sb_str(&buf));
                sb_free(&buf);
        }
        SIM_attr_free(&ret);
}

static void
handle_qbookmark(gdb_remote_t *gdb)
{
        SIM_run_alone(create_bookmark, gdb);
}

static void
general_query(gdb_remote_t *gdb, const char *buffer)
{
        typedef struct {
                const char *command;
                void (*handle_cmd)(gdb_remote_t *gdb);
        } cmd_without_arg_t;
        typedef struct {
                const char *prefix;
                void (*handle_cmd)(gdb_remote_t *gdb, const char *suffix);
        } cmd_with_arg_t;

        const cmd_without_arg_t cmds_without_arg[] = {
                {"C", handle_qc},
                {"Offsets", handle_qoffsets},
                {"Symbol::", send_ok},
                {"Supported", supported_query},
                {"fThreadInfo", handle_qf_thread_info},
                {"sThreadInfo", handle_qs_thread_info},
                {"Attached", handle_qattached},
                {"Bookmark", handle_qbookmark},
                {"TStatus", send_unsupported} // to avoid warning
        };
        const cmd_with_arg_t cmds_with_arg[] = {
                {"Rcmd,", handle_simics_command},
                {"ThreadExtraInfo,", handle_thread_extra_info},
                {"P", handle_qp},
                {"Xfer:", handle_qxfer},
                {"Supported:", supported_query_arg},
                {"GetTIBAddr:", handle_get_tib_addr},
                {"L", send_unsupported_with_args} // to avoid warning
        };

        for (int i = 0; i < ALEN(cmds_without_arg); i++) {
                if (strcmp(buffer + 1, cmds_without_arg[i].command) == 0) {
                        cmds_without_arg[i].handle_cmd(gdb);
                        return;
                }
        }
        for (int i = 0; i < ALEN(cmds_with_arg); i++) {
                const int len = strlen(cmds_with_arg[i].prefix);
                if (strncmp(buffer + 1, cmds_with_arg[i].prefix, len) == 0) {
                        cmds_with_arg[i].handle_cmd(gdb, buffer + len + 1);
                        return;
                }
        }

        SIM_LOG_UNIMPLEMENTED(1, to_obj(gdb), 0,
                              "general query \"%s\"", buffer);
        send_unsupported(gdb);
}

static void
handle_thread_alive(gdb_remote_t *gdb, const char *buffer)
{
        /* TODO: This is OK most of the time, but clearly broken.
           Ideally, we should examine the tracker_list.all_trackees
           list to see if the thread still exists. */
        send_ok(gdb);
}

static void
read_single_register(gdb_remote_t *gdb, const char *buffer)
{
        ASSERT(buffer[0] == 'p');
        const char *endp;
        size_t idx = hexstrtoull(buffer + 1, &endp, 0);
        if (*endp != '\0') {
                SIM_LOG_ERROR(to_obj(gdb), 0, "Malformed p packet: \"%s\"",
                              buffer + 1);
                send_error(gdb, EINVAL);
                return;
        }

        reg_desc_vect_t *rds = VLEN(gdb->register_descriptions) > 0
                ? &gdb->register_descriptions
                : &gdb->default_register_descriptions;

        register_description_t *rd;
        if (gdb->arch->reg_mapper) {
                rd = gdb->arch->reg_mapper(gdb, rds, idx);
        } else  {
                /* Register index is the index in our register VECT */
                if (idx >= VLEN(*rds)) {
                        SIM_LOG_INFO(2, to_obj(gdb), 0,
                                     "Bad index in single-register read: %zu"
                                     " (there are only %d registers)",
                                     idx, VLEN(*rds));

                        /* GDB seems to think we have more registers than we
                           think we have, and will ask for them with a 'p'
                           query. Returning unsupported seems to be the right
                           thing to do here, according to the gdb-serial
                           protocol reference. */
                        send_unsupported(gdb);
                        return;
                }
                rd = &VGET(*rds, idx);
        }

        cpu_thread_t ct = gdb_other(gdb);
        if (!ct.cpu)
                SIM_LOG_INFO(3, to_obj(gdb), 0,
                             "Reading register: Thread %lld not active,"
                             " pretending all registers are zero", ct.thread);



        uint64 val = ct.cpu ? rd->read(ct.cpu, rd) : 0;

        SIM_LOG_INFO(3, to_obj(gdb), 0,
                     "Reading 0x%llx from register %s", val, rd->name);
        strbuf_t buf = SB_INIT;
        gdb_write_hex(&buf, val, gdb->arch->is_be, rd->size);
        send_packet(gdb, sb_str(&buf));
        sb_free(&buf);
}

static void
write_single_register(gdb_remote_t *gdb, const char *buffer)
{
        cpu_thread_t ct = gdb_other(gdb);
        if (!ct.cpu) {
                SIM_LOG_INFO(1, to_obj(gdb), 0,
                             "Writing register: Thread %lld not active,"
                             " ignoring write", ct.thread);
                return;
        }

        strbuf_t err = SB_INIT;
        vect_str_t idx_val = split_string(buffer + 1, '=');
        if (VLEN(idx_val) != 2) {
                sb_set(&err, "P packet not in ID=VALUE format");
                goto error;
        }
        const char *endp;
        uint64 idx = hexstrtoull(VGET(idx_val, 0), &endp, 0);
        if (*endp != '\0') {
                sb_set(&err, "Malformed register ID in P packet");
                goto error;
        }

        reg_desc_vect_t *rds = VLEN(gdb->register_descriptions) > 0
                ? &gdb->register_descriptions
                : &gdb->default_register_descriptions;

        register_description_t *rd;
        if (gdb->arch->reg_mapper) {
                rd = gdb->arch->reg_mapper(gdb, rds, idx);
        } else {
                if (idx >= VLEN(*rds)) {
                        sb_fmt(&err, "Illegal register ID (%llu) in P packet", idx);
                        goto error;
                }
                rd = &VGET(*rds, idx);
        }

        const char *val_str = VGET(idx_val, 1);
        if (rd->size > 64) {
                SIM_LOG_INFO(1, to_obj(gdb), 0,
                             "Writing to '%s which is > 64 bits', ignoring",
                             rd->name);
                send_error(gdb, EACCES);
                goto error;
        }
        uint64 val = gdb_read_hex(&val_str, gdb->arch->is_be, rd->size);
        if (*val_str != '\0') {
                sb_set(&err, "Malformed register value in P packet");
                goto error;
        }

        bool success = rd->write(ct.cpu, rd, val);
        if (success) {
                SIM_LOG_INFO(3, to_obj(gdb), 0,
                             "Writing 0x%llx to register %s", val, rd->name);
                send_ok(gdb);
        } else {
                SIM_LOG_INFO(1, to_obj(gdb), 0,
                             "Failed writing 0x%llx to register %s", val,
                             rd->name);
                send_error(gdb, EACCES);
        }

  error:
        if (sb_len(&err)) {
                SIM_LOG_ERROR(to_obj(gdb), 0, "%s: %s", sb_str(&err), buffer);
                sb_free(&err);
                send_error(gdb, EINVAL);
        }
        free_vect_str(idx_val);
}

static void
read_registers(gdb_remote_t *gdb, strbuf_t *buf)
{
        cpu_thread_t ct = gdb_other(gdb);
        if (!ct.cpu)
                SIM_LOG_INFO(3, to_obj(gdb), 0,
                             "Reading registers: Thread %lld not active,"
                             " pretending all registers are zero", ct.thread);

        reg_desc_vect_t *rds = VLEN(gdb->register_descriptions) > 0
                ? &gdb->register_descriptions
                : &gdb->default_register_descriptions;
        VFOREACH_T(*rds, register_description_t, rd) {
                uint64 val = ct.cpu ? rd->read(ct.cpu, rd) : 0;
                gdb_write_hex(buf, val, gdb->arch->is_be, rd->size);
        }
}

static void
write_registers(gdb_remote_t *gdb, const char *buf)
{
        cpu_thread_t ct = gdb_other(gdb);
        if (!ct.cpu) {
                SIM_LOG_INFO(3, to_obj(gdb), 0,
                             "Writing registers: Thread %lld not active,"
                             " ignoring write", ct.thread);
                return;
        }

        reg_desc_vect_t *rds = VLEN(gdb->register_descriptions) > 0
                ? &gdb->register_descriptions
                : &gdb->default_register_descriptions;
        VFOREACH_T(*rds, register_description_t, rd) {
                if (rd->size > 64) {
                        SIM_LOG_INFO(1, to_obj(gdb), 0,
                                     "Writing to '%s' which is > 64 bits,"
                                     " ignoring", rd->name);
                        advance_buffer(&buf, rd->size);
                } else {
                        uint64 val = gdb_read_hex(&buf, gdb->arch->is_be,
                                                  rd->size);
                        rd->write(ct.cpu, rd, val);
                }
        }
}

void
handle_ctrl_c(gdb_remote_t *gdb)
{
        VT_abort_user(NULL);
        stop_simulation(gdb);
        SIM_register_work(send_sigint, gdb);
}

static void
handle_reset(gdb_remote_t *gdb, const char *buf)
{
        conf_object_t *cpu = gdb_other(gdb).cpu;
        int hard_reset = atoi(buf);
        SIM_reset_processor(cpu, hard_reset);
        if (SIM_clear_exception())
                SIM_LOG_ERROR(
                        to_obj(gdb), 0,
                        "Failed to reset processor: %s", SIM_last_error());
}

/* The segment commands adds offsets to breakpoints. This is a custom
   command so not officially supported in the GDB remote protocol. */
static void
handle_segment(gdb_remote_t *gdb, const char *buf)
{
        /* Remove leading spaces. */
        while(buf[0] == ' ')
                buf += 1;

        if (buf[0] == '0' && (buf[1] == 'x' || buf[1] == 'X')) {
                buf += 2;
        }
        const char *endp;
        uint64 new_segm = hexstrtoull(buf, &endp, false);
        if (*endp != '"') {
                SIM_LOG_INFO(1, to_obj(gdb), 0,
                             "Badly formatted segment command");
                send_error(gdb, EINVAL);
        } else {
                gdb->segment_linear_base = new_segm;
                SIM_LOG_INFO(3, to_obj(gdb), 0, "Segment updated to 0x%x",
                             gdb->segment_linear_base);
                send_ok(gdb);
        }
}

void
unhandled_command(gdb_remote_t *gdb, const char *cmd)
{
        if (gdb->extender) {
                char *reply = gdb->extender_iface->handle_command(gdb->extender,
                                                                  cmd);
                send_packet(gdb, reply);
                MM_FREE(reply);
        } else {
                send_unsupported(gdb);
        }
}

/* Carry out a command sent by gdb. */
void
gdb_serial_command(gdb_remote_t *gdb, const char *cmd)
{
        unsigned char ch = cmd[0];
        if (ch == 3)
                SIM_LOG_INFO(4, to_obj(gdb), 0, "got message: \"^C\"");
        else
                SIM_LOG_INFO(4, to_obj(gdb), 0, "got message: \"%s\"", cmd);

        switch (ch) {
        case 3:
                handle_ctrl_c(gdb);
                break;

        case '!':       /* extended ops */
                SIM_LOG_INFO(3, to_obj(gdb), 0, "! = Extended ops");
                break;

        case '?': {      /* last signal */
                SIM_LOG_INFO(3, to_obj(gdb), 0, "? = last signal");
                strbuf_t buf = SB_INIT;
                stop_reply_packet(gdb, &buf, Sig_trap);
                send_packet(gdb, sb_str(&buf));
                sb_free(&buf);
                break;
        }

        case 'D':       /* detach */
                SIM_LOG_INFO(3, to_obj(gdb), 0, "D = detach");
                send_packet(gdb, "OK");
                gdb_disconnect(gdb);
                break;

        case 'H':       /* set thread */
                switch (cmd[1])
                {
                case 'g':
                        SIM_LOG_INFO(3, to_obj(gdb), 0,
                                     "Hg = last signal, thread used in"
                                     " other operations");
                        gdb->other_thread =
                                hexstrtoll(cmd + 2, NULL);
                        send_ok(gdb);
                        break;
                case 'c':
                        SIM_LOG_INFO(3, to_obj(gdb), 0,
                                     "Hc = last signal, thread used in"
                                     " step/continue");
                        gdb->cont_thread = hexstrtoll(cmd + 2, NULL);
                        send_ok(gdb);
                        break;
                default:
                        SIM_printf("H%c = last signal, not defined\n",
                                   cmd[1]);
                        break;
                }
                break;

        case 'g': {     /* read registers */
                SIM_LOG_INFO(3, to_obj(gdb), 0,
                             "g = read registers"
                             " (current thread = %lld)",
                             gdb_other(gdb).thread);
                strbuf_t buf = SB_INIT;
                read_registers(gdb, &buf);
                send_packet(gdb, sb_str(&buf));
                sb_free(&buf);
                break;
        }

        case 'G':       /* write regs */
                SIM_LOG_INFO(3, to_obj(gdb), 0,
                             "G = write regs"
                             " (current thread = %lld",
                             gdb_other(gdb).thread);
                write_registers(gdb, cmd + 1);
                send_ok(gdb);
                break;

        case 'm':       /* read mem */
                SIM_LOG_INFO(3, to_obj(gdb), 0, "m = read mem");
                send_memory(gdb, cmd + 1);
                break;

        case 'M':       /* write mem */
                SIM_LOG_INFO(3, to_obj(gdb), 0, "M = write mem");
                write_memory(gdb, cmd + 1);
                break;

        case 'C':       /* continue with signal */
                SIM_LOG_UNIMPLEMENTED(1, to_obj(gdb), 0,
                                      "C = continue with signal");
                unhandled_command(gdb, cmd);
                break;

        case 'S':       /* step with signal */
                SIM_LOG_UNIMPLEMENTED(1, to_obj(gdb), 0,
                                      "S = step with signal");
                unhandled_command(gdb, cmd);
                break;

        case 'b':
                if (cmd[1] == 's') {
                        SIM_LOG_INFO(3, to_obj(gdb), 0,
                                     "a = reverse step");
                        do_reverse (gdb);
                        break;
                } else if (cmd[1] == 'c') {
                        /* Backwards continue */
                        gdb->next_reverse_direction = true;
                        post_continue(gdb);
                        break;
                } else {
                        SIM_LOG_UNIMPLEMENTED(1, to_obj(gdb), 0,
                                              "unsupported backwards "
                                              "continue arg");
                        unhandled_command(gdb, cmd);
                        break;
                }

        case 'c':       /* continue */
                SIM_LOG_INFO(3, to_obj(gdb), 0, "c = continue");
                if (cmd[1]) {
                        /* can't continue with address */
                        SIM_LOG_UNIMPLEMENTED(1, to_obj(gdb), 0,
                                              "unsupported continue "
                                              "arg");
                        unhandled_command(gdb, cmd);
                        break;
                }

                SIM_LOG_INFO(3, to_obj(gdb), 0, "Continue");
                post_continue(gdb);
                break;

        case 's':       /* step */
                SIM_LOG_INFO(3, to_obj(gdb), 0, "s = step");
                if (cmd[1]) {
                        SIM_LOG_UNIMPLEMENTED(1, to_obj(gdb), 0,
                                              "unsupported step arg");
                        unhandled_command(gdb, cmd);
                        break;
                }
                handle_vcont(gdb, ";s");
                break;

        case 'k':       /* kill */
                SIM_LOG_UNIMPLEMENTED(1, to_obj(gdb), 0, "k = kill");
                unhandled_command(gdb, cmd);
                break;
        case 'T':       /* thread alive */
                SIM_LOG_INFO(3, to_obj(gdb), 0, "T = thread alive");
                handle_thread_alive(gdb, cmd + 1);
                break;

        case 'R':       /* remote restart */
                handle_reset(gdb, cmd + 1);
                break;

        case 'r':       /* reset */
                SIM_LOG_UNIMPLEMENTED(1, to_obj(gdb), 0, "r = reset");
                unhandled_command(gdb, cmd);
                break;

        case 'q':       /* general query */
                SIM_LOG_INFO(3, to_obj(gdb), 0, "q = general query");
                general_query(gdb, cmd);
                break;

        case 'p': /* read single register */
                SIM_LOG_INFO(3, to_obj(gdb), 0,
                             "p = read single register"
                             " (thread = %lld)",
                             gdb_other(gdb).thread);
                read_single_register(gdb, cmd);
                break;

        case 'P': /* write single register */
                SIM_LOG_INFO(3, to_obj(gdb), 0,
                             "P = write single register"
                             " (thread = %lld)",
                             gdb_other(gdb).thread);
                write_single_register(gdb, cmd);
                break;

        case 'Q':       /* general set */
                SIM_LOG_INFO(3, to_obj(gdb), 0, "Q = general set");
                if (strlen(cmd) >= 10 && strncmp(cmd, "QBookmark:", 10) == 0) {
                        goto_bookmark(gdb, cmd + 10);
                } else {
                        SIM_LOG_UNIMPLEMENTED(1, to_obj(gdb), 0,
                                              "Q = general set (%s)", cmd);
                        unhandled_command(gdb, cmd);
                }
                break;

        case 'Z':
                SIM_LOG_INFO(3, to_obj(gdb), 0, "Z = set breakpoint");
                do_handle_breakpoint(gdb, cmd + 1, true);
                break;

        case 'z':
                SIM_LOG_INFO(3, to_obj(gdb), 0, "z = remove breakpoint");
                do_handle_breakpoint(gdb, cmd + 1, false);
                break;

        case 'X': /* write binary memory */
                SIM_LOG_UNIMPLEMENTED(1, to_obj(gdb), 0,
                                      "X = write binary memory");
                unhandled_command(gdb, cmd);
                break;

        case 'e': /* undocumented step range thingie */
                SIM_LOG_UNIMPLEMENTED(1, to_obj(gdb), 0,
                                      "e = step thingie");
                unhandled_command(gdb, cmd);
                break;

        case 'v':       /* verbose packet prefix */
                handle_verbose_packet(gdb, cmd);
                break;

        case '"':      /* custom commands. */
                if (strncmp(cmd, "\"segment,", 9) == 0) {
                        handle_segment(gdb, &cmd[9]);
                        break;
                }
                /* Fall-through */
        default:        /* unknown protocol */
                if (isprint(ch)) {
                        SIM_LOG_ERROR(to_obj(gdb), 0,
                                      "%#2.2x (%c) = unknown request",
                                      ch, ch);
                } else {
                        SIM_LOG_ERROR(to_obj(gdb), 0,
                                      "%#2.2x = unknown request", ch);
                }
                unhandled_command(gdb, cmd);
                break;
        }
}

/* Return true if CPU_ARCH_NAME match GDB_ARCH_NAME in any
   combination with endian and variant.  IS_BIGENDIAN is one if target
   architecture is configured as big endian.  */
static bool
arch_match_p(const char *gdb_arch_name, const char *cpu_arch_name,
             bool is_bigendian, const char *variant)
{
        const char *const endian_names[] = { "le", "be" };

        if (variant && strlen (variant)) {
                if (strncmp (gdb_arch_name, cpu_arch_name,
                             strlen (cpu_arch_name)) == 0
                    && gdb_arch_name[strlen (cpu_arch_name)] == '_'
                    && strcmp (gdb_arch_name + strlen (cpu_arch_name)
                               + 1, variant) == 0)
                        return true;
                if (strncmp (gdb_arch_name, cpu_arch_name,
                             strlen (cpu_arch_name)) == 0
                    && strncmp (gdb_arch_name + strlen (cpu_arch_name),
                                endian_names[is_bigendian], 2) == 0
                    && gdb_arch_name[strlen (cpu_arch_name) + 2] == '_'
                    && strcmp (gdb_arch_name + strlen (cpu_arch_name)
                               + 2 + 1, variant) == 0)
                        return true;
        } else {
                if (strcmp (gdb_arch_name, cpu_arch_name) == 0)
                        return 1;
                if (strncmp (gdb_arch_name, cpu_arch_name,
                             strlen (cpu_arch_name)) == 0
                    && strcmp (gdb_arch_name + strlen (cpu_arch_name),
                               endian_names[is_bigendian]) == 0)
                        return true;
        }

        return false;
}

static const struct gdb_arch *
find_gdb_arch(const char *architecture, bool is_bigendian, const char *variant)
{
        for (int i = 0; gdb_archs[i]; i++) {
                const gdb_arch_t *a = gdb_archs[i];
                if (arch_match_p(a->name, architecture, is_bigendian, variant))
                        return a;
        }
        return NULL;
}

static bool
arch_reg_init(gdb_remote_t *gdb, conf_object_t *cpu, int bits,
              const char *name, regclass_t regclass)
{
        if (SIM_clear_exception()) {
                SIM_LOG_ERROR(to_obj(gdb), 0, "arch_reg_init() called with"
                              " pending exception: %s",
                              SIM_last_error());
        }

        const int_register_interface_t *const ir =
                SIM_c_get_interface(cpu, INT_REGISTER_INTERFACE);
        if (ir == NULL) {
                SIM_LOG_ERROR(to_obj(gdb), 0,
                              "cannot find %s interface in CPU %s",
                              INT_REGISTER_INTERFACE, SIM_object_name(cpu));
                return false;
        }

        if (bits > 64 && regclass != regclass_unused) {
                SIM_LOG_ERROR(to_obj(gdb), 0, "Register '%s' has size > 64 bits,"
                              " but wrong class. Changing class so that"
                              " reads and writes are ignored.", name);
                regclass = regclass_unused;
        }
        if (bits % 8 != 0) {
                int new_bits = (bits + 7) / 8;
                SIM_LOG_ERROR(to_obj(gdb), 0,
                              "Register '%s' size (%d) is not 8 bits aligned,"
                              " changing size to %d", name, bits, new_bits);
                            bits = new_bits;
        }

        register_description_t rd = {
                .name = name, .size = bits, .type = NULL };
        switch (regclass) {
        case regclass_i:
        case regclass_i_opt:
        case regclass_i32l:
        case regclass_i32h:
                rd.regnum = ir->get_number(cpu, name);
                if (rd.regnum < 0) {
                        if (regclass != regclass_i_opt) {
                                SIM_LOG_ERROR(to_obj(gdb), 0, "cannot find"
                                              " register %s in CPU %s",
                                              name, SIM_object_name(cpu));
                                return false;
                        }
                        rd.regnum = -1;
                        rd.read = reg_read_zero;
                        rd.write = reg_write_ignore;
                } else if (regclass == regclass_i32l) {
                        rd.read = reg_read_int32l;
                        rd.write = reg_write_int32l;
                } else if (regclass == regclass_i32h) {
                        rd.read = reg_read_int32h;
                        rd.write = reg_write_int32h;
                } else {
                        rd.read = reg_read_int;
                        rd.write = reg_write_int;
                }
                break;
        case regclass_v9_f:
                break;
        case regclass_unused:
                rd.regnum = 0;
                rd.read = reg_read_zero;
                rd.write = reg_write_ignore;
                break;
        }
        VADD(gdb->default_register_descriptions, rd);
        return true;
}


static bool
init_regs(gdb_remote_t *gdb, conf_object_t *cpu, const gdb_arch_t *arch)
{
        if (arch->init && !arch->init(gdb, cpu))
                return false;

        if (!VEMPTY(gdb->default_register_descriptions)
            || !VEMPTY(gdb->register_descriptions))
                return true;                 /* already initialised */

        /* Try to get the registers from the gdb_remote_registers attribute */
        get_register_descriptions(gdb, cpu);
        if (!VEMPTY(gdb->register_descriptions))
            return true;

        for (int i = 0; i < arch->nregs; i++) {
                const regspec_t *r = &arch->regs[i];
                if (!arch_reg_init(gdb, cpu, r->bits, r->name, r->regclass))
                        return false;
        }
        return true;
}

/* Return true on success, false on failure. */
static bool
setup_architecture(gdb_remote_t *gdb)
{
        conf_object_t *cpu = gdb_any_processor(gdb);
        cpu_endian_t endian = processor_iface(cpu)->get_endian(cpu);

        bool is_bigendian = (endian == Sim_Endian_Big);

        if (!gdb->architecture) {
                attr_value_t arch_attr = SIM_get_attribute(cpu, "architecture");
                if (SIM_clear_exception()) {
                        SIM_LOG_ERROR(to_obj(gdb), 0,
                                      "Error reading attribute"
                                      " architecture from"
                                      " object %s: %s",
                                      SIM_object_name(cpu),
                                      SIM_last_error());
                        return false;
                } else if (!SIM_attr_is_string(arch_attr)) {
                        SIM_LOG_ERROR(to_obj(gdb), 0,
                                      "Failed getting architecture from %s.",
                                      SIM_object_name(cpu));
                        return false;
                }
                gdb->architecture = SIM_attr_string_detach(&arch_attr);
        }

        /* If processor had a context object try to get the
           gdb-remote-variant attribute.  It is used to match
           GDB stub architecture.  */
        char *variant = NULL;
        if (gdb_context_object(gdb)) {
                attr_value_t attr = SIM_get_attribute(gdb_context_object(gdb),
                                                      "gdb_remote_variant");
                if (SIM_attr_is_string(attr)) {
                        variant = SIM_attr_string_detach(&attr);
                } else if (SIM_clear_exception()) {
                        SIM_LOG_ERROR(to_obj(gdb), 0,
                                      "Error reading attribute"
                                      " gdb_remote_variant from"
                                      " object %s: %s",
                                      SIM_object_name(gdb_context_object(gdb)),
                                      SIM_last_error());
                } else if (!SIM_attr_is_nil(attr)) {
                        SIM_LOG_ERROR(to_obj(gdb), 0,
                                      "Unexpected type of attribute "
                                      " gdb_remote_variant in"
                                      " object %s",
                                      SIM_object_name(gdb_context_object(gdb)));
                }
        }

        const struct gdb_arch *arch = find_gdb_arch(gdb->architecture,
                                                    is_bigendian, variant);
        MM_FREE(variant);

        if (arch == NULL) {
                SIM_LOG_ERROR(to_obj(gdb), 0, "Unsupported CPU architecture: %s",
                              gdb->architecture);
                return false;
        }

        if (!gdb->arch) {
                SIM_LOG_INFO(2, to_obj(gdb), 0, "Attached to %s",
                             SIM_object_name(gdb->context_object
                                             ? gdb->context_object
                                             : cpu));
        }

        /* FIXME jrydberg 2006-02-09: Why shouldn't this be possible? */
        if (gdb->arch && gdb->arch != arch) {
                SIM_LOG_ERROR(to_obj(gdb), 0,
                              "Cannot change CPU architecture.");
                return false;
        }

        gdb->arch = arch;

        attr_value_t queue_attr = SIM_make_attr_object(SIM_object_clock(cpu));
        if (SIM_set_attribute(to_obj(gdb), "queue", &queue_attr) != Sim_Set_Ok) {
                SIM_LOG_ERROR(to_obj(gdb), 0,
                              "error setting queue from CPU %s: %s",
                              SIM_object_name(cpu), SIM_last_error());
                return false;
        }

        if (!init_regs(gdb, cpu, arch)) {
                gdb->arch = NULL;
                queue_attr = SIM_make_attr_nil();
                SIM_set_attribute(to_obj(gdb), "queue", &queue_attr);
                return false;
        }

        return true;
}

/* Called when we've done accept() on the socket and after simulation has
   stopped */
static void
gdb_connected(void *gdb_ptr)
{
        gdb_remote_t *gdb = gdb_ptr;

        if (gdb->arch == NULL) {
                if (!setup_architecture(gdb)) {
                        gdb_disconnect(gdb);
                        return;
                }
        }

        activate_gdb_notifier(gdb);

        gdb->sim_stopped_hap_handle
                = SIM_hap_add_callback("Core_Simulation_Stopped",
                                       gdb_simulation_stopped_hap, gdb);
        gdb->continuation_hap_handle
                = SIM_hap_add_callback("Core_Continuation",
                                       gdb_continuation_hap, gdb);

        if (SIM_simics_is_running()) {
                VT_stop_message(to_obj(gdb), "Remote GDB connected");
                /*  Just connected, so cannot call stop_simulation(). Still
                    want to disable sending async stop that may be received by
                    GDB while waiting for a command reply. */
                gdb->stop_in_progress = true;
        }
}

static void
external_connection_events_on_input(
        conf_object_t *obj,
        void *cookie)
{
        read_gdb_data(cookie);
}

/* A remote GDB has requested to connect to this GDB stub.  Accept it
   and fetch GDB stub architecture (done in set_gdb_cpu.)  */
static void
external_connection_events_on_accept(
        conf_object_t *obj,
        conf_object_t *server,
        uint64 id)
{
        gdb_remote_t *gdb = gdb_of_obj(obj);

        /* Only accept one connection per gdb-remote object, otherwise
           we might end up in tricky situations.  */
        if (gdb->connected) {
                CALL(gdb->server, accept)(id, NULL, false);
                return;
        }

        INIT_REQUIRED_IFACE(&gdb->server, external_connection_ctl, server);
        gdb->connected = true;
        CALL(gdb->server, accept)(id, gdb, false);
        SIM_LOG_INFO(3, obj, 0, "New GDB connection established");
        if (socket_write(gdb, "+", 1) != 1) {
                SIM_LOG_INFO(1, obj, 0,
                             "Connection successful but failed to respond"
                             " with a '+'");
        }
        /* Make sure we have halted simulation before continuing */
        SIM_register_work(gdb_connected, gdb);
}

enum {
        Server_TCP,
        Server_UNIX,
        Server_Pipe,
};

typedef struct {
        const char *port;
        const char *class;
        const char *desc;
} server_info_t;

#ifdef _WIN32
static const server_info_t servers[] = {
        [Server_TCP] = {.port = "tcp", .class = "tcp-server",
                        .desc = "gdb-remote TCP server"},
        [Server_Pipe] = {.port = "named_pipe",
                         .class = "named-pipe-server",
                         .desc = "gdb-remote Windows named pipe server"},
};
#else
static const server_info_t servers[] = {
        [Server_TCP] = {.port = "tcp", .class = "tcp-server",
                        .desc = "gdb-remote TCP server"},
        [Server_UNIX] = {.port = "unix_socket",
                         .class = "unix-socket-server",
                         .desc = "gdb-remote Unix domain socket server"},
};
#endif

static attr_value_t
get_processor(conf_object_t *obj)
{
        gdb_remote_t *gdb = gdb_of_obj(obj);
        return SIM_make_attr_object (gdb->processor);
}

static set_error_t
set_processor(conf_object_t *obj, attr_value_t *val)
{
        gdb_remote_t *gdb = gdb_of_obj(obj);
        conf_object_t *cpu = SIM_attr_is_nil(*val) ? NULL : SIM_attr_object(*val);
        if (cpu && !processor_iface(cpu)) {
                SIM_LOG_ERROR(
                        to_obj(gdb), 0,
                        "Failed getting " PROCESSOR_INFO_INTERFACE
                        " interface from CPU %s.",
                        SIM_object_name(cpu));
                return Sim_Set_Interface_Not_Found;
        } else {
                gdb->processor = cpu;
                if (cpu) {
                        SIM_LOG_INFO(2, to_obj(gdb), 0, "Attached to CPU: %s",
                                     SIM_object_name(cpu));
                } else {
                        SIM_LOG_INFO(2, to_obj(gdb), 0,
                                     "Not attached to a CPU");
                }
                return Sim_Set_Ok;
        }
}

static set_error_t
set_signal(conf_object_t *obj, attr_value_t *val)
{
        gdb_remote_t *gdb = gdb_of_obj(obj);

        int64 ival = SIM_attr_integer(*val);
        if (ival <= 0 || ival > 255) {
                SIM_attribute_error("Signal number must be in 1..255");
                return Sim_Set_Illegal_Value;
        }

        do_signal(gdb, ival);
        return Sim_Set_Ok;
}

static set_error_t
set_send_packet(conf_object_t *obj, attr_value_t *val)
{
        gdb_remote_t *gdb = gdb_of_obj(obj);

        const char *str = SIM_attr_string(*val);
        send_packet(gdb, str);
        SIM_attr_free(val);
        return Sim_Set_Ok;
}

static set_error_t
set_large_operations(conf_object_t *obj, attr_value_t *val)
{
        gdb_remote_t *gdb = gdb_of_obj(obj);
        gdb->large_operations = !!SIM_attr_integer(*val);
        return Sim_Set_Ok;
}

static attr_value_t
get_large_operations(conf_object_t *obj)
{
        gdb_remote_t *gdb = gdb_of_obj(obj);
        return SIM_make_attr_uint64(gdb->large_operations);
}

static set_error_t
set_disconnect(conf_object_t *obj, attr_value_t *val)
{
        gdb_remote_t *gdb = gdb_of_obj(obj);
        gdb_disconnect(gdb);
        return Sim_Set_Ok;
}

static attr_value_t
get_connected(conf_object_t *obj)
{
        gdb_remote_t *gdb = gdb_of_obj(obj);
        return SIM_make_attr_boolean(gdb->connected);
}

static bool
is_cont_thread(gdb_remote_t *gdb, conf_object_t *ctx, conf_object_t *cpu)
{
        ASSERT(!gdb->processor);
        return ctx == gdb_context_object(gdb)
                && is_current_thread(gdb, gdb->cont_thread, cpu);
}

static void
thread_change(gdb_remote_t *gdb, conf_object_t *ctx, conf_object_t *cpu)
{
        if (gdb->processor) {
                ASSERT(gdb->on_thread_change == OTC_Do_Nothing);
                return;
        }
        switch (gdb->on_thread_change) {
        case OTC_Do_Nothing:
                break;
        case OTC_Stop:
                if (is_cont_thread(gdb, ctx, cpu)) {
                        gdb->on_thread_change = OTC_Do_Nothing;
                        VT_stop_finished(NULL);
                        stop_simulation(gdb);
                        SIM_register_work(send_sigtrap, gdb);
                }
                break;
        case OTC_Single_Step:
                if (is_cont_thread(gdb, ctx, cpu)) {
                        gdb->on_thread_change = OTC_Do_Nothing;
                        do_step(gdb, cpu);
                }
                break;
        }
}

static void
context_change(void *_gdb, conf_object_t *ctx_obj, conf_object_t *cpu)
{
        gdb_remote_t *gdb = _gdb;

        thread_change(gdb, ctx_obj, cpu);
}

static void
thread_active(gdb_remote_t *gdb, conf_object_t *cpu, bool active)
{
        if (active)
                thread_change(gdb, gdb_context_object(gdb), cpu);
}

/* Connect to thread_tracker by ugly-reading attributes. */
static void
context_updated(void *_gdb, conf_object_t *ctx_obj)
{
        gdb_remote_t *gdb = _gdb;

        attr_value_t cpus = default_processor_list(to_obj(gdb));
        for (int i = 0; i < SIM_attr_list_size(cpus); i++) {
                conf_object_t *cpu
                        = SIM_attr_object(SIM_attr_list_item(cpus, i));
                thread_active(gdb, cpu, true);
        }
        SIM_attr_free(&cpus);
}

static attr_value_t
get_architecture(conf_object_t *obj)
{
        gdb_remote_t *gdb = (gdb_remote_t *) obj;
        return SIM_make_attr_string(gdb->architecture);
}

static set_error_t
set_architecture(conf_object_t *obj, attr_value_t *val)
{
        gdb_remote_t *gdb = gdb_of_obj(obj);
        gdb->architecture = MM_STRDUP(SIM_attr_string(*val));
        return Sim_Set_Ok;
}

static set_error_t
set_extender(conf_object_t *obj, attr_value_t *val)
{
        gdb_remote_t *gdb = gdb_of_obj(obj);
        conf_object_t *extender = SIM_attr_object_or_nil(*val);

        if (extender) {
                const gdb_extender_interface_t *iface = SIM_c_get_interface(
                        extender, GDB_EXTENDER_INTERFACE);
                if (iface == NULL)
                        return Sim_Set_Interface_Not_Found;
                gdb->extender = extender;
                gdb->extender_iface = iface;
        } else {
                gdb->extender = NULL;
        }
        return Sim_Set_Ok;
}

static attr_value_t
get_extender(conf_object_t *obj)
{
        gdb_remote_t *gdb = (gdb_remote_t *) obj;
        return SIM_make_attr_object(gdb->extender);
}

static attr_value_t
get_listen(conf_object_t *obj)
{
        return SIM_get_attribute(
                SIM_object_descendant(obj, servers[Server_TCP].port), "port");
}

/* Called when the ``listen'' attribute of the object is set to a
   value.  Only integers are accepted.  Start listening for GDB remote
   connections to the specified port.  */

static set_error_t
set_listen(conf_object_t *obj, attr_value_t *val)
{
        // Do not trigger connection change if restoring micro checkpoint
        if (SIM_is_loading_micro_checkpoint(obj))
                return Sim_Set_Ok;

        gdb_remote_t *gdb = gdb_of_obj(obj);
#if !defined(SIMICS_4_8_API) && !defined(SIMICS_5_API)
        if (!SIM_is_restoring_state(obj)) {
                SIM_LOG_INFO(
                        1, obj, 0,
                        "The <" DEVICE_NAME ">->listen attribute is deprecated."
                        " Use <" DEVICE_NAME ">.%s->port instead.",
                        servers[Server_TCP].port);
        }
#endif
        conf_object_t *cpu = gdb_any_processor(gdb);
        if (!cpu) {
                SIM_LOG_ERROR(to_obj(gdb), 0, "Not connected to processor.");
                return Sim_Set_Ok;
        }
        conf_object_t *server = SIM_object_descendant(
                obj, servers[Server_TCP].port);
        set_error_t ret = SIM_set_attribute(server, "port", val);
        (void)SIM_clear_exception();

        if (ret == Sim_Set_Ok) {
                attr_value_t attr = SIM_get_attribute(server, "port");
                uint16 port = SIM_attr_integer(attr);
                SIM_LOG_INFO(2, obj, 0,
                             "Awaiting GDB connections on port %d.", port);
                SIM_LOG_INFO(2, obj, 0, "Connect from GDB using: \"target "
                             "remote localhost:%d\"", port);
                SIM_free_attribute(attr);
        }
        if (gdb->architecture)
                setup_architecture(gdb);
        return ret;
}

static set_error_t
set_context_object(conf_object_t *obj, attr_value_t *val)
{
        gdb_remote_t *gdb = gdb_of_obj(obj);
        gdb->context_object = SIM_attr_is_nil(*val) ? NULL : SIM_attr_object(*val);
        if (gdb->context_change_hap_handle >= 0)
                SIM_hap_delete_callback_id("Core_Context_Change",
                                           gdb->context_change_hap_handle);
        if (gdb->context_updated_hap_handle >= 0)
                SIM_hap_delete_callback_id("Core_Context_Updated",
                                           gdb->context_updated_hap_handle);
        gdb->context_change_hap_handle = gdb->context_updated_hap_handle = -1;
        if (gdb->context_object) {
                gdb->context_change_hap_handle = SIM_hap_add_callback_obj(
                        "Core_Context_Change", gdb->context_object, 0,
                        (obj_hap_func_t)context_change, gdb);
                gdb->context_updated_hap_handle = SIM_hap_add_callback_obj(
                        "Core_Context_Updated", gdb->context_object, 0,
                        (obj_hap_func_t)context_updated, gdb);
        }
        context_updated(gdb, gdb->context_object);
        return Sim_Set_Ok;
}

static attr_value_t 
get_context_object(conf_object_t *obj)
{
        gdb_remote_t *gdb = (gdb_remote_t *) obj;
        return SIM_make_attr_object(gdb->context_object);
}

static set_error_t
set_send_target_xml(conf_object_t *obj, attr_value_t *val)
{
        gdb_remote_t *gdb = (gdb_remote_t *) obj;

        if (!SIM_attr_is_boolean(*val))
                return Sim_Set_Illegal_Value;

        gdb->send_target_xml = SIM_attr_boolean(*val);
        return Sim_Set_Ok;
}

static attr_value_t 
get_send_target_xml(conf_object_t *obj)
{
        gdb_remote_t *gdb = (gdb_remote_t *) obj;
        return SIM_make_attr_boolean(gdb->send_target_xml);
}

static set_error_t
set_follow_context(conf_object_t *obj, attr_value_t *val)
{
        gdb_remote_t *gdb = (gdb_remote_t *) obj;

        int64 ival = SIM_attr_integer(*val);
        if (ival != 0 && ival != 1)
                return Sim_Set_Illegal_Value;

        gdb->follow_context = ival;
        return Sim_Set_Ok;
}

static attr_value_t
get_follow_context(conf_object_t *obj)
{
        gdb_remote_t *gdb = (gdb_remote_t *) obj;
        return SIM_make_attr_uint64(gdb->follow_context);
}

static set_error_t
set_inject_serial_command(conf_object_t *obj, attr_value_t *val)
{
        gdb_remote_t *gdb = gdb_of_obj(obj);
        gdb_serial_command(gdb, SIM_attr_string(*val));
        return Sim_Set_Ok;
}

static set_error_t
set_allow_remote_commands(conf_object_t *obj, attr_value_t *val)
{
        gdb_remote_t *gdb = gdb_of_obj(obj);
        gdb->allow_remote_commands = SIM_attr_boolean(*val);
        return Sim_Set_Ok;
}

static attr_value_t
get_allow_remote_commands(conf_object_t *obj)
{
        gdb_remote_t *gdb = gdb_of_obj(obj);
        return SIM_make_attr_boolean(gdb->allow_remote_commands);
}

static attr_value_t
get_use_ipv4(conf_object_t *obj)
{
        return SIM_make_attr_boolean(VT_use_ipv4());
}

static set_error_t
set_use_ipv4(conf_object_t *obj, attr_value_t *val)
{
        // Output deprecation warning on manual access only
#if !defined(SIMICS_4_8_API) && !defined(SIMICS_5_API)
        if (SIM_object_is_configured(obj)
            && !SIM_is_restoring_state(obj))
                SIM_LOG_ERROR(obj, 0,
                           "The <" DEVICE_NAME ">->use_ipv4 attribute"
                           " is deprecated. Use sim->force_ipv4 or"
                           " prefs->force_ipv4 instead.");
#endif
        return SIM_set_attribute(SIM_get_object("sim"), "force_ipv4", val);
}

static conf_object_t *
gdb_remote_alloc_object(conf_class_t *cls)
{
        gdb_remote_t *gdb = MM_ZALLOC(1, gdb_remote_t);
        return to_obj(gdb);
}

/* Construct new instance of gdb-remote class.
   This does not cause any ports to be listened to. */
static void *
gdb_remote_init_object(conf_object_t *obj)
{
        gdb_remote_t *gdb = gdb_of_obj(obj);
        gdb->send_target_xml = 1;
        gdb->cont_thread = gdb->other_thread = -1;
        gdb->context_change_hap_handle = gdb->context_updated_hap_handle = -1;
        gdb->sim_stopped_hap_handle = gdb->continuation_hap_handle = -1;
        gdb->segment_linear_base = 0;
        gdb->allow_remote_commands = true;
        for (int i = 0; i < ALEN(servers); i++) {
                if (servers[i].port) {
                        SIM_set_attribute_default(
                                SIM_object_descendant(obj, servers[i].port),
                                "client", SIM_make_attr_object(obj));
                }
        }
        return obj;
}

void
init_local(void)
{
        strbuf_t desc = sb_new(
                "The <module>gdb-remote</module> module allows a"
                " GDB session to connect to Simics and control the execution."
                " An object of class <class>" DEVICE_NAME "</class> is"
                " used to accept incoming GDB connection requests."
                "\n\n"
                "A GDB binary capable of debugging many Simics target machines"
                " is included in the Simics Base package. If you want to build"
                " your own gdb, read on."
                "\n\n"
                "The following table lists, for each target architectures"
                " supported by <class>" DEVICE_NAME "</class>, the string"
                " to give to <tt>configure</tt> as the <tt>--target</tt>"
                " parameter when building GDB, and any command you may have"
                " to enter at the GDB command prompt before connecting to"
                " Simics:"
                "\n\n");
        sb_addstr(&desc, "<dl>");

        for (int i = 0; gdb_archs[i]; i++) {
                const gdb_arch_t *a = gdb_archs[i];
                if (a->hidden)
                        continue;
                sb_addfmt(&desc, "<dt>%s</dt><dd>", a->name);
                if (a->help.target_flag)
                        sb_addfmt(&desc, "<tt>--target %s</tt><br/>",
                                  a->help.target_flag);
                if (a->help.prompt_cmd)
                        sb_addfmt(&desc, "command: <tt>%s</tt>",
                                  a->help.prompt_cmd);
                sb_addstr(&desc, "</dd>");
        }
        sb_addstr(&desc, "</dl>");
        sb_addstr(
                &desc, "\n\n"
                "Note that these <tt>--target</tt> flags are not the only"
                " ones that will work, just examples of ones that do work.");

        const class_info_t class_data = {
                .alloc = gdb_remote_alloc_object,
                .init = gdb_remote_init_object,
                .description = sb_str(&desc),
                .short_desc = "gdb remote debugger",
                .kind = Sim_Class_Kind_Pseudo
        };

        conf_class_t *gdb_remote_class = SIM_create_class("gdb-remote",
                                                          &class_data);

        for (int i = 0; i < ALEN(servers); i++) {
                if (servers[i].port) {
                        SIM_register_port(gdb_remote_class, servers[i].port,
                                          SIM_get_class(servers[i].class),
                                          servers[i].desc);
                }
        }

        SIM_register_attribute(
                gdb_remote_class, "use_ipv4",
                get_use_ipv4,
                set_use_ipv4,
                Sim_Attr_Pseudo,
                "b",
                "Determines if connections should be restricted to IPv4."
                " Default is FALSE");

        SIM_register_attribute(
                gdb_remote_class, "listen",
                get_listen, set_listen,
                Sim_Attr_Pseudo | Sim_Init_Phase_1,
                "i",
                "Set to start listening for incoming GDB connections on the"
                " specified port. If 0 is specified, an arbitrary available"
                " port will be used. Read to get the port currently listened"
                " on, or 0 if none.");
        SIM_register_attribute(
                gdb_remote_class, "processor",
                get_processor, set_processor,
                Sim_Attr_Pseudo,
                "o|n", "Processor to connect the GDB stub to.");
        SIM_register_attribute(
                gdb_remote_class, "architecture",
                get_architecture, set_architecture,
                Sim_Attr_Pseudo,
                "s", "Architecture of target.");
        SIM_register_attribute(
                gdb_remote_class, "extender",
                get_extender, set_extender,
                Sim_Attr_Pseudo | Sim_Attr_Internal,
                "o|n", "Experimental protocol extender object.");
        SIM_register_attribute(
                gdb_remote_class, "disconnect",
                0, set_disconnect,
                Sim_Attr_Pseudo,
                "b", "Disconnects the remote GDB");
        SIM_register_attribute(
                gdb_remote_class, "connected",
                get_connected, 0,
                Sim_Attr_Pseudo, "b",
                "Returns true if the gdb-remote object is connected to a"
                " GDB session, false if not.");
        SIM_register_attribute(
                gdb_remote_class, "signal",
                0, set_signal,
                Sim_Attr_Pseudo,
                "i",
                "Sends a signal to the remote GDB. This makes GDB think the"
                " program it is debugging has received a signal."
                " See the <tt>signal(7)</tt> man page for a list of"
                " signal numbers.");
        SIM_register_attribute(
                gdb_remote_class, "send_packet",
                0, set_send_packet, Sim_Attr_Pseudo, "s",
                "Sends a raw packet from gdb-remote to GDB. The string that"
                " this attribute is written with will be sent as a packet to"
                " GDB.");
        SIM_register_attribute(
                gdb_remote_class, "large_operations",
                get_large_operations,
                set_large_operations,
                Sim_Attr_Optional,
                "i",
                "Set to non-zero if memory operations received from GDB"
                " should be performed as single operations instead of"
                " bytewise");
        SIM_register_attribute(
                gdb_remote_class, "follow_context",
                get_follow_context,
                set_follow_context,
                Sim_Attr_Pseudo, "i",
                "Set to non-zero if context should be followed.");
        SIM_register_attribute(
                gdb_remote_class, "context_object",
                get_context_object,
                set_context_object,
                Sim_Attr_Optional,
                "o|n",
                "Context object that this GDB session is attached to.");
        SIM_register_attribute(
                gdb_remote_class, "send_target_xml",
                get_send_target_xml,
                set_send_target_xml,
                Sim_Attr_Optional,
                "b",
                "Should an XML target description be sent to GDB, "
                "default is true, but can be disabled since it can confuse "
                "some clients (e.g. Eclipse on a Linux host).");
        SIM_register_attribute(
                gdb_remote_class, "inject_serial_command",
                0, set_inject_serial_command,
                Sim_Attr_Pseudo | Sim_Attr_Internal, "s",
                "Inject a GDB serial command as if the remote gdb"
                " process had sent it.");

        SIM_register_attribute(
                gdb_remote_class, "allow_remote_commands",
                get_allow_remote_commands,
                set_allow_remote_commands,
                Sim_Attr_Pseudo | Sim_Attr_Internal, "b",
                "When set to true, allow qRcmd command which allows any Simics"
                " commands to be executed from remote connection. This will"
                " allow a gdb remote client to do anything that can be done"
                " from Simics CLI.");

        step_event = SIM_register_event(
            "singlestep breakpoint", gdb_remote_class, Sim_EC_Notsaved,
            gdb_step_handler, 0, 0, 0, 0);

        static const external_connection_events_interface_t ext_iface = {
                .on_accept = external_connection_events_on_accept,
                .on_input = external_connection_events_on_input,
        };
        SIM_REGISTER_INTERFACE(gdb_remote_class,
                               external_connection_events, &ext_iface);

        init_gdb_recording(gdb_remote_class);
}

bool
read_opt_attr(conf_object_t *log_obj, conf_object_t *obj, const char *attr_name,
              attr_value_t * const attr)
{
        if (!SIM_class_has_attribute(SIM_object_class(obj), attr_name))
                return false;

        attr_value_t local_attr = SIM_get_attribute(obj, attr_name);
        if (SIM_clear_exception()) {
                SIM_LOG_ERROR(log_obj, 0, "Error '%s' when reading attribute"
                              " '%s' from object '%s'.", SIM_last_error(),
                              attr_name, SIM_object_name(obj));
                SIM_attr_free(&local_attr);
                return false;
        }
        *attr = local_attr;
        return true;
}
