/*
  gdb-remote.c - Remote GDB connectivity via TCP/IP

  This Software is part of Wind River Simics. The rights to copy, distribute,
  modify, or otherwise make use of this Software may be licensed only
  pursuant to the terms of an applicable Wind River license agreement.
  
  Copyright 2010-2017 Intel Corporation

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>

#ifdef _WIN32
 #include <winsock2.h>
 #include <windows.h>
 #include <ws2tcpip.h>
#else
 #include <unistd.h>
 #include <sys/time.h>
 #include <sys/types.h>
 #include <sys/socket.h>
 #include <sys/stat.h>
 #include <netinet/in.h>
 #include <netinet/tcp.h>
 #include <sys/un.h>
 #include <arpa/inet.h>
 #include <netdb.h>
#endif

#include <simics/simulator-api.h>
#include <simics/util/os.h>
#include <simics/arch/sparc.h>
#include <simics/model-iface/int-register.h>
#include <simics/simulator-iface/context-tracker.h>
#include <simics/arch/x86.h>

#include "gdb-remote.h"
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

static struct gdb_breakpoint *breakpoint_get(gdb_remote_t *gdb, int bp_number);

/*
 * This is weird; we send data bytewise, least significant byte first
 * (most significant first in each byte), but we receive nibblewise,
 * most significant first
 */

#define GDB_IO_HEX(bits)                                                 \
void                                                                     \
gdb_print_hex ## bits ## _le(char *p, uint ## bits value)                \
{                                                                        \
        for (int i = 0; i < sizeof value; ++i) {                         \
                *p++ = hexchar[(value >> 4) & 0xf];                      \
                *p++ = hexchar[value & 0xf];                             \
                value >>= 4;                                             \
                value >>= 4;                                             \
        }                                                                \
}                                                                        \
                                                                         \
void                                                                     \
gdb_print_hex ## bits ## _be(char *p, uint ## bits value)                \
{                                                                        \
        for (int i = 0; i < sizeof value; ++i) {                         \
                *p++ = hexchar[(value >> (sizeof value * 8 - 4)) & 0xf]; \
                *p++ = hexchar[(value >> (sizeof value * 8 - 8)) & 0xf]; \
                value <<= 4;                                             \
                value <<= 4;                                             \
        }                                                                \
}                                                                        \
                                                                         \
static uint ## bits                                                      \
gdb_read_hex ## bits ## _le(const char *_p)                              \
{                                                                        \
        const unsigned char *p = (const unsigned char *)_p;              \
        uint ## bits res = 0;                                            \
        for (int i = 0; i < sizeof res; ++i, p += 2) {                   \
                uint ## bits v = (HEXVAL(*p) << 4) | HEXVAL(*(p + 1));   \
                v <<= sizeof res * 8 - 8;                                \
                res = (res >> 8) | v;                                    \
        }                                                                \
        return res;                                                      \
}                                                                        \
                                                                         \
static uint ## bits                                                      \
gdb_read_hex ## bits ## _be(const char *_p)                              \
{                                                                        \
        const unsigned char *p = (const unsigned char *)_p;              \
        uint ## bits res = 0;                                            \
        for (int i = 0; i < sizeof res; ++i, p += 2) {                   \
                uint8 v = (HEXVAL(*p) << 4) | HEXVAL(*(p + 1));          \
                res = (res << 8) | v;                                    \
        }                                                                \
        return res;                                                      \
}

GDB_IO_HEX(8)
GDB_IO_HEX(16)
GDB_IO_HEX(32)
GDB_IO_HEX(64)

static uint64
gdb_read_hex(const char **buf, bool is_be, int bits)
{
        uint64 v;
        if (is_be) {
                switch (bits) {
                case 8: v = gdb_read_hex8_be(*buf); break;
                case 16: v = gdb_read_hex16_be(*buf); break;
                case 32: v = gdb_read_hex32_be(*buf); break;
                case 64: v = gdb_read_hex64_be(*buf); break;
                default: ASSERT(0);  return 0;
                }
        } else {
                switch (bits) {
                case 8: v = gdb_read_hex8_le(*buf); break;
                case 16: v = gdb_read_hex16_le(*buf); break;
                case 32: v = gdb_read_hex32_le(*buf); break;
                case 64: v = gdb_read_hex64_le(*buf); break;
                default: ASSERT(0); return 0;
                }
        }
        *buf += bits/4;
        return v;
}

static void
gdb_write_hex(strbuf_t *buf, uint64 val, bool is_be, int bits)
{
        char b[17];
        memset(b, 0, sizeof(b));
        if (is_be) {
                switch (bits) {
                case 8: gdb_print_hex8_be(b, val); break;
                case 16: gdb_print_hex16_be(b, val); break;
                case 32: gdb_print_hex32_be(b, val); break;
                case 64: gdb_print_hex64_be(b, val); break;
                default: ASSERT(0); break;
                }
        } else {
                switch (bits) {
                case 8: gdb_print_hex8_le(b, val); break;
                case 16: gdb_print_hex16_le(b, val); break;
                case 32: gdb_print_hex32_le(b, val); break;
                case 64: gdb_print_hex64_le(b, val); break;
                default: ASSERT(0); break;
                }
        }
        sb_addstr(buf, b);
}

static int64
hexstrtol(const char *adr, char **endp)
{
        /* this is not entirely correct; an invalid string that starts
           with "0x" will incorrectly be accepted. */
        return strtoll(adr, endp, 16);
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
        attr_value_t cpus = default_processor_list(&gdb->obj);
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
get_context_attr(gdb_remote_t *gdb, conf_object_t *cpu)
{
        conf_object_t *ctx =
                context_handler_iface(cpu)->get_current_context(cpu);
        if (ctx) {
                return ctx;
        } else {
                SIM_LOG_ERROR(&gdb->obj, 0,
                              "reading the current-context attribute"
                              " of %s: %s",
                              SIM_object_name(cpu),
                              SIM_clear_exception()
                              ? SIM_last_error()
                              : "is not a conf object");
                return NULL;
        }
}

static conf_object_t *
gdb_context_object(gdb_remote_t *gdb)
{
        if (gdb->context_object)
                return gdb->context_object;
        else if (gdb->processor)
                return get_context_attr(gdb, gdb->processor);
        else
                return NULL;
}

/* Return the processor where the given thread is currently active, or NULL if
   it isn't active on any processor right now. */
static conf_object_t *
find_cpu_for_active_thread(gdb_remote_t *gdb, int64 thread)
{
        conf_object_t **cpus = gdb_all_processors(gdb);
        conf_object_t *result = NULL;
        for (int i = 0; cpus[i]; i++) {
                if (get_context_attr(gdb, cpus[i]) == gdb_context_object(gdb)
                    && is_current_thread(gdb, thread, cpus[i])) {
                        result = cpus[i];
                        break;
                }
        }
        MM_FREE(cpus);
        return result;
}

/* Call SIM_current_processor(), hiding any Simics exception triggered by the
   call. */
static conf_object_t *
simics_current_processor(void)
{
        conf_object_t *cpu = SIM_current_processor();
        return SIM_clear_exception() == SimExc_No_Exception ? cpu : NULL;
}

/* Find an arbitrary processor that is executing in a context we are interested
   in. If SIM_current_processor() is in the set of such processors, prefer it. */
static conf_object_t *
gdb_current_processor(gdb_remote_t *gdb)
{
        conf_object_t *result = NULL;
        conf_object_t **cpus = gdb_all_processors(gdb);
        conf_object_t *scp = simics_current_processor();

  again:
        for (int i = 0; cpus[i]; i++) {
                if (get_context_attr(gdb, cpus[i]) == gdb_context_object(gdb)
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
        SIM_LOG_INFO(3, &gdb->obj, 0, "do_signal(sig = %d), is running %d",
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
                        SIM_LOG_INFO(3, &gdb->obj, 0,
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
                SIM_LOG_ERROR(&gdb->obj, 0,
                              "Badly formatted memory address/length/data: %s",
                              adr);
                send_error(gdb, EINVAL);
                return;
        }
        la += gdb->segment_linear_base;

        len = hexstrtoull(endp + 1, &endp, gdb->arch->bit_extend);
        if (*endp != ':') {
                SIM_LOG_ERROR(&gdb->obj, 0,
                              "Badly formatted memory address/length/data: %s",
                              adr);
                send_error(gdb, EINVAL);
                return;
        }

        if (!cpu) {
                SIM_LOG_INFO(3, &gdb->obj, 0,
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
                                SIM_LOG_ERROR(&gdb->obj, 0,
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
                                &gdb->obj, 0,
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
                                &gdb->obj, 0,
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
                        SIM_LOG_ERROR(&gdb->obj, 0,
                                      "Failed writing memory to la: "
                                      "%#llx  pa: %#llx", la, pa);
                        send_error(gdb, EACCES);
                        return;
                }

                endp += 2;
        }

        if (*endp) {
                SIM_LOG_ERROR(&gdb->obj, 0,
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
                SIM_LOG_ERROR(&gdb->obj, 0,
                              "Badly formatted memory address/length: %s",
                              adr);
                send_error(gdb, EINVAL);
                return;
        }
        la += gdb->segment_linear_base;

        len = hexstrtoull(endp + 1, &endp, gdb->arch->bit_extend);
        if (*endp) {
                SIM_LOG_ERROR(&gdb->obj, 0,
                              "Badly formatted memory address/length: %s",
                              adr);
                send_error(gdb, EINVAL);
                return;
        }

        char buf[len * 2 + 1];
        char *p = buf;
        if (!cpu) {
                SIM_LOG_INFO(3, &gdb->obj, 0,
                             "Cannot read memory, because process is"
                             " not active");
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
                                SIM_LOG_INFO(1, &gdb->obj, 0,
                                             "Failed reading from la: %#llx"
                                             " pa: %#llx len: %lld",
                                             la, pa, len);
                                goto done;
                        }
                }

                /* Since the gdb remote protocol is seriously weird,
                 * it reads data in target byte order, but writes in
                 * big-endian. */
                if (gdb->arch->is_be) {
                        for (int i = len-1; i >= 0; i--) {
                                gdb_print_hex8_le(p, value >> (i*8) & 0xff);
                                p += 2;
                        }
                } else {
                        for (int i = 0; i < len; i++) {
                                gdb_print_hex8_le(p, value >> (i*8) & 0xff);
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
                                SIM_LOG_INFO(1, &gdb->obj, 0,
                                             "Failed reading from la:"
                                             " %#llx  pa: %#llx",
                                             la, pa);
                                break;
                        }
                }
                gdb_print_hex8_le(p, value);
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
        SIM_LOG_INFO(3, &gdb->obj, 0, "breaking simulation");
        if (gdb->is_running && !gdb->stop_in_progress) {
                SIM_LOG_INFO(3, &gdb->obj, 0, "setting stop in progress");
                deactivate_gdb_notifier(gdb);
                gdb->stop_in_progress = true;
        }
}

/*
 * For some targets gdb adjusts pc after hitting the breakpoint to compensate
 * for target breakpoint implementations which insert breakpoint instructions
 * and stops after the instruction which caused the breakpoint.
 * In Simics breakpoints takes place before the instruction to break on.
 * Here we adjust pc to counteract gdb's later adjustment if needed.
 */
static void
counteract_decr_pc_after_break(gdb_remote_t *gdb, conf_object_t *cpu)
{
        if (gdb->arch->decr_pc_after_break)
                processor_iface(cpu)->set_program_counter(
                        cpu, (processor_iface(cpu)->get_program_counter(cpu)
                              + gdb->arch->decr_pc_after_break));
}

static void
ordered_breakpoint_handler(conf_object_t *obj, int64 bp_number, void *data)
{
        gdb_remote_t *gdb = (gdb_remote_t *)obj;
        generic_transaction_t *memop = (generic_transaction_t *)data;

        SIM_LOG_INFO(3, &gdb->obj, 0, "inside breakpoint handler %d",
                     (int)bp_number);

        VT_stop_message(&gdb->obj, "Hit breakpoint set by remote gdb");
        stop_simulation(gdb);

        gdb->bp = breakpoint_get(gdb, (int)bp_number);
        if (gdb->bp)
                gdb->access_address = memop->logical_address;

        counteract_decr_pc_after_break(gdb, gdb_cont(gdb).cpu);

        if (VT_is_reversing()) {
                return;
        }

        if (gdb->step_handler_cpu)
                SIM_event_cancel_step(gdb->step_handler_cpu, step_event,
                                      &gdb->obj, 0, NULL);

        SIM_register_work(send_sigtrap, gdb);
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
                        &gdb->obj, 0,
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
                                       SIM_step_count(SIM_current_processor());
                                if (count)
                                        VT_rewind(SIM_current_processor(),
                                                  count - 1);
                        }

                        do_signal(gdb, Sig_trap);
                }
        } else {
                SIM_continue(0);
                exception_type_t ex = SIM_clear_exception();
                if (ex != SimExc_No_Exception && ex != SimExc_Break) {
                        SIM_LOG_ERROR(
                                &gdb->obj, 0,
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
        /* Always follow context if the user explicitly asked for it. */
        if (gdb->follow_context)
                return true;

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
        SIM_LOG_INFO(3, &gdb->obj, 0, "gdb_step_handler()");

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
                                      &gdb->obj, 0, NULL);
        gdb->step_handler_cpu = cpu;
        SIM_event_post_step(gdb->step_handler_cpu, step_event,
                            &gdb->obj, 1, gdb);
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
                                SIM_step_count(SIM_current_processor());
                        if (count)
                                VT_rewind(SIM_current_processor(), count - 1);
                }

                do_signal(gdb, Sig_trap);
        }
}

static void
do_reverse(gdb_remote_t *gdb)
{
        SIM_register_work(post_reverse2, gdb);
}

static struct gdb_breakpoint *
breakpoint_get(gdb_remote_t *gdb, int bp_number)
{
        int i;

        for (i = 0; i < gdb->breakpoints.used; ++i) {
                struct gdb_breakpoint *bp = gdb->breakpoints.entries + i;

                if (bp->bp_id == bp_number)
                        return bp;
        }

        return NULL;
}

static int
breakpoint_lookup(gdb_remote_t *gdb, logical_address_t la,
                  logical_address_t len, enum gdb_breakpoint_type type)
{
        for (int i = 0; i < gdb->breakpoints.used; ++i) {
                struct gdb_breakpoint *bp = gdb->breakpoints.entries + i;

                if (bp->la == la && bp->len == len && bp->type == type)
                        return i;
        }

        return -1;
}

static void
do_handle_breakpoint(gdb_remote_t *gdb, const char *args, bool shall_set)
{
        enum gdb_breakpoint_type gdb_type;
        access_t              sim_type = 0;
        logical_address_t     la, len;
        breakpoint_id_t       bp_id;
        hap_handle_t          hap_id;
        int                   bp_idx;
        const char           *endp;

        if (args[0] < '0' || args[0] > '0' + Gdb_Bp_Access || args[1] != ',')
                goto syntax_error;

        gdb_type = args[0] - '0';

        la = hexstrtoull(args + 2, &endp, gdb->arch->bit_extend);
        if (endp[0] != ',' || endp[1] == 0)
                goto syntax_error;

        /* Add an offset which was set by the custom 'segment' command. */
        la += gdb->segment_linear_base;

        len = hexstrtoull(endp + 1, &endp, false);
        if (endp[0])
                goto syntax_error;

        switch (gdb_type) {
        case Gdb_Bp_Software:
                sim_type = Sim_Access_Execute;
                break;
        case Gdb_Bp_Hardware:
                sim_type = Sim_Access_Execute;
                break;
        case Gdb_Bp_Write:
                sim_type = Sim_Access_Write;
                break;
        case Gdb_Bp_Read:
                sim_type = Sim_Access_Read;
                break;
        case Gdb_Bp_Access:
                sim_type = Sim_Access_Read | Sim_Access_Write;
                break;
        default:
                ASSERT(0);
        }

        bp_idx = breakpoint_lookup(gdb, la, len, gdb_type);

        struct gdb_breakpoints *b = &gdb->breakpoints;
        if (shall_set) {
                if (bp_idx >= 0) {
                        SIM_LOG_INFO(3, &gdb->obj, 0,
                                     "Setting identical breakpoint");
                        ++b->entries[bp_idx].count;
                        send_ok(gdb);
                        return;
                }

                bp_id = SIM_breakpoint(gdb_context_object(gdb), Sim_Break_Virtual,
                                       sim_type, la, len,
                                       Sim_Breakpoint_Simulation);
                if (SIM_clear_exception()) {
                        SIM_LOG_ERROR(&gdb->obj, 0,
                                      "Failed setting breakpoint: %s",
                                      SIM_last_error());
                        send_error(gdb, EINVAL);
                        return;
                }

                SIM_LOG_INFO(3, &gdb->obj, 0, "Set breakpoint id %d at %#llx",
                             bp_id, la);

                if (b->used >= b->size) {
                        b->size = b->size ? b->size * 2 : 16;
                        b->entries = MM_REALLOC(b->entries, b->size,
                                                struct gdb_breakpoint);
                }

                hap_id = SIM_hap_add_callback_index(
                        "Core_Breakpoint_Memop",
                        (obj_hap_func_t)gdb_breakpoint_handler,
                        gdb, bp_id);
                b->entries[b->used].la = la;
                b->entries[b->used].len = len;
                b->entries[b->used].type = gdb_type;
                b->entries[b->used].bp_id = bp_id;
                b->entries[b->used].hap_id = hap_id;
                b->entries[b->used].count = 1;
                b->used++;

        } else {
                if (bp_idx < 0) {
                        SIM_LOG_ERROR(&gdb->obj, 0,
                                      "Could not find breakpoint to remove");
                        send_error(gdb, EINVAL);
                        return;
                }

                if (--b->entries[bp_idx].count) {
                        SIM_LOG_INFO(3, &gdb->obj, 0,
                                     "removing multibreakpoint");
                        send_ok(gdb);
                        return;
                }

                SIM_delete_breakpoint(b->entries[bp_idx].bp_id);
                SIM_hap_delete_callback_id("Core_Breakpoint_Memop",
                                           b->entries[bp_idx].hap_id);

                if (--b->used > 0) {
                        b->entries[bp_idx] = b->entries[b->used];
                }
        }


        send_ok(gdb);
        return;

 syntax_error:
        SIM_LOG_ERROR(&gdb->obj, 0,
                      "Badly formatted breakpoint: \"%s\"", args);
        send_error(gdb, EINVAL);
}

static void
gdb_simulation_stopped_hap(void *_gdb, conf_object_t *obj)
{
        gdb_remote_t *gdb = (gdb_remote_t *)_gdb;

        SIM_LOG_INFO(3, &gdb->obj, 0,
                     "Core_Simulation_Stopped hap; running %d",
                     gdb->is_running);

        gdb->is_running = false;

        if (gdb->stop_in_progress) {
                /* re-enable requests from gdb now that we have stopped */
                SIM_LOG_INFO(3, &gdb->obj, 0, "clearing stop in progress");
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

        SIM_LOG_INFO(3, &gdb->obj, 0,
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
                        1, &gdb->obj, 0,
                        "vCont: step or continue with signal: \"%s\"."
                        " Ignoring the signal part.",
                        buffer);
        }
        char action = tolower(rest[0]);
        rest++;
        if (action == 'c') {
                if (*c_found) {
                        SIM_LOG_UNIMPLEMENTED(
                                1, &gdb->obj, 0,
                                "vCont packet with multiple continue actions,"
                                " ignoring all but the first action: \"%s\"",
                                buffer);
                }
                *c_found = true;
        } else if (action == 's') {
                if (*s_found) {
                        SIM_LOG_UNIMPLEMENTED(
                                1, &gdb->obj, 0,
                                "vCont packet with multiple step actions,"
                                " ignoring all but the last action: \"%s\"",
                                buffer);
                }
                *s_found = true;
        } else {
                return NULL;
        }
        *(*c_found ? c_thread : s_thread)
                = (rest[0] == ':' ? hexstrtoull(rest + 1, &rest, true) : -1);
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
                        SIM_LOG_ERROR(&gdb->obj, 0,
                                      "Malformed vCont packet \"%s\", ignoring",
                                      buffer);
                        return;
                }
        }

        if (s_found) {
                //gdb->cont_thread = s_thread;
                gdb->cont_thread = 0;
                conf_object_t *cpu = find_cpu_for_active_thread(
                        gdb, gdb->cont_thread);
                if (cpu) {
                        do_step(gdb, cpu);
                } else {
                        gdb->on_thread_change = OTC_Single_Step;
                        post_continue(gdb);
                }
        } else if (c_found) {
                gdb->cont_thread = c_thread;
                post_continue(gdb);
        } else {
                SIM_LOG_ERROR(&gdb->obj, 0,
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
                SIM_LOG_UNIMPLEMENTED(1, &gdb->obj, 0,
                                      "verbose packet: [%s]\n",
                                      buffer);
        }
}

void
gdb_disconnect(gdb_remote_t *gdb)
{
        if (gdb->fd != OS_INVALID_SOCKET) {
                deactivate_gdb_notifier(gdb);
                os_socket_close(gdb->fd);
                gdb->fd = -1;
        }

        if (gdb->sim_stopped_hap_handle >= 0)
                SIM_hap_delete_callback_id("Core_Simulation_Stopped",
                                           gdb->sim_stopped_hap_handle);
        if (gdb->continuation_hap_handle >= 0)
                SIM_hap_delete_callback_id("Core_Continuation",
                                           gdb->continuation_hap_handle);

        for (int i = 0; i < gdb->breakpoints.used; ++i) {
                SIM_delete_breakpoint(gdb->breakpoints.entries[i].bp_id);
                SIM_hap_delete_callback_id("Core_Breakpoint_Memop",
                                        gdb->breakpoints.entries[i].hap_id);
        }

        gdb->breakpoints.used = 0;

        SIM_LOG_INFO(2, &gdb->obj, 0, "Disconnected");
        gdb->fd = OS_INVALID_SOCKET;
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

        send_packet(gdb, buf);
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

static const char *
gdb_arch_name(gdb_remote_t *gdb)
{
        attr_value_t attr;
        if (target_is_ppc64(gdb)) {
                 attr = SIM_get_attribute(gdb_any_processor(gdb),
                                          "gdb_remote_architecture_64");
        } else {
                attr = SIM_get_attribute(gdb_any_processor(gdb),
                                         "gdb_remote_architecture");
        }
        SIM_clear_exception();
        if (SIM_attr_is_string(attr)) {
                const char *ret = SIM_attr_string(attr);
                SIM_LOG_INFO(3, &gdb->obj, 0, "arch name is %s", ret);
                return ret;

        } else if (gdb->send_target_xml) {
                SIM_LOG_INFO(3, &gdb->obj, 0, "arch name is %s",
                             gdb->arch->arch_name );
                return gdb->arch->arch_name;
        }
        SIM_LOG_INFO(3, &gdb->obj, 0, "arch name is NULL");
        return NULL;
}

static char *
target_xml(gdb_remote_t *gdb)
{
        const char *arch_name = gdb_arch_name(gdb);
        if (arch_name == NULL)
                return NULL;

        strbuf_t desc = sb_newf(
                "<target version=\"1.0\">\n"
                "  <architecture>%s</architecture>\n", arch_name);

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
        attr_value_t attr = SIM_get_attribute(cpu, "gdb_remote_registers");
        if (SIM_attr_is_invalid(attr)) {
                SIM_clear_exception();
                goto end;
        }
        if (DBG_check_typing_system("[[s[[siisb]*]]*]", &attr) != Sim_Set_Ok) {
                SIM_LOG_ERROR(&gdb->obj, 0, "bad gdb_remote_registers value");
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
                SIM_LOG_UNIMPLEMENTED(1, &gdb->obj, 0,
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
        SIM_LOG_ERROR(&gdb->obj, 0, "malformed offset,length specification"
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
                SIM_LOG_UNIMPLEMENTED(1, &gdb->obj, 0,
                                      "qXfer query \"%s\"",
                                      cmd);
                send_unsupported(gdb);
        }
        free_vect_str(strings);
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
                        3, &gdb->obj, 0,
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
                SIM_LOG_ERROR(&gdb->obj, 0, "Too short qP packet");
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
        SIM_LOG_INFO(2, &gdb->obj, 0, "Skipping to bookmark %s", bookmark);

        strbuf_t cmd = sb_newf("skip-to %s", bookmark);
        SIM_run_command(sb_str(&cmd));
        sb_free(&cmd);

        if (SIM_clear_exception()) {
                SIM_LOG_ERROR(&gdb->obj, 0,
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

        if (SIM_attr_is_string(ret)) {
                strbuf_t buf = sb_newf("QB%s", SIM_attr_string(ret));
                send_packet(gdb, sb_str(&buf));
                sb_free(&buf);
        } else {
                SIM_clear_exception();
                SIM_LOG_ERROR(&gdb->obj, 0, "Failed creating bookmark %s",
                              SIM_last_error());
                send_error(gdb, EINVAL);
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

        SIM_LOG_UNIMPLEMENTED(1, &gdb->obj, 0,
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
                SIM_LOG_ERROR(&gdb->obj, 0, "Malformed p packet: \"%s\"",
                              buffer + 1);
                send_error(gdb, EINVAL);
                return;
        }

        reg_desc_vect_t *rds = VLEN(gdb->register_descriptions) > 0
                ? &gdb->register_descriptions
                : &gdb->default_register_descriptions;
        // HACK
        if (idx >= VLEN(*rds)) {
            idx = VLEN(*rds)-1;
        }
        //if (idx >= VLEN(*rds)) {
        //        SIM_LOG_INFO(2, &gdb->obj, 0,
        //                     "Bad index in single-register read: %zu"
        //                     " (there are only %d registers)",
        //                     idx, VLEN(*rds));

         //       /* GDB seems to think we have more registers than we think we
         //          have, and will ask for them with a 'p' query. Returning
         //          unsupported seems to be the right thing to do here,
         //          according to the gdb-serial protocol reference. */
         //       send_unsupported(gdb);
         //       return;
       // }

        cpu_thread_t ct = gdb_other(gdb);
        if (!ct.cpu)
                SIM_LOG_INFO(3, &gdb->obj, 0,
                             "Reading register: Thread %lld not active,"
                             " pretending all registers are zero", ct.thread);

        register_description_t *rd = &VGET(*rds, idx);
        uint64 val = ct.cpu ? rd->read(ct.cpu, rd) : 0;
        SIM_LOG_INFO(3, &gdb->obj, 0,
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
                SIM_LOG_INFO(1, &gdb->obj, 0,
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
        if (idx >= VLEN(*rds)) {
                sb_fmt(&err, "Illegal register ID (%llu) in P packet", idx);
                goto error;
        }

        register_description_t *rd = &VGET(*rds, idx);
        const char *val_str = VGET(idx_val, 1);
        uint64 val = gdb_read_hex(&val_str, gdb->arch->is_be, rd->size);
        if (*val_str != '\0') {
                sb_set(&err, "Malformed register value in P packet");
                goto error;
        }

        bool success = rd->write(ct.cpu, rd, val);
        if (success) {
                SIM_LOG_INFO(3, &gdb->obj, 0,
                             "Writing 0x%llx to register %s", val, rd->name);
                send_ok(gdb);
        } else {
                SIM_LOG_INFO(1, &gdb->obj, 0,
                             "Failed writing 0x%llx to register %s", val,
                             rd->name);
                send_error(gdb, EACCES);
        }

  error:
        if (sb_len(&err)) {
                SIM_LOG_ERROR(&gdb->obj, 0, "%s: %s", sb_str(&err), buffer);
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
                SIM_LOG_INFO(3, &gdb->obj, 0,
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
                SIM_LOG_INFO(3, &gdb->obj, 0,
                             "Writing registers: Thread %lld not active,"
                             " ignoring write", ct.thread);
                return;
        }

        reg_desc_vect_t *rds = VLEN(gdb->register_descriptions) > 0
                ? &gdb->register_descriptions
                : &gdb->default_register_descriptions;
        VFOREACH_T(*rds, register_description_t, rd) {
                uint64 val = gdb_read_hex(&buf, gdb->arch->is_be, rd->size);
                rd->write(ct.cpu, rd, val);
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
                        &gdb->obj, 0,
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
                SIM_LOG_INFO(1, &gdb->obj, 0,
                             "Badly formatted segment command");
                send_error(gdb, EINVAL);
        } else {
                gdb->segment_linear_base = new_segm;
                SIM_LOG_INFO(3, &gdb->obj, 0, "Segment updated to 0x%x",
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
                SIM_LOG_INFO(4, &gdb->obj, 0, "got message: \"^C\"");
        else
                SIM_LOG_INFO(4, &gdb->obj, 0, "got message: \"%s\"", cmd);

        switch (ch) {
        case 3:
                handle_ctrl_c(gdb);
                break;

        case '!':       /* extended ops */
                SIM_LOG_INFO(3, &gdb->obj, 0, "! = Extended ops");
                break;

        case '?': {      /* last signal */
                SIM_LOG_INFO(3, &gdb->obj, 0, "? = last signal");
                strbuf_t buf = SB_INIT;
                stop_reply_packet(gdb, &buf, Sig_trap);
                send_packet(gdb, sb_str(&buf));
                sb_free(&buf);
                break;
        }

        case 'D':       /* detach */
                SIM_LOG_INFO(3, &gdb->obj, 0, "D = detach");
                send_packet(gdb, "OK");
                gdb_disconnect(gdb);
                break;

        case 'H':       /* set thread */
                switch (cmd[1])
                {
                case 'g':
                        SIM_LOG_INFO(3, &gdb->obj, 0,
                                     "Hg = last signal, thread used in"
                                     " other operations");
                        gdb->other_thread =
                                hexstrtol(cmd + 2, NULL);
                        send_ok(gdb);
                        break;
                case 'c':
                        SIM_LOG_INFO(3, &gdb->obj, 0,
                                     "Hc = last signal, thread used in"
                                     " step/continue");
                        gdb->cont_thread = hexstrtol(cmd + 2, NULL);
                        send_ok(gdb);
                        break;
                default:
                        SIM_printf("H%c = last signal, not defined\n",
                                   cmd[1]);
                        break;
                }
                break;

        case 'g': {     /* read registers */
                SIM_LOG_INFO(3, &gdb->obj, 0,
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
                SIM_LOG_INFO(3, &gdb->obj, 0,
                             "G = write regs"
                             " (current thread = %lld",
                             gdb_other(gdb).thread);
                write_registers(gdb, cmd + 1);
                send_ok(gdb);
                break;

        case 'm':       /* read mem */
                SIM_LOG_INFO(3, &gdb->obj, 0, "m = read mem");
                send_memory(gdb, cmd + 1);
                break;

        case 'M':       /* write mem */
                SIM_LOG_INFO(3, &gdb->obj, 0, "M = write mem");
                write_memory(gdb, cmd + 1);
                break;

        case 'C':       /* continue with signal */
                SIM_LOG_UNIMPLEMENTED(1, &gdb->obj, 0,
                                      "C = continue with signal");
                unhandled_command(gdb, cmd);
                break;

        case 'S':       /* step with signal */
                SIM_LOG_UNIMPLEMENTED(1, &gdb->obj, 0,
                                      "S = step with signal");
                unhandled_command(gdb, cmd);
                break;

        case 'b':
                if (cmd[1] == 's') {
                        SIM_LOG_INFO(3, &gdb->obj, 0,
                                     "a = reverse step");
                        do_reverse (gdb);
                        break;
                } else if (cmd[1] == 'c') {
                        /* Backwards continue */
                        gdb->next_reverse_direction = true;
                        post_continue(gdb);
                        break;
                } else {
                        SIM_LOG_UNIMPLEMENTED(1, &gdb->obj, 0,
                                              "unsupported backwards "
                                              "continue arg");
                        unhandled_command(gdb, cmd);
                        break;
                }

        case 'c':       /* continue */
                SIM_LOG_INFO(3, &gdb->obj, 0, "c = continue");
                if (cmd[1]) {
                        /* can't continue with address */
                        SIM_LOG_UNIMPLEMENTED(1, &gdb->obj, 0,
                                              "unsupported continue "
                                              "arg");
                        unhandled_command(gdb, cmd);
                        break;
                }

                SIM_LOG_INFO(3, &gdb->obj, 0, "Continue");
                post_continue(gdb);
                break;

        case 's':       /* step */
                SIM_LOG_INFO(3, &gdb->obj, 0, "s = step");
                if (cmd[1]) {
                        SIM_LOG_UNIMPLEMENTED(1, &gdb->obj, 0,
                                              "unsupported step arg");
                        unhandled_command(gdb, cmd);
                        break;
                }
                handle_vcont(gdb, ";s");
                break;

        case 'k':       /* kill */
                SIM_LOG_UNIMPLEMENTED(1, &gdb->obj, 0, "k = kill");
                unhandled_command(gdb, cmd);
                break;
        case 'T':       /* thread alive */
                SIM_LOG_INFO(3, &gdb->obj, 0, "T = thread alive");
                handle_thread_alive(gdb, cmd + 1);
                break;

        case 'R':       /* remote restart */
                handle_reset(gdb, cmd + 1);
                break;

        case 'r':       /* reset */
                SIM_LOG_UNIMPLEMENTED(1, &gdb->obj, 0, "r = reset");
                unhandled_command(gdb, cmd);
                break;

        case 'q':       /* general query */
                SIM_LOG_INFO(3, &gdb->obj, 0, "q = general query");
                general_query(gdb, cmd);
                break;

        case 'p': /* read single register */
                SIM_LOG_INFO(3, &gdb->obj, 0,
                             "p = read single register"
                             " (thread = %lld)",
                             gdb_other(gdb).thread);
                read_single_register(gdb, cmd);
                break;

        case 'P': /* write single register */
                SIM_LOG_INFO(3, &gdb->obj, 0,
                             "P = write single register"
                             " (thread = %lld)",
                             gdb_other(gdb).thread);
                write_single_register(gdb, cmd);
                break;

        case 'Q':       /* general set */
                SIM_LOG_INFO(3, &gdb->obj, 0, "Q = general set");
                if (strlen(cmd) >= 10 && strncmp(cmd, "QBookmark:", 10) == 0) {
                        goto_bookmark(gdb, cmd + 10);
                } else {
                        SIM_LOG_UNIMPLEMENTED(1, &gdb->obj, 0,
                                              "Q = general set (%s)", cmd);
                        unhandled_command(gdb, cmd);
                }
                break;

        case 'Z':
                SIM_LOG_INFO(3, &gdb->obj, 0, "Z = set breakpoint");
                do_handle_breakpoint(gdb, cmd + 1, true);
                break;

        case 'z':
                SIM_LOG_INFO(3, &gdb->obj, 0, "z = remove breakpoint");
                do_handle_breakpoint(gdb, cmd + 1, false);
                break;

        case 'X': /* write binary memory */
                SIM_LOG_UNIMPLEMENTED(1, &gdb->obj, 0,
                                      "X = write binary memory");
                unhandled_command(gdb, cmd);
                break;

        case 'e': /* undocumented step range thingie */
                SIM_LOG_UNIMPLEMENTED(1, &gdb->obj, 0,
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
                        SIM_LOG_ERROR(&gdb->obj, 0,
                                      "%#2.2x (%c) = unknown request",
                                      ch, ch);
                } else {
                        SIM_LOG_ERROR(&gdb->obj, 0,
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
                SIM_log_error(&gdb->obj, 0, "arch_reg_init() called with"
                              " pending exception: %s",
                              SIM_last_error());
        }

        const int_register_interface_t *const ir =
                SIM_c_get_interface(cpu, INT_REGISTER_INTERFACE);
        if (ir == NULL) {
                SIM_log_error(&gdb->obj, 0,
                              "cannot find %s interface in CPU %s",
                              INT_REGISTER_INTERFACE, SIM_object_name(cpu));
                return false;
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
                                SIM_log_error(&gdb->obj, 0, "cannot find"
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
                rd.regnum = atoi(name + 1);
                rd.read = reg_read_v9f;
                rd.write = reg_write_v9f;
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
                        SIM_LOG_ERROR(&gdb->obj, 0,
                                      "Error reading attribute"
                                      " architecture from"
                                      " object %s: %s",
                                      SIM_object_name(cpu),
                                      SIM_last_error());
                        return false;
                } else if (!SIM_attr_is_string(arch_attr)) {
                        SIM_LOG_ERROR(&gdb->obj, 0,
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
                        SIM_log_error(&gdb->obj, 0,
                                      "Error reading attribute"
                                      " gdb_remote_variant from"
                                      " object %s: %s",
                                      SIM_object_name(gdb_context_object(gdb)),
                                      SIM_last_error());
                } else if (!SIM_attr_is_nil(attr)) {
                        SIM_log_error(&gdb->obj, 0,
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
                SIM_LOG_ERROR(&gdb->obj, 0, "Unsupported CPU architecture: %s",
                              gdb->architecture);
                return false;
        }

        if (!gdb->arch) {
                SIM_LOG_INFO(2, &gdb->obj, 0, "Attached to %s", 
                             SIM_object_name(gdb->context_object
                                             ? gdb->context_object
                                             : cpu));
        }

        /* FIXME jrydberg 2006-02-09: Why shouldn't this be possible? */
        if (gdb->arch && gdb->arch != arch) {
                SIM_LOG_ERROR(&gdb->obj, 0,
                              "Cannot change CPU architecture.");
                return false;
        }

        gdb->arch = arch;

        attr_value_t queue_attr = SIM_make_attr_object(SIM_object_clock(cpu));
        if (SIM_set_attribute(&gdb->obj, "queue", &queue_attr) != Sim_Set_Ok) {
                SIM_LOG_ERROR(&gdb->obj, 0,
                              "error setting queue from CPU %s: %s",
                              SIM_object_name(cpu), SIM_last_error());
                return false;
        }

        if (!init_regs(gdb, cpu, arch)) {
                gdb->arch = NULL;
                queue_attr = SIM_make_attr_nil();
                SIM_set_attribute(&gdb->obj, "queue", &queue_attr);
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

        VT_stop_message(&gdb->obj, "Remote GDB connected");
}

/* A remote GDB has requested to connect to this GDB stub.  Accept it
   and fetch GDB stub architecture (done in set_gdb_cpu.)  */
static void
gdb_accept(void *gdb_ptr)
{
        gdb_remote_t *gdb = gdb_ptr;
        struct sockaddr inet_addr;
        socklen_t len;
        int true_arg = 1;

        len = sizeof inet_addr;
        socket_t fd = accept(gdb->server_fd, &inet_addr, &len);
        if (fd == OS_INVALID_SOCKET) {
                if (errno != EAGAIN)
                        pr("[gdb-remote] accept() failed: %s\n",
                           os_describe_last_socket_error());
                return;
        }

        /* Only accept one connection per gdb-remote object, otherwise
           we might end up in tricky situations.  */
        if (gdb->fd != OS_INVALID_SOCKET) {
                os_socket_close(fd);
                return;
        }

        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                       (char *)&true_arg, 4) < 0) {
                pr("[gdb-remote] setsockopt(): %s\n", 
                   os_describe_last_socket_error());
        }
        SIM_LOG_INFO(3, &gdb->obj, 0, "New GDB connection established");

        os_set_socket_non_blocking(fd);

        gdb->fd = fd;
        if (os_socket_write(gdb->fd, "+", 1) != 1)
                SIM_LOG_INFO(1, &gdb->obj, 0,
                             "Connection successful but failed to respond"
                             " with a '+'");	
        /* Make sure we have halted simulation before continuing */
        SIM_register_work(gdb_connected, gdb);
}

/* Sets up a listen sockets allowing GDB clients to connect to Simics.
   Simics will listen on LISTEN_PORT.  */

static void
setup_listen_socket(gdb_remote_t *gdb, int listen_port)
{
        int dummy = 1;
        socket_t fd;

        gdb->server_port = 0;

        if (!os_socket_isvalid(fd = socket(PF_INET, SOCK_STREAM, 0))) {
                SIM_LOG_ERROR(&gdb->obj, 0, "socket(): %s",
                              os_describe_last_socket_error());
                return;
        }

/* To prevent opening a port that someone else is already listening to.
   See discussion in bug 7633. */
#ifdef _WIN32
 #define LISTEN_SOCKOPT SO_EXCLUSIVEADDRUSE
#else
 #define LISTEN_SOCKOPT SO_REUSEADDR
#endif

        if (setsockopt(fd, SOL_SOCKET, LISTEN_SOCKOPT, (void *)&dummy, 4) < 0)
                SIM_LOG_ERROR(&gdb->obj, 0, "setsockopt(): %s",
                              os_describe_last_socket_error());

        struct sockaddr_in inet_addr = {
                .sin_family = AF_INET,
                .sin_port = htons(listen_port),
                .sin_addr.s_addr = htonl(INADDR_ANY)
        };

        /* bind address to socket */
        if (bind(fd, (struct sockaddr *)&inet_addr, sizeof(inet_addr)) < 0) {
                SIM_LOG_ERROR(&gdb->obj, 0, "bind(): %s",
                              os_describe_last_socket_error());
                os_socket_close(fd);
                return;
        }

        /* now listen for incoming connections */
        if (listen(fd, 5) < 0) {
                SIM_LOG_ERROR(&gdb->obj, 0, "listen(): %s",
                              os_describe_last_socket_error());
                os_socket_close(fd);
                return;
        }

        /* get the actual port used */
        socklen_t len = sizeof(inet_addr);
        if (getsockname(fd, (struct sockaddr *)&inet_addr, &len) == -1) {
                SIM_LOG_ERROR(&gdb->obj, 0, "getsockname failed: %s",
                              os_describe_last_socket_error());
                os_socket_close(fd);
                return;
        }
        gdb->server_port = ntohs(inet_addr.sin_port);

        gdb->server_fd = fd;
        os_set_socket_non_blocking(fd);

        SIM_notify_on_socket(fd, Sim_NM_Read, 0, gdb_accept, gdb);
        SIM_LOG_INFO(2, &gdb->obj, 0,
                     "Awaiting GDB connections on port %d.", gdb->server_port);
        SIM_LOG_INFO(2, &gdb->obj, 0, "Connect from GDB using: \"target "
                     "remote localhost:%d\"", gdb->server_port);

        if (gdb->architecture) {
                setup_architecture(gdb);
        }
}

static attr_value_t
get_processor(void *arg, conf_object_t *obj, attr_value_t *idx)
{
        gdb_remote_t *gdb = (gdb_remote_t *)obj;
        return SIM_make_attr_object (gdb->processor);
}

static set_error_t
set_processor(void *dummy, conf_object_t *obj, attr_value_t *val,
              attr_value_t *idx)
{
        gdb_remote_t *gdb = (gdb_remote_t *)obj;
        conf_object_t *cpu = SIM_attr_is_nil(*val) ? NULL : SIM_attr_object(*val);
        if (cpu && (!processor_iface(cpu) || !context_handler_iface(cpu))) {
                SIM_LOG_ERROR(
                        &gdb->obj, 0,
                        "Failed getting " PROCESSOR_INFO_INTERFACE " or "
                        CONTEXT_HANDLER_INTERFACE " interface from CPU %s.",
                        SIM_object_name(gdb->processor));
                return Sim_Set_Interface_Not_Found;
        } else {
                gdb->processor = cpu;
                if (cpu)
                        SIM_LOG_INFO(2, &gdb->obj, 0, "Attached to CPU: %s",
                                     SIM_object_name(cpu));
                else
                        SIM_LOG_INFO(2, &gdb->obj, 0, "Not attached to a CPU");
                return Sim_Set_Ok;
        }
}

static set_error_t
set_signal(void *dummy, conf_object_t *obj, attr_value_t *val,
           attr_value_t *idx)
{
        gdb_remote_t *gdb = (gdb_remote_t *)obj;

        int64 ival = SIM_attr_integer(*val);
        if (ival <= 0 || ival > 255) {
                SIM_attribute_error("Signal number must be in 1..255");
                return Sim_Set_Illegal_Value;
        }

        do_signal(gdb, ival);
        return Sim_Set_Ok;
}

static set_error_t
set_send_packet(void *dummy, conf_object_t *obj, attr_value_t *val,
                attr_value_t *idx)
{
        gdb_remote_t *gdb = (gdb_remote_t *)obj;

        const char *str = SIM_attr_string(*val);
        send_packet(gdb, str);
        SIM_attr_free(val);
        return Sim_Set_Ok;
}

static set_error_t
set_large_operations(void *dummy, conf_object_t *obj, attr_value_t *val,
                     attr_value_t *idx)
{
        gdb_remote_t *gdb = (gdb_remote_t *)obj;
        gdb->large_operations = !!SIM_attr_integer(*val);
        return Sim_Set_Ok;
}

static attr_value_t
get_large_operations(void *dont_care, conf_object_t *obj, attr_value_t *idx)
{
        gdb_remote_t *gdb = (gdb_remote_t *)obj;
        return SIM_make_attr_uint64(gdb->large_operations);
}

static set_error_t
set_disconnect(void *dummy, conf_object_t *obj, attr_value_t *val,
               attr_value_t *idx)
{
        gdb_remote_t *gdb = (gdb_remote_t *)obj;
        gdb_disconnect(gdb);
        return Sim_Set_Ok;
}

static attr_value_t
get_connected(void *dummy, conf_object_t *obj, attr_value_t *idx)
{
        gdb_remote_t *gdb = (gdb_remote_t *)obj;

        return SIM_make_attr_boolean(gdb->fd != OS_INVALID_SOCKET);
}

static bool
is_cont_thread(gdb_remote_t *gdb, conf_object_t *ctx, conf_object_t *cpu)
{
        return ctx == gdb_context_object(gdb)
                && is_current_thread(gdb, gdb->cont_thread, cpu);
}

static void
thread_change(gdb_remote_t *gdb, conf_object_t *ctx, conf_object_t *cpu)
{
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
thread_active(void *_gdb, conf_object_t *tracker, int64 tid,
              conf_object_t *cpu, bool active)
{
        gdb_remote_t *gdb = _gdb;
        if (active)
                thread_change(gdb, gdb_context_object(gdb), cpu);
}

/* Connect to thread_tracker by ugly-reading attributes. */
static void
context_updated(void *_gdb, conf_object_t *ctx_obj)
{
        gdb_remote_t *gdb = _gdb;

        attr_value_t cpus = default_processor_list(&gdb->obj);
        for (int i = 0; i < SIM_attr_list_size(cpus); i++) {
                conf_object_t *cpu
                        = SIM_attr_object(SIM_attr_list_item(cpus, i));
                thread_active(gdb, &gdb->obj,
                              default_thread_id,
                              cpu, true);
        }
        SIM_attr_free(&cpus);
}

static attr_value_t
get_architecture(void *arg, conf_object_t *obj, attr_value_t *idx)
{
        gdb_remote_t *gdb = (gdb_remote_t *) obj;
        return SIM_make_attr_string(gdb->architecture);
}

static set_error_t
set_architecture(void *arg, conf_object_t *obj, attr_value_t *val,
                 attr_value_t *idx)
{
        gdb_remote_t *gdb = (gdb_remote_t *)obj;
        gdb->architecture = MM_STRDUP(SIM_attr_string(*val));
        return Sim_Set_Ok;
}

static set_error_t
set_extender(void *arg, conf_object_t *obj, attr_value_t *val,
                 attr_value_t *idx)
{
        gdb_remote_t *gdb = (gdb_remote_t *)obj;
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
get_extender(void *dummy, conf_object_t *obj, attr_value_t *idx)
{
        gdb_remote_t *gdb = (gdb_remote_t *) obj;
        return SIM_make_attr_object(gdb->extender);
}

static attr_value_t
get_listen(void *dummy, conf_object_t *obj, attr_value_t *idx)
{
        gdb_remote_t *gdb = (gdb_remote_t *) obj;
        return SIM_make_attr_uint64(gdb->server_port);
}

/* Called when the ``listen'' attribute of the object is set to a
   value.  Only integers are accepted.  Start listening for GDB remote
   connections to the specified port.  */

static set_error_t
set_listen(void *ignore, conf_object_t *obj, attr_value_t *val,
           attr_value_t *idx)
{
        gdb_remote_t *gdb = (gdb_remote_t *)obj;

        if (SIM_attr_integer(*val) < 0)
                return Sim_Set_Illegal_Value;

        conf_object_t *cpu = gdb_any_processor(gdb);
        if (!cpu) {
                SIM_LOG_ERROR(&gdb->obj, 0, "Not connected to processor.");
                return Sim_Set_Ok;
        }

        setup_listen_socket(gdb, SIM_attr_integer(*val));
        return Sim_Set_Ok;
}

static set_error_t
set_context_object(void *dummy, conf_object_t *obj, attr_value_t *val,
                   attr_value_t *idx)
{
        gdb_remote_t *gdb = (gdb_remote_t *)obj;
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
get_context_object(void *dummy, conf_object_t *obj, attr_value_t *idx)
{
        gdb_remote_t *gdb = (gdb_remote_t *) obj;
        return SIM_make_attr_object(gdb->context_object);
}

static set_error_t
set_send_target_xml(void *dummy, conf_object_t *obj, attr_value_t *val,
                   attr_value_t *idx)
{
        gdb_remote_t *gdb = (gdb_remote_t *) obj;

        if (!SIM_attr_is_boolean(*val))
                return Sim_Set_Illegal_Value;

        gdb->send_target_xml = SIM_attr_boolean(*val);
        return Sim_Set_Ok;
}

static attr_value_t 
get_send_target_xml(void *dummy, conf_object_t *obj, attr_value_t *idx)
{
        gdb_remote_t *gdb = (gdb_remote_t *) obj;
        return SIM_make_attr_boolean(gdb->send_target_xml);
}

static set_error_t
set_follow_context(void *dummy, conf_object_t *obj, attr_value_t *val,
                   attr_value_t *idx)
{
        gdb_remote_t *gdb = (gdb_remote_t *) obj;

        int64 ival = SIM_attr_integer(*val);
        if (ival != 0 && ival != 1)
                return Sim_Set_Illegal_Value;

        gdb->follow_context = ival;
        return Sim_Set_Ok;
}

static attr_value_t
get_follow_context(void *dummy, conf_object_t *obj, attr_value_t *idx)
{
        gdb_remote_t *gdb = (gdb_remote_t *) obj;
        return SIM_make_attr_uint64(gdb->follow_context);
}

static set_error_t
set_inject_serial_command(void *data, conf_object_t *obj, attr_value_t *val,
                          attr_value_t *idx)
{
        gdb_remote_t *gdb = (gdb_remote_t *)obj;
        gdb_serial_command(gdb, SIM_attr_string(*val));
        return Sim_Set_Ok;
}

static conf_object_t *
gdb_remote_alloc_object(void *data)
{
        gdb_remote_t *gdb = MM_ZALLOC(1, gdb_remote_t);
        return &gdb->obj;
}

/* Construct new instance of gdb-remote class.
   This does not cause any ports to be listened to. */
static void *
gdb_remote_init_object(conf_object_t *obj, void *data)
{
        gdb_remote_t *gdb = (gdb_remote_t *)obj;
        gdb->fd = OS_INVALID_SOCKET;
        gdb->server_port = 0;
        gdb->send_target_xml = 1;
        gdb->cont_thread = gdb->other_thread = -1;
        gdb->context_change_hap_handle = gdb->context_updated_hap_handle = -1;
        gdb->sim_stopped_hap_handle = gdb->continuation_hap_handle = -1;
        gdb->segment_linear_base = 0;
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

        const class_data_t class_data = {
                .alloc_object = gdb_remote_alloc_object,
                .init_object = gdb_remote_init_object,
                .description = sb_str(&desc),
                .kind = Sim_Class_Kind_Pseudo
        };

        conf_class_t *gdb_remote_class = SIM_register_class("gdb-remote",
                                                            &class_data);

        SIM_register_typed_attribute(
                gdb_remote_class, "listen",
                get_listen, 0, set_listen, 0,
                Sim_Attr_Pseudo | Sim_Init_Phase_1,
                "i", NULL,
                "Set to start listening for incoming GDB connections on the"
                " specified port. If 0 is specified, an arbitrary available"
                " port will be used. Read to get the port currently listened"
                " on, or 0 if none.");
        SIM_register_typed_attribute(
                gdb_remote_class, "processor",
                get_processor, 0, set_processor, 0,
                Sim_Attr_Pseudo,
                "o|n", NULL, "Processor to connect the GDB stub to.");
        SIM_register_typed_attribute(
                gdb_remote_class, "architecture",
                get_architecture, 0, set_architecture, 0,
                Sim_Attr_Pseudo,
                "s", NULL, "Architecture of target.");
        SIM_register_typed_attribute(
                gdb_remote_class, "extender",
                get_extender, 0, set_extender, 0,
                Sim_Attr_Pseudo | Sim_Attr_Internal,
                "o|n", NULL, "Experimental protocol extender object.");
        SIM_register_typed_attribute(
                gdb_remote_class, "disconnect",
                0, 0, set_disconnect, 0,
                Sim_Attr_Pseudo,
                "b", NULL, "Disconnects the remote GDB");
        SIM_register_typed_attribute(
                gdb_remote_class, "connected",
                get_connected, NULL, 0, NULL,
                Sim_Attr_Pseudo, "b", NULL,
                "Returns true if the gdb-remote object is connected to a"
                " GDB session, false if not.");
        SIM_register_typed_attribute(
                gdb_remote_class, "signal",
                0, 0, set_signal, 0,
                Sim_Attr_Pseudo,
                "i", NULL,
                "Sends a signal to the remote GDB. This makes GDB think the"
                " program it is debugging has received a signal."
                " See the <tt>signal(7)</tt> man page for a list of"
                " signal numbers.");
        SIM_register_typed_attribute(
                gdb_remote_class, "send_packet",
                0, 0, set_send_packet, 0, Sim_Attr_Pseudo, "s", NULL,
                "Sends a raw packet from gdb-remote to GDB. The string that"
                " this attribute is written with will be sent as a packet to"
                " GDB.");
        SIM_register_typed_attribute(
                gdb_remote_class, "large_operations",
                get_large_operations, 0,
                set_large_operations, 0,
                Sim_Attr_Optional,
                "i", NULL,
                "Set to non-zero if memory operations received from GDB"
                " should be performed as single operations instead of"
                " bytewise");
        SIM_register_typed_attribute(
                gdb_remote_class, "follow_context",
                get_follow_context, 0, 
                set_follow_context, 0,
                Sim_Attr_Pseudo, "i", NULL,
                "Set to non-zero if context should be followed.");
        SIM_register_typed_attribute(
                gdb_remote_class, "context_object",
                get_context_object, 0, 
                set_context_object, 0,
                Sim_Attr_Optional,
                "o|n", NULL,
                "Context object that this GDB session is attached to.");
        SIM_register_typed_attribute(
                gdb_remote_class, "send_target_xml",
                get_send_target_xml, 0, 
                set_send_target_xml, 0,
                Sim_Attr_Optional,
                "b", NULL,
                "Should an XML target description be sent to GDB, "
                "default is true, but can be disabled since it can confuse "
                "some clients (e.g. Eclipse on a Linux host).");
        SIM_register_typed_attribute(
                gdb_remote_class, "inject_serial_command",
                0, NULL, set_inject_serial_command, NULL,
                Sim_Attr_Pseudo | Sim_Attr_Internal, "s", NULL,
                "Inject a GDB serial command as if the remote gdb"
                " process had sent it.");

        step_event = SIM_register_event(
            "singlestep breakpoint", gdb_remote_class, Sim_EC_Notsaved,
            gdb_step_handler, 0, 0, 0, 0);

        os_initialize_sockets();
}

uint64
reg_read_zero(conf_object_t *cpu, register_description_t *rd)
{
        return 0;
}

uint64
reg_read_int(conf_object_t *cpu, register_description_t *rd)
{
        const int_register_interface_t *const iface =
                SIM_c_get_interface(cpu, INT_REGISTER_INTERFACE);
        ASSERT(iface);
        return iface->read(cpu, rd->regnum);
}

uint64
reg_read_int32l(conf_object_t *cpu, register_description_t *rd)
{
        return (uint32)reg_read_int(cpu, rd);
}

uint64
reg_read_int32h(conf_object_t *cpu, register_description_t *rd)
{
        return reg_read_int(cpu, rd) >> 32;
}

uint64
reg_read_v9f(conf_object_t *cpu, register_description_t *rd)
{
        const sparc_v9_interface_t *const iface
                = SIM_c_get_interface(cpu, SPARC_V9_INTERFACE);
        ASSERT(iface);
        if (rd->size == 32)
                return iface->read_fp_register_i(cpu, rd->regnum);
        else if (rd->size == 64)
                return iface->read_fp_register_x(cpu, rd->regnum);
        else
                ASSERT(false);
}

bool
reg_write_ignore(conf_object_t *cpu, register_description_t *rd, uint64 val)
{
        return false;
}

bool
reg_write_int(conf_object_t *cpu, register_description_t *rd, uint64 val)
{
        const int_register_interface_t *const iface =
                SIM_c_get_interface(cpu, INT_REGISTER_INTERFACE);
        ASSERT(iface);
        iface->write(cpu, rd->regnum, val);
        return true;
}

bool
reg_write_int32l(conf_object_t *cpu, register_description_t *rd, uint64 val)
{
        return reg_write_int(cpu, rd,
                             reg_read_int32h(cpu, rd) << 32 | (uint32)val);
}

bool
reg_write_int32h(conf_object_t *cpu, register_description_t *rd, uint64 val)
{
        return reg_write_int(cpu, rd,
                             val << 32 | reg_read_int32l(cpu, rd));
}

bool
reg_write_v9f(conf_object_t *cpu, register_description_t *rd, uint64 val)
{
        const sparc_v9_interface_t *const iface
                = SIM_c_get_interface(cpu, SPARC_V9_INTERFACE);
        ASSERT(iface);
        if (rd->size == 32)
                iface->write_fp_register_i(cpu, rd->regnum, val);
        else if (rd->size == 64)
                iface->write_fp_register_x(cpu, rd->regnum, val);
        else
                ASSERT(false);
        return true;
}
