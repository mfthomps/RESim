/*
  gdb-remote.h

  © 2010 Intel Corporation

  This software and the related documents are Intel copyrighted materials, and
  your use of them is governed by the express license under which they were
  provided to you ("License"). Unless the License provides otherwise, you may
  not use, modify, copy, publish, distribute, disclose or transmit this software
  or the related documents without Intel's prior written permission.

  This software and the related documents are provided as is, with no express or
  implied warranties, other than those that are expressly stated in the License.
*/

#ifndef GDB_REMOTE_H
#define GDB_REMOTE_H

#include <simics/simulator-api.h>
#include <simics/util/vect.h>
#include <simics/base/iface-call.h>

#include <simics/model-iface/external-connection.h>
#include <simics/model-iface/processor-info.h>
#include <simics/simulator-iface/context-tracker.h>
#include "gdb-extender-iface.h"
#include "gdb-record.h"
 
#define GDB_MAX_PACKET_SIZE 8192

typedef enum {
        Gdb_Bp_Software, Gdb_Bp_Hardware,
        Gdb_Bp_Write, Gdb_Bp_Read, Gdb_Bp_Access
} gdb_breakpoint_type_t;

typedef enum {
        Simics_Gdb_Bp_Hap,
        Simics_Gdb_Virt_Insn,
        Simics_Gdb_Virt_Data,
} simics_bp_type_t;

typedef struct {
        union {
                struct {
                        breakpoint_id_t bp_id;
                        hap_handle_t hap_id;
                };
                virtual_instr_bp_handle_t *virt_insn;
                struct {
                        virtual_data_bp_handle_t *virt_data_write;
                        virtual_data_bp_handle_t *virt_data_read;
                };
        };
        simics_bp_type_t bp_type;
        bool valid;
} installed_bp_data_t;

struct gdb_breakpoint {
        struct gdb_remote *gdb;
        gdb_breakpoint_type_t type;
        logical_address_t la;
        logical_address_t len;
        installed_bp_data_t bp_data;
        int count;
};

struct gdb_server {
        conf_object_t obj;
};

typedef struct {
        const char *name;
        int length;
} register_section_t;

typedef struct gdb_remote gdb_remote_t;

typedef struct register_description register_description_t;
struct register_description {
        const char *name;   /* name of register */
        int size;           /* register size in bits */
        int regnum;         /* Simics register number */
        const char *type;   /* register type (for the target XML description) */

        /* Register read function. */
        uint64 (*read)(conf_object_t *cpu, register_description_t *rd);

        /* Register write function. Returns true if the write was allowed,
           false otherwise. */
        bool (*write)(conf_object_t *cpu, register_description_t *rd,
                      uint64 val);
};

typedef VECT(register_description_t) reg_desc_vect_t;
typedef QUEUE(char) char_queue_t;

struct gdb_remote {
        conf_object_t obj;

        char_queue_t received; /* characters received from gdb */

	char *architecture;

        conf_object_t *processor;
        conf_object_t *context_object;
        hap_handle_t context_change_hap_handle, context_updated_hap_handle;

        hap_handle_t sim_stopped_hap_handle, continuation_hap_handle;

        /* Thread ID for stepping. >0 means that stepping follows that
           specific thread, -1 means that stepping doesn't follow a specific
           thread. */
        int64 cont_thread;
        /* Thread ID for other operations (e.g., inspection). >0 means to use
           that specific thread, -1 means the currently active thread. */
        int64 other_thread;

        /* The processor we're currently single-stepping on, or NULL if we
           aren't single-stepping. */
        conf_object_t *step_handler_cpu;

        struct gdb_breakpoint *bp;
        logical_address_t access_address;

        enum { OTC_Do_Nothing, OTC_Stop, OTC_Single_Step } on_thread_change;
        int follow_context;

        bool is_running;

        struct gdb_breakpoints {
                int size, used;
                struct gdb_breakpoint *entries;
        } breakpoints;

        bool large_operations;

        const struct gdb_arch *arch;
        void *arch_data;

        /* Experimental support, might change at any time */
        conf_object_t *extender;
        const gdb_extender_interface_t *extender_iface;

        /* Set when the simulation has been requested to stop and the notifier
           for receiving gdb messages has been (temporarily) disabled. */
        bool stop_in_progress;

        /* Should we execute in reverse next time we start executing? */
        bool next_reverse_direction;

        /* Should an XML target description be sent to GDB,
           default is true, but can be disabled since it can confuse
           some clients (e.g. Eclipse). */
        bool send_target_xml;

        /* Hardcoded registers or Xtensa specific */
        reg_desc_vect_t default_register_descriptions;

        /* Runtime defined registers. */
        VECT(register_section_t) register_sections;
        reg_desc_vect_t register_descriptions;

        /* Offset to add to breakpoints, used by custom 'segment' command. */
        uint32 segment_linear_base;

        /* Alloc qRcmd command which allows any simics command to be executed
           from remote. This will allow a gdb remote connection to do anything
           that can be done from CLI. */
        bool allow_remote_commands;

        IFACE_OBJ(external_connection_ctl) server;
        bool connected;

        struct {
                bool enabled;
                VECT(gdb_record_t) records;
        } record_socket;
};

typedef enum {
        regclass_i,             /* integer register */
        regclass_i_opt,         /* optional integer register */
        regclass_i32l,          /* low 32-bit of 64-bit register */
        regclass_i32h,          /* high 32-bit of 64-bit register */
        regclass_v9_f,          /* SPARC-V9 floating-point register */
        regclass_unused         /* unused register (always 0 to GDB) */
} regclass_t;

typedef struct {
        int bits;                         /* register width in bits */
        const char *name;                 /* register name (constant string) */
        regclass_t regclass;
} regspec_t;

typedef struct gdb_arch gdb_arch_t;

struct gdb_arch {
        const char *name;       /* architecture name */
        const char *arch_name;

        /* hints about connecting GDB */
        struct {
                const char *target_flag;
                const char *prompt_cmd;
        } help;

        bool is_be;
        bool bit_extend;     /* should 32 bit addrs be extended to 64? */
        bool hidden;         /* don't print this arch in the list */

        bool (*init)(gdb_remote_t *gdb, conf_object_t *cpu);
        int (*read_register_window_shadow)(
                gdb_remote_t *gdb, conf_object_t *cpu,
                logical_address_t la, logical_address_t len, char *buf);

        /* Optional way to get hold of the target registers */
        bool (*get_register_descriptions)(gdb_remote_t *gdb, conf_object_t *cpu);

        /* Optional mapper from another register number to the correct 
           register_description_t */
        register_description_t *(*reg_mapper)(
                gdb_remote_t *gdb, reg_desc_vect_t *rds, int idx);

        const regspec_t *regs;
        int nregs;                           /* size of regs array */
};

/* Generated table; terminated by NULL */
extern const gdb_arch_t *const gdb_archs[];

void gdb_print_hex(char *buf, uint64 val, bool is_be, uint8 bits);

bool read_opt_attr(conf_object_t *log_obj, conf_object_t *obj,
                   const char *attr_name, attr_value_t * const attr);

void handle_ctrl_c(gdb_remote_t *gdb);
void gdb_serial_command(gdb_remote_t *gdb, const char *cmd);

FORCE_INLINE gdb_remote_t *
gdb_of_obj(conf_object_t *obj)
{
        return (gdb_remote_t *)obj;
}

FORCE_INLINE conf_object_t *
to_obj(gdb_remote_t *gdb)
{
        return &gdb->obj;
}

#endif /* GDB_REMOTE_H */
