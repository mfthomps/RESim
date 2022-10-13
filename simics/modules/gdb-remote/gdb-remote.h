/*
  gdb-remote.h

  This Software is part of Wind River Simics. The rights to copy, distribute,
  modify, or otherwise make use of this Software may be licensed only
  pursuant to the terms of an applicable license agreement.
  
  Copyright 2010-2019 Intel Corporation

*/

#ifndef GDB_REMOTE_H
#define GDB_REMOTE_H

#include <simics/simulator-api.h>
#include <simics/util/vect.h>

#include <simics/model-iface/processor-info.h>
#include <simics/simulator-iface/context-tracker.h>
#include "gdb-extender-iface.h"

#define GDB_MAX_PACKET_SIZE 8192

enum gdb_breakpoint_type { 
        Gdb_Bp_Software, Gdb_Bp_Hardware, 
        Gdb_Bp_Write, Gdb_Bp_Read, Gdb_Bp_Access 
};

struct gdb_breakpoint {
        enum gdb_breakpoint_type type;
        logical_address_t        la, len;
        breakpoint_id_t          bp_id;
        hap_handle_t             hap_id;
        int                      count;
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

        socket_t server_fd;
        socket_t fd;            /* the socket file descriptor */

        int server_port;        /* port we are listening for connections on */

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

        /* Hardcoded registers. */
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
        int decr_pc_after_break;

        const regspec_t *regs;
        int nregs;                           /* size of regs array */
};

/* Generated table; terminated by NULL */
extern const gdb_arch_t *const gdb_archs[];

#define GDB_PRINT_HEX_HEADER(bits)                              \
void gdb_print_hex ## bits ## _le(char *p, uint ## bits value); \
void gdb_print_hex ## bits ## _be(char *p, uint ## bits value)

GDB_PRINT_HEX_HEADER(8);
GDB_PRINT_HEX_HEADER(16);
GDB_PRINT_HEX_HEADER(32);
GDB_PRINT_HEX_HEADER(64);

bool read_opt_attr(conf_object_t *log_obj, conf_object_t *obj,
                   const char *attr_name, attr_value_t * const attr);
uint64 reg_read_zero(conf_object_t *cpu, register_description_t *rd);
uint64 reg_read_int(conf_object_t *cpu, register_description_t *rd);
uint64 reg_read_int32l(conf_object_t *cpu, register_description_t *rd);
uint64 reg_read_int32h(conf_object_t *cpu, register_description_t *rd);
uint64 reg_read_v9f(conf_object_t *cpu, register_description_t *rd);
bool reg_write_ignore(conf_object_t *cpu, register_description_t *rd,
                      uint64 val);
bool reg_write_int(conf_object_t *cpu, register_description_t *rd,
                   uint64 val);
bool reg_write_int32l(conf_object_t *cpu, register_description_t *rd,
                      uint64 val);
bool reg_write_int32h(conf_object_t *cpu, register_description_t *rd,
                      uint64 val);
bool reg_write_v9f(conf_object_t *cpu, register_description_t *rd,
                   uint64 val);

void handle_ctrl_c(gdb_remote_t *gdb);
void gdb_serial_command(gdb_remote_t *gdb, const char *cmd);

#endif /* GDB_REMOTE_H */
