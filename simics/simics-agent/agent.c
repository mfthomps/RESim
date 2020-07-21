/* This Software is part of Wind River Simics. The rights to copy, distribute,
   modify, or otherwise make use of this Software may be licensed only
   pursuant to the terms of an applicable Wind River license agreement.

   Copyright 2012-2016 Intel Corporation */

#include "magic.h"
#include "agent.h"
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef __linux
#include "util_linux.h"
#endif

int simics_agent_debug = 0;

static void
trigger_magic(struct matic_buffer *buf)
{
/* The default magic instruction hap number used by the simics agent is 12.
   WARNING! Do not changes this value unless instructed to do so. */
        MAGIC_ASM(12, buf);
}

static inline void
print_matic_buffer_header(struct matic_buffer *buf)
{
        printf("BUFFER : magic=0x%016" PRIx64 " size=%-4hu code=0x%04hx"
               " num=%08x\n", buf->head.magic, buf->head.size, buf->head.code,
               buf->head.num);
}

typedef int (*handler_func)(struct matic_buffer *buf, struct agent *my);

static const struct req_handler {
        uint16_t code;
        handler_func func;
        const char *name;
} reqs[] = {
        { 0x0000, &announce_agent_response, "announce_agent" },
        { 0x0010, &set_poll_response, "set-poll-interval" },
        { 0x0020, &get_time_response, "get-time" },
        { 0x0030, &file_open_response, "file-open" },
        { 0x0100, &ticket_discard_response, "ticket-discard" },
        { 0x0110, &ticket_read_response, "ticket-read" },
        { 0x0120, &ticket_write_response, "ticket-write" },
        { 0x0130, &ticket_write_response, "ticket-sync-write" },
        { 0x0150, &ticket_getpos_response, "ticket-getpos" },
        { 0x0160, &ticket_setpos_response, "ticket-setpos" },
        { 0x1000, &set_time_response, "set-time" },
        { 0x1010, &read_dir_response, "read-dir" },
        { 0x1020, &file_perm_response, "file-permission" },
        { 0x17F0, &restart_agent, "restart-agent" },
        { 0x1800, &process_open_response, "process-open" },
#if defined(__linux)
        { 0x1810, &process_exec_response, "process-exec" },
        { 0x1820, &process_poll_response, "process-poll" },
#endif
        { 0xFFF0, &quit_agent_response, "quit-agent" },
        { 0x0000, NULL, NULL },
};

static void
protocol_failure(struct matic_buffer *buf, int ec)
{
        const char *info = NULL;
        buf->head.magic = MAGIC;
        buf->head.size = 0;
        buf->head.code = 0x000F;
        buf->head.num = ec;
        buf_string_append(buf, strerror(ec));
        switch (ec) {
        case EPROTONOSUPPORT:
                info = "Unrecognized major version";
                break;
        case ENOMSG:
                info = "Not a request message";
                break;
        case EBADR:
                info = "Invalid message size";
                break;
        case EBADRQC:
                info = "Unknown request code";
                break;
        default:
                break;
        }
        if (info)
                buf_string_append(buf, info);
        if (simics_agent_debug)
                fprintf(stderr, "PROTOCOL ERROR: %s (%d): %s\n",
                        buf->data, ec, info ? info : "");
}

static bool
compatible_magic(uint64_t this, uint64_t that)
{
        return this >> 8 == that >> 8;
}

static int
do_work(struct matic_buffer *buf, struct agent *my)
{
        static uint16_t last_code = 0;
        if (buf->head.magic != my->magic) {
                if ((buf->head.code == 0)
                    && compatible_magic(buf->head.magic, MAGIC)) {
                        /* reset and continue */
                        ticketstore_reset(&my->tickets);
                        my->magic = MAGIC;
                } else if (my->magic == MAGIC) {
                        my->magic = buf->head.magic;
                        if (my->verbose)
                                printf("%s connected (%016" PRIx64 ")\n",
                                       my->name, my->magic);
                } else {
                        return EPROTONOSUPPORT;
                }
        }
        if (buf->head.code == 0x0002)
                buf->head.num++;
        if (buf->head.code & 0xF)
                return ENOMSG;
        if (buf->head.size > MAX_PAYLOAD_SIZE)
                return EBADR;
        if (simics_agent_debug && last_code != buf->head.code) {
                print_matic_buffer_header(buf);
                last_code = buf->head.code;
        }

        const struct req_handler *req;
        for (req = &reqs[0]; req->name; req++) {
                if (buf->head.code == req->code)
                        break;
        }
        if (!req->name)
                return EBADRQC;

        int rc = req->func(buf, my);
        if (rc)
                common_error_response(buf, rc, NULL);
        if ((buf->head.code & 0xF) == 0xE)
                DBG_PRINT(": %s error: %s (%hu)", req->name,
                          buf->data, buf->head.code);
        return 0;
}

static int
main_loop(struct matic_buffer *buf, struct agent *my)
{
        int rc;
        do {
                /* touch the memory page */
                buf->head.magic = my->magic;
                trigger_magic(buf);
                rc = do_work(buf, my);
                if (!rc)
                        continue;
                if (rc == ENOMSG) { /* no request message */
#ifdef __linux
                        if (my->sel.nfds) {
                                if (async_exit_response(buf, my))
                                        continue;
                                if (async_event_response(buf, my, my->timeout))
                                        continue;
                        }
#endif
                        sleep_millisec(my->timeout);
                        announce_agent_response(buf, my);
                } else {
                        DBG_PRINT("; do_work returned %d for", rc);
                        if (simics_agent_debug)
                                print_matic_buffer_header(buf);
                        protocol_failure(buf, rc);
                }
        } while (!my->quit);
        return rc;
}

/* Simics agent argument descriptor.
 * It is used to determine how to parse the command-line arguments.
 * The 'token' is the character used for short flags, like -h.
 * The 'value' will determine if the argument requires a value, and if so what
 * type it is.
 */
static const struct agent_arg {
        const char *name;       /* argument name */
        const char *descr;      /* argument description */
        int token;              /* short argument token */
        int value;              /* argument value type, if non-zero */
} args[] = {
        { "debug", "Print debug information", 'd', 0 },
        { "help", "Print this help information", 'h', 0 },
        { "id", "Override the agent magic id", 0, '#' },
        { "name", "Set the Simics agent name", 0, '$' },
        { "poll", "Set the poll interval [milliseconds]", 0, '#' },
        { "quiet", "Make the agent more quiet", 'q', 0 },
        { "verbose", "Make the agent more verbose", 'v', 0 },
        { "upload", "File to upload to host", 0, '#' },
        { "download", "File to download from host", 0, '#' },
        { "to", "Destination for file transfer", 0, '#' },
        { "overwrite", "Overwrite option for file transfer", 'f', 0 },
        { "executable", "Executable option for file transfer", 'x', 0 },
        { NULL, NULL, 0, 0 }
};

static void
print_help(struct agent *my)
{
        int n;
        for (n = 0; args[n].name; n++) {
                char *val = NULL;

                switch (n) {
                case 0:
                        dynstr_printf(&val, 0, "%s", simics_agent_debug ?
                                     "true" : "false");
                        break;
                case 1:
                        dynstr_printf(&val, 0, "%s",
                                     my->help ? "true" : "false");
                        break;
                case 2:
                        if (my->magic)
                                dynstr_printf(&val, 0, "%016" PRIx64,
                                              my->magic);
                        else
                                dynstr_printf(&val, 0, "<hex number>");
                        break;
                case 3:
                        if (my->name)
                                dynstr_printf(&val, 0, "%s", my->name);
                        else
                                dynstr_printf(&val, 0, "<string>");
                        break;
                case 4:
                        dynstr_printf(&val, 0, "%u", my->timeout);
                        break;
                case 5:
                case 6:
                        dynstr_printf(&val, 0, "verbosity=%u", my->verbose);
                        break;
                case 7:
                        if (my->from && !my->download)
                                dynstr_printf(&val, 0, "%s", my->from);
                        break;
                case 8:
                        if (my->from && my->download)
                                dynstr_printf(&val, 0, "%s", my->from);
                        break;
                case 9:
                        if (my->to)
                                dynstr_printf(&val, 0, "%s", my->to);
                        break;
                case 10:
                        if (my->from)
                                dynstr_printf(&val, 0, "%s",
                                              my->overwrite ? "true" : "false");
                        break;
                case 11:
                        if (my->from)
                                dynstr_printf(&val, 0, "%s",
                                              my->executable ? "true" : "false");
                        break;
                default:
                        break;
                }
                if (args[n].token) {
                        printf("  -%c, --%s", args[n].token, args[n].name);
                } else {
                        printf("  --%s", args[n].name);
                }
                if (val) {
                        if (args[n].value)
                                printf("=%s", val);
                        else
                                printf(" [%s]", val);
                        free(val);
                }
                printf("\n\t%s\n", args[n].descr);
        }
}

/* Parse the argument value and update the context.
 * Returns 0 for unknown arguments.
 * Returns 2 if it consumed the value string.
 * Returns 1 otherwise. */
static int
parse_arg_value(struct agent *my, int n, const char *val)
{
        char *end = NULL;
        switch (n) {
        case 0: /* debug */
                simics_agent_debug = 1;
                break;
        case 1: /* help */
                my->help = 1;
                break;
        case 2: /* id */
                my->magic = strtoull(val, &end, 16);
                if (*end)
                        printf("WARNING: Garbage '%s' at offset %u in id-value"
                               " '%s'\n", end, (uint32_t)(end - val), val);
                return 2;
        case 3: /* name */
                if (my->name)
                        printf("WARNING: Agent %s is renamed %s\n",
                               my->name, val);
                my->name = val;
                return 2;
        case 4: /* poll */
                my->timeout = strtoul(val, &end, 0);
                if (*end)
                        printf("WARNING: Garbage '%s' at offset %u in"
                               " poll-value '%s'\n",
                               end, (uint32_t)(end - val), val);
                return 2;
        case 5: /* quiet */
                if (my->verbose)
                        my->verbose--;
                break;
        case 6: /* verbose */
                my->verbose++;
                break;
        case 7: /* upload */
                my->download = 0;
                my->from = val;
                return 2;
        case 8: /* download */
                my->download = 1;
                my->from = val;
                return 2;
        case 9: /* to */
                my->to = val;
                return 2;
        case 10: /* overwrite */
                my->overwrite = 1;
                break;
        case 11: /* executable */
                my->executable = 1;
                break;
        default:
                return 0;
        }
        return 1;
}

static int
parse_long_args(struct agent *my, int *i)
{
        const char *arg = my->argv[*i] + 2;
        size_t len = 0;
        int n;

        for (n = 0; args[n].name; n++) {
                len = strlen(args[n].name);
                if (strncmp(args[n].name, arg, len) == 0)
                        break;
        }
        if (!args[n].name) {
                printf("WARNING: Unrecognized long option --%s\n", arg);
                return 0;
        }

        const char *end = arg + len;
        if (*end == 0) {
                int rc = parse_arg_value(my, n, my->argv[*i + 1]);
                if (rc > 1)
                        *i += 1;
                return !rc;
        } else if (*end == '=') {
                return !parse_arg_value(my, n, end + 1);
        }
        printf("ERROR: Unrecognized long option --%s\n", arg);
        return 1;
}

static int
parse_short_args(struct agent *my, int i)
{
        const char *arg = my->argv[i];
        int rc = 0;
        int x;

        for (x = 1; arg[x]; x++) {
                int n;
                for (n = 0; args[n].name; n++) {
                        if (!args[n].token)
                                continue;
                        if (arg[x] == args[n].token) {
                                parse_arg_value(my, n, NULL);
                                break;
                        }
                }
                if (!args[n].token) {
                        printf("ERROR: Unrecognized short option -%c\n",
                               arg[x]);
                        rc++;
                }
        }
        return rc;
}

static struct matic_buffer *
get_aligned_buffer(void)
{
        static char matic_buffer[2 * MATIC_PAGE_SIZE];
        size_t ptr = (size_t)matic_buffer + (MATIC_PAGE_SIZE - 1);
        ptr &= ~(MATIC_PAGE_SIZE - 1);
        return (struct matic_buffer *)ptr;
}

int
main(int argc, char *argv[])
{
        static struct agent my = {
                .magic = MAGIC,
                .timeout = MATIC_POLL_TIME,
                .verbose = 1,
        };
        struct matic_buffer *buf = get_aligned_buffer();
        int rc = uname(&my.sys);

        /* initialize */
        my.argv = argv;
        my.argc = argc;
        mode_t mask = umask(022);
        my.acs = 0666 & ~mask;
        if (mask != 022)
                umask(mask);
        ticketstore_init(&my.tickets);
#ifdef __linux
        ticket_selector_init(&my.sel);
#endif

        /* parse arguments */
        int err = 0;
        int i;
        for (i = 1; i < argc; i++) {
                if (argv[i][0] == '-') {
                        if (argv[i][1] == '-')
                                err += parse_long_args(&my, &i);
                        else
                                err += parse_short_args(&my, i);
                } else {
                        if (!my.name) {
                                my.name = argv[i];
                        } else {
                                printf("ERROR: Unknown argument: %s\n", argv[i]);
                                err++;
                        }
                }
        }

        if (my.help) {
                printf("USAGE: %s [OPTIONS] [<agent name>]\n",
                       argv[0]);
                puts("OPTIONS:");
                print_help(&my);
                return 0;
        }
        if (!my.name) {
                if (isalnum(my.sys.nodename[0]))
                        my.name = my.sys.nodename;
                else
                        my.name = my.sys.sysname;
        }

        if (my.verbose)
                printf("%s, v%u.%u, %s %s\n", my.name, MAJOR, MINOR,
                       __DATE__, __TIME__);
        DBG_PRINT(": MaTIC Buffer address %p, size %u bytes",
                  (void *)buf, MATIC_PAGE_SIZE);
        DBG_PRINT(": MaTIC Magic ID value 0x%016" PRIx64, my.magic);
        if (my.verbose > 1)
                printf("sysname=%s\n"
                       "nodename=%s\n"
                       "release=%s\n"
                       "version=%s\n"
                       "machine=%s\n",
                       my.sys.sysname, my.sys.nodename, my.sys.release,
                       my.sys.version, my.sys.machine);

        if (!err) {
                announce_agent_response(buf, &my);
                rc = main_loop(buf, &my);

                /* Leave a goodbye message with a last hap */
                quit_agent_response(buf, &my);
                trigger_magic(buf);
        } else
                rc = EINVAL;
        ticketstore_free(&my.tickets);
#if defined(__linux)
        if (my.sel.nfds)
                ticket_child_free(&my.sel);
#endif
        if (!rc)
                rc = my.quit_code;
        if (my.verbose || rc)
                printf("%s: %s (%d)\n", argv[0], strerror(rc), rc);
        return rc;
}

