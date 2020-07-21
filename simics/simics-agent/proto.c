/* This Software is part of Wind River Simics. The rights to copy, distribute,
   modify, or otherwise make use of this Software may be licensed only
   pursuant to the terms of an applicable Wind River license agreement.

   Copyright 2012-2016 Intel Corporation */

#include "agent.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>

int
announce_agent_response(struct matic_buffer *buf, struct agent *my)
{
        size_t len = 0;
        buf->head.size = 0;
        buf->head.code = 0x0002;        /* set announcement response */
        buf->head.num = 0;
        len += buf_string_append(buf, "name");
        len += buf_string_printf(buf, "%s", my->name);
        len += buf_string_append(buf, "capabilities");
        len += buf_string_printf(buf, sys_cap);
        len += buf_string_append(buf, "hostname");
        len += buf_string_printf(buf, "%s", my->sys.nodename);
        len += buf_string_append(buf, "machine");
        len += buf_string_printf(buf, "%s", my->sys.machine);
        len += buf_string_append(buf, "system");
        len += buf_string_printf(buf, "%s", my->sys.sysname);
        len += buf_string_append(buf, "release");
        len += buf_string_printf(buf, "%s", my->sys.release);
        len += buf_string_append(buf, "version");
        len += buf_string_printf(buf, "%s", my->sys.version);
        len += buf_string_append(buf, "agent");
        len += buf_string_printf(buf, "%u.%u %s %s",
                                 MAJOR, MINOR, __DATE__, __TIME__);
        if (my->magic == MAGIC && my->from) {
                len += buf_string_append(buf, "download");
                len += buf_string_printf(buf, "%d", my->download);
                char *cwd = getcwd(NULL, 0);
                len += buf_string_append(buf, "path");
                len += buf_string_printf(buf, "%s", cwd);
                free(cwd);
                len += buf_string_append(buf, "from");
                len += buf_string_printf(buf, "%s", my->from);
                if (my->to) {
                        len += buf_string_append(buf, "to");
                        len += buf_string_printf(buf, "%s", my->to);
                }
                len += buf_string_append(buf, "overwrite");
                len += buf_string_printf(buf, "%d", my->overwrite);
                len += buf_string_append(buf, "executable");
                len += buf_string_printf(buf, "%d", my->executable);
        }
        if (len >= MAX_PAYLOAD_SIZE)
                return ENOSPC;
        return 0;
}

int
common_error_response(struct matic_buffer *buf, int ec, const char *info)
{
        buf->head.size = 0;
        buf->head.code |= 0xe;  /* set response bits to error response */
        buf->head.num = ec;
        buf_string_append(buf, strerror(ec));
        if (info)
                buf_string_append(buf, info);
        return 0;
}

int
file_open_response(struct matic_buffer *buf, struct agent *my)
{
        size_t offs = 0;
        const char *path = buf_string_next(buf->data, &offs, 0);
        const char *mode = buf_string_next(buf->data, &offs, 0);
        DBG_PRINT(": path='%s', mode='%s' access=%s", path, mode,
                  access_mode_string(my->acs));
        /* Try to open the file */
        FILE *fdesc = fopen(path, mode);
        if (!fdesc)
                return common_error_response(buf, errno, "fopen()");
        /* Create a ticket */
        struct ticket_desc *tck = ticketstore_create(&my->tickets, path);
        if (!tck) {
                fclose(fdesc);
                return common_error_response(buf, errno,
                                             "ticketstore_create()");
        }
        tck->io = fdesc;
        tck->size = 0;
        tck->access = my->acs;
        tck->req_code = buf->head.code;

        /* best effort check of the file size, ok if fails */
        int rc = fseek(fdesc, 0, SEEK_END);
        if (!rc) {
                long pos = ftell(fdesc);
                if (pos != -1)
                        tck->size = (uint64_t)pos;
                rewind(fdesc);
        }
        /* Compile a ticket response */
        buf->head.code |= 3; /* file-open-ticket */
        buf->head.size = offsetof(struct ticket_entry, name);
        buf->head.num = 1;
        struct ticket_entry *tresp = (struct ticket_entry *)buf->data;
        tresp->total = tck->size;
        tresp->ticket = tck->id;
        tresp->mode = tck->access;
        buf_string_append(buf, tck->name);
        return 0;
}

int
file_perm_response(struct matic_buffer *buf, struct agent *my)
{
        mode_t mode = (mode_t)buf->u16[0];
        if (!buf->head.num) {
                umask(mode);
                buf->head.size = 0;
                buf->head.code |= 1;    /* set response bits to ok response */
                return 0;
        }
        struct ticket_desc *ticket =
                ticketstore_find(&my->tickets, buf->head.num);
        if (!ticket) {
                return common_error_response(buf, ENOMSG, "ticketstore_find()");
        } else if (ticket->io) {
                if (chmod(ticket->name, mode))
                        return common_error_response(buf, errno, "chmod()");
                ticket->access = mode;
        } else {
                ticket->access = mode;
        }
        buf->head.size = 0;
        buf->head.code |= 1;    /* set response bits to ok response */
        return 0;
}

int
process_open_response(struct matic_buffer *buf, struct agent *my)
{
        size_t offs = 0;
        const char *cmdline = buf_string_next(buf->data, &offs, 0);
        const char *mode = buf_string_next(buf->data, &offs, 0);
        DBG_PRINT(": cmd-line='%s', mode='%s' (buffer %p)",
                  cmdline, mode, (void *)buf);
        struct ticket_desc *tck =
                ticketstore_create(&my->tickets, cmdline);
        if (!tck)
                return common_error_response(buf, errno,
                                             "ticketstore_create()");
        tck->size = 0;
        tck->req_code = buf->head.code;
        if (mode[0] == 'r')
                tck->access = S_IRUSR;
        else if (mode[0] == 'w')
                tck->access = S_IWUSR;
        else
                tck->access = 0;        /* let popen handle the fault */
        tck->io = popen(cmdline, mode);
        if (!tck->io) {
                ticketstore_delete(&my->tickets, tck);
                return common_error_response(buf, errno, "popen()");
        }
        /* Create response message */
        buf->head.code |= 3; /* process-open-ticket */
        buf->head.size = offsetof(struct ticket_entry, name);
        buf->head.num = 1;
        struct ticket_entry *tresp = (struct ticket_entry *)buf->data;
        tresp->total = tck->size;
        tresp->ticket = tck->id;
        tresp->mode = tck->access;
        buf_string_append(buf, tck->name);
        return 0;
}

int
quit_agent_response(struct matic_buffer *buf, struct agent *my)
{
        my->quit = 1;
        if (buf->head.size > 0) {
                my->quit_code = buf->head.num;
                size_t offs = 0;
                const char *quit_msg = buf_string_next(buf->data, &offs, 0);
                fprintf(stderr, "%s\n", quit_msg);
        }
        buf->head.size = 0;
        buf->head.code |= 1; /* quit-agent-ack */
        buf->head.num = 0;
        return 0;
}

int
read_dir_response(struct matic_buffer *buf, struct agent *my)
{
        char *path = buf->data;
        DBG_PRINT(": path='%s'", path);
        struct ticket_desc *tck =
                ticketstore_create(&my->tickets, path);
        if (!tck)
                return common_error_response(buf, errno,
                                             "ticketstore_create()");
        tck->size = dynstr_listdir(&tck->data, path);
        tck->access = S_IRUSR;
        tck->req_code = buf->head.code;
        DBG_PRINT(": ticket size=%u name='%s'",
                  (uint32_t)tck->size, tck->name);
        /* create response message */
        buf->head.code |= 3; /* read-dir-ticket */
        buf->head.size = offsetof(struct ticket_entry, name);
        buf->head.num = 1;
        struct ticket_entry *tresp = (struct ticket_entry *)buf->data;
        tresp->total = tck->size;
        tresp->ticket = tck->id;
        tresp->mode = tck->access;
        buf_string_append(buf, tck->name);
        return 0;
}

int
restart_agent(struct matic_buffer *buf, struct agent *my)
{
        char magic[24];
        char poll[16];
        char verbose[8];
        const char *argv[7] = {
                my->argv[0],
                my->name,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL
        };
        int n = 2;
        /* Create new cmd-line argument array */
        sprintf(magic, "--id=%08x%08x",
                (uint32_t)(my->magic >> 32), (uint32_t)my->magic);
        argv[n++] = magic;
        sprintf(poll, "--poll=%u", my->timeout);
        argv[n++] = poll;
        if (!my->verbose)
                argv[n++] = "-q";
        else if (my->verbose > 1) {
                size_t lim = my->verbose + 2;
                if (lim > 8)
                        lim = 8;
                snprintf(verbose, lim, "-vvvvvv");
                argv[n++] = verbose;
        }
        if (simics_agent_debug)
                argv[n++] = "--debug";
        wrap_execve(my->argv[0], (char *const *)argv);
        return common_error_response(buf, errno, "execve failed");
}

int
set_poll_response(struct matic_buffer *buf, struct agent *my)
{
        DBG_PRINT(": poll-interval %u ms", buf->head.num);
        my->timeout = buf->head.num;
        buf->head.size = 0;
        buf->head.code |= 1; /* set-poll-interval-ok */
        buf->head.num = 0;
        return 0;
}

int
ticket_discard_response(struct matic_buffer *buf, struct agent *my)
{
        uint32_t *tnv = (uint32_t *)buf->data;
        int n;

        if (buf->head.num < 1)
                return common_error_response(buf, ENOMSG, "No tickets");

        for (n = 0; n < buf->head.num; n++) {
                if (n * sizeof(*tnv) >= buf->head.size)
                        return common_error_response(
                                buf, ENOMSG, "Ticket outside data");
                if (!ticketstore_find(&my->tickets, tnv[n]))
                        return common_error_response(
                                buf, ENOMSG, "ticketstore_find()");
        }
        if (n < buf->head.num)
                return common_error_response(buf, ENOMSG, "ticketstore_find()");

        for (n = 0; n < buf->head.num; n++) {
                struct ticket_desc *ticket =
                        ticketstore_find(&my->tickets, tnv[n]);
                ticketstore_delete(&my->tickets, ticket);
        }
        buf->head.size = 0;
        buf->head.code |= 1; /* ticket-discard-ok */
        buf->head.num = 0;
        return 0;
}

int
ticket_getpos_response(struct matic_buffer *buf, struct agent *my)
{
        struct ticket_position *data = (struct ticket_position *)buf->data;
        struct ticket_desc *ticket =
                ticketstore_find(&my->tickets, buf->head.num);
        if (!ticket)
                return common_error_response(buf, ENOMSG, "ticketstore_find()");

        if (ticket->io) {
                long pos = ftell(ticket->io);
                if (pos == -1)
                        return common_error_response(buf, errno, "ftell()");
                data->offset = (uint64_t)pos;
                data->size = ticket->size;
        } else if (ticket->data) {
                data->offset = ticket->offset;
                data->size = ticket->size;
        } else
                return common_error_response(buf, ENODATA, "No ticket data");

        buf->head.size = sizeof(*data);
        buf->head.code |= 2;    /* set response bits to data response */
        return 0;
}

int
ticket_read_response(struct matic_buffer *buf, struct agent *my)
{
        struct ticket_desc *ticket =
                ticketstore_find(&my->tickets, buf->head.num);
        if (!ticket)
                return common_error_response(buf, ENOMSG, "ticketstore_find()");
        if (!(ticket->access & S_IRUSR))
                return common_error_response(buf, EPERM,
                                             "ticket is write-only");

        size_t len = 0;
        if (ticket->io) {
                len = fread(buf->data, 1, MAX_PAYLOAD_SIZE, ticket->io);
                if (len < MAX_PAYLOAD_SIZE) {
                        int ec = ferror(ticket->io);
                        if (ec) {
                                clearerr(ticket->io);
                                return common_error_response(buf, ec,
                                                             "fread()");
                        }
                }
                if (feof(ticket->io))
                        buf->head.code |= 2; /* ticket-read-last */
                else
                        buf->head.code |= 4; /* ticket-read-more */
        } else if (ticket->data) {
                len = ticket->size - ticket->offset;
                if (len > MAX_PAYLOAD_SIZE)
                        len = MAX_PAYLOAD_SIZE;
                memcpy(buf->data, ticket->data, len);
                ticket->offset += len;
                if (ticket->offset >= ticket->size)
                        buf->head.code |= 2; /* ticket-read-last */
                else
                        buf->head.code |= 4; /* ticket-read-more */
        } else
                return common_error_response(buf, ENODATA, "No ticket data");

        ticket->sent += len;
        buf->head.size = len;
        return 0;
}

int
ticket_setpos_response(struct matic_buffer *buf, struct agent *my)
{
        long offset = (long)buf->u64[0];
        struct ticket_desc *ticket =
                ticketstore_find(&my->tickets, buf->head.num);
        if (!ticket)
                return common_error_response(buf, ENOMSG, "ticketstore_find()");

        if (ticket->io) {
                if (fseek(ticket->io, offset, SEEK_SET))
                        return common_error_response(buf, errno, "fseeko()");
                ticket->offset = (uint64_t)offset;
        } else if (ticket->data) {
                if (offset > ticket->size)
                        ticket->offset = ticket->size;
                ticket->offset = (uint64_t)offset;
        } else
                return common_error_response(buf, ENODATA, "No ticket data");

        buf->head.size = 0;
        buf->head.code |= 1;    /* set response bits to ok response */
        return 0;
}

int
ticket_write_response(struct matic_buffer *buf, struct agent *my)
{
        struct ticket_desc *ticket =
                ticketstore_find(&my->tickets, buf->head.num);
        if (!ticket)
                return common_error_response(buf, ENOMSG, "ticketstore_find()");
        if (!(ticket->access & S_IWUSR))
                return common_error_response(buf, EPERM,
                                             "ticket is read-only");

        if (ticket->io) {
                size_t len = fwrite(buf->data, 1, buf->head.size, ticket->io);
                if (len < buf->head.size) {
                        int ec = ferror(ticket->io);
                        clearerr(ticket->io);
                        return common_error_response(buf, ec, "fwrite()");
                }
                if (buf->head.code & 0x10) {
                        int ec = fflush(ticket->io);
                        if (ec)
                                return common_error_response(buf, ec,
                                                             "fflush()");
                }
        } else if (ticket->data) {
                int rc = buf_copy_data(buf, &ticket->data,
                                       (size_t)ticket->size);
                if (rc)
                        return common_error_response(buf, rc,
                                                     "buf_copy_data()");
        }
        buf->head.code |= 1; /* ticket-write-ok */
        buf->head.size = 0;
        return 0;
}

