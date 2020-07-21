/* This Software is part of Wind River Simics. The rights to copy, distribute,
   modify, or otherwise make use of this Software may be licensed only
   pursuant to the terms of an applicable Wind River license agreement.

   Copyright 2012-2016 Intel Corporation */

#ifdef __linux
#include "util_linux.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <time.h>

#ifndef CLOCK_REALTIME_COARSE
#define CLOCK_REALTIME_COARSE CLOCK_REALTIME
#endif

const char *sys_cap = "C99,LINUX,POSIX,SHELL,EXEC";

bool
async_event_response(struct matic_buffer *buf, struct agent *my,
                     uint32_t timeout)
{
        struct ticket_select *sel = &my->sel;
        int fd;

        DBG_PRINT("%p, %p, %u)", buf, my, timeout);
        if (!sel->nevs) {
                int rc = ticket_readable_update(&my->sel, timeout);
                if (rc) {
                        buf->head.code = 0x1820; /* process-poll */
                        common_error_response(buf, rc, "select()");
                        return true;
                }
                if (!sel->nevs)
                        return false;
        }

        buf->head.size = 0;
        buf->head.num = 0;

        for (fd = 3; fd < sel->nfds; fd++) {
                if (FD_ISSET(fd, &sel->exset)) {
                        if (buf_append_ticket_fd(buf, my, fd))
                                break;
                        FD_CLR(fd, &sel->exset);
                        sel->nevs--;
                }
        }
        if (buf->head.num > 0) {
                buf->head.code = 0x182c; /* exception in pipe */
                return true;
        }
        buf->head.code = 0x1823; /* ticket response */
        for (fd = 3; fd < sel->nfds; fd++) {
                if (FD_ISSET(fd, &sel->rdset)) {
                        if (buf_append_ticket_fd(buf, my, fd))
                                break;
                        FD_CLR(fd, &sel->rdset);
                        sel->nevs--;
                }
        }
        return true;
}

bool
async_exit_response(struct matic_buffer *buf, struct agent *my)
{
        struct ticket_select *sel = &my->sel;
        struct ticket_child *tc = ticket_child_exited(sel);
        if (!tc)
                return false;

        DBG_PRINT("%p, %p)", buf, my);
        if (WIFSIGNALED(tc->stus)) {
                buf->head.code = 0x182d;  /* died response */
                buf->head.num = WTERMSIG(tc->stus);
        } else if (WIFEXITED(tc->stus)) {
                buf->head.code = 0x1824;    /* exited response */
                buf->head.num = WEXITSTATUS(tc->stus);
        } else
                return false; /* ignore non-terminated statuses */

        buf->head.size = 0;

        int n;
        for (n = 0; n < 3; n++) {
                struct ticket_desc *td =
                        ticketstore_find(&my->tickets, tc->tn[n]);
                buf_append_ticket(buf, td);
                /* Assume all three tickets fit in one buffer, but it's ok if
                   they don't */
        }
        ticket_child_delete(sel, tc);
        return true;
}

int
get_time_response(struct matic_buffer *buf, struct agent *my)
{
        struct timespec ts;

        int rc = clock_gettime(CLOCK_REALTIME_COARSE, &ts);
        if (rc == -1)
                return common_error_response(buf, errno, "clock_gettime()");

        struct tm *tm = gmtime(&ts.tv_sec);
        if (!tm)
                return common_error_response(buf, ENODATA, "localtime()");

        buf->head.size = strftime(buf->data, MAX_PAYLOAD_SIZE,
                                  "%a, %d %b %Y %T %z", tm);
        if (!buf->head.size)
                return common_error_response(buf, EMSGSIZE, "strftime()");

        buf->head.code |= 2; /* get-time-response */
        buf->head.num = 0;
        buf->head.size++;
        return 0;
}

static int
pexec_sub(int argc, char **argv, int pipes[3][2])
{
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	dup(pipes[0][0]);
	dup(pipes[1][1]);
	dup(pipes[2][1]);

	int x, y;
	for (x = 0; x < 3; x++)
		for (y = 0; y < 2; y++)
			close(pipes[x][y]);

        execve(argv[0], argv, NULL);
        return errno; /* A successful call does not return */
}

static int
fixup_pexec_ticket(struct ticket_desc *td, struct ticket_child *tc,
                   int fd, int sn)
{
        tc->fd[sn] = fd;
        tc->tn[sn] = td->id;
        td->fd = fd;
        td->io = fdopen(fd, sn ? "r" : "a");
        td->req_code = 0x1810;
        if (sn)
                td->access = S_IRUSR;
        else
                td->access = S_IWUSR;
        if (!td->io)
                return errno;
        return 0;
}

static int
pexec(struct agent *my, int argc, char **argv, struct ticket_desc **tdv)
{
        static const char *pipe_name[3] = {
                "stdin", "stdout", "stderr"
        };
        int n;

        DBG_PRINT("(%p, %d, %p, %p) exec '%s'", my, argc, argv, tdv, argv[0]);
        for (n = 0; n < 3; n++) {
                tdv[n] = ticketstore_create(&my->tickets, pipe_name[n]);
                if (!tdv[n])
                        goto burn_tickets;
        }
        DBG_PRINT("; tickets created (%d)", n);

        int pipes[3][2] = { { 0, 0 }, { 0, 0 }, { 0, 0 } };
        for (n = 0; n < 3; n++) {
                int rc = pipe(pipes[n]);
                if (rc < 0)
                        goto clean_pipes;
        }
        DBG_PRINT("; pipes created (%d)", n);

        pid_t cpid = fork();
        if (cpid) {
                struct ticket_child *tc = ticket_child_create(&my->sel);
                if (!tc)
                        goto clean_pipes;
                tc->pid = cpid;
                DBG_PRINT("; child created (%u)", (uint32_t)cpid);

                /* stdin */
                close(pipes[0][0]);
                if (fixup_pexec_ticket(tdv[0], tc, pipes[0][1], 0))
                        goto clean_pipes;
                /* stdout */
                close(pipes[1][1]);
                if (fixup_pexec_ticket(tdv[1], tc, pipes[1][0], 1))
                        goto clean_pipes;
                /* stderr */
                close(pipes[2][1]);
                if (fixup_pexec_ticket(tdv[2], tc, pipes[2][0], 2))
                        goto clean_pipes;
                return 0;
        }
        /* Only the child comes here! */
        return pexec_sub(argc, argv, pipes);

  clean_pipes:
        DBG_PRINT("; clean pipes");
        for (n = 0; n < 3; n++) {
                if (pipes[n][0])
                        close(pipes[n][0]);
                if (pipes[n][1])
                        close(pipes[n][1]);
        }
  burn_tickets:
        DBG_PRINT("; burn tickets");
        for (n = 0; n < 3; n++) {
                if (tdv[n])
                        ticketstore_delete(&my->tickets, tdv[n]);
        }
        return errno;
}

int
process_exec_response(struct matic_buffer *buf, struct agent *my)
{
        if (buf->head.num < 1)
                return common_error_response(buf, errno,
                                             "no command line arguments");

        size_t offs = 0;
        char **argv = buf_string_array(buf->data, &offs, buf->head.num);
        DBG_PRINT(": argv[0]='%s' argc=%u", argv[0], buf->head.num);
        struct ticket_desc *tdv[3] = { NULL, NULL, NULL };

        int rc = pexec(my, buf->head.num, argv, tdv);
        DBG_PRINT("; pexec() returned %d", rc);
        if (rc)
                return common_error_response(buf, rc,
                                             "process_exec_response()");

        /* Create response message */
        buf->head.code |= 3;    /* set response bits to ticket response */
        buf->head.size = 0;
        buf->head.num = 0;

        int n;
        for (n = 0; n < 3; n++) {
                rc = buf_append_ticket(buf, tdv[n]);
                if (!rc)
                        buf->head.num++;
        }
        DBG_PRINT("; Wrote %u tickets to the response buffer", buf->head.num);
        return 0;
}

int
process_poll_response(struct matic_buffer *buf, struct agent *my)
{
        if (async_exit_response(buf, my))
                return 0;
        if (!async_event_response(buf, my, 0)) {
                /* give an empty response */
                buf->head.code |= 3;    /* ticket response */
                buf->head.size = 0;
                buf->head.num = 0;
        }
        return 0;
}

int
set_time_response(struct matic_buffer *buf, struct agent *my)
{
        struct timespec ts = {
                .tv_sec = buf->u64[0],
                .tv_nsec = buf->head.num * 1000000, /* milliseconds */
        };

        if (clock_settime(CLOCK_REALTIME, &ts))
                return common_error_response(buf, errno, "clock_settime()");

        buf->head.size = 0;
        buf->head.num = 0;
        buf->head.code |= 1; /* set-time-ok */
        return 0;
}

#endif /* __linux */
