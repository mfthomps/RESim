/* This Software is part of Wind River Simics. The rights to copy, distribute,
   modify, or otherwise make use of this Software may be licensed only
   pursuant to the terms of an applicable Wind River license agreement.

   Copyright 2012-2016 Intel Corporation */

#ifdef __linux
#include "util_linux.h"
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <sys/wait.h>

extern char *environ[];

/* Ticket child list element functions */

static inline struct ticket_child *
ticket_elem_to_child(struct dublist_elem *elem)
{
        return (struct ticket_child *)elem;
}

static inline struct ticket_child *
ticket_child_first(struct dublist *list)
{
        return ticket_elem_to_child(list->head);
}

static inline struct ticket_child *
ticket_child_next(struct ticket_child *tc)
{
        return ticket_elem_to_child(tc->elem.next);
}

int
buf_append_ticket_fd(struct matic_buffer *buf, struct agent *my, int fd)
{
        struct ticket_select *sel = &my->sel;
        int n = 0;
        struct ticket_child *tc =
                ticket_child_find_fd(sel, fd, &n);
        struct ticket_desc *td =
                ticketstore_find(&my->tickets, tc->tn[n]);
        int rc = buf_append_ticket(buf, td);
        if (rc)
                return rc;
        buf->head.num++;
        return 0;
}

size_t
dynstr_listdir(char **files, const char *path)
{
        size_t at = 0;
        DBG_PRINT("(%p, '%s'): *files=%p", files, path, *files);
        DIR *d = opendir(path);
        if (!d)
                return 0;

        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
                /* suppress . and .. directories */
                if (e->d_name[0] == '.') {
                        if ((e->d_name[1] == 0) || (e->d_name[1] == '.'))
                                continue;
                }
                at = dynstr_printf(files, at, "%s", e->d_name);
#ifdef _DIRENT_HAVE_D_TYPE
                switch (e->d_type) {
                case 0: /* DT_UNKNOWN */
                case 2: /* DT_CHR */
                case 6: /* DT_BLK */
                case 8: /* DT_REG */
                        break;
                case 1: /* DT_FIFO */
                        at = dynstr_printf(files, at, "|");
                        break;
                case 4: /* DT_DIR */
                        at = dynstr_printf(files, at, "/");
                        break;
                case 10: /* DT_LNK */
                        at = dynstr_printf(files, at, "@");
                        break;
                case 12:
                        at = dynstr_printf(files, at, "=");
                        break;
                default:
                        DBG_PRINT(": unknown type=%d", (int)e->d_type);
                        break;
                }
#endif
                at++;
        }
        closedir(d);
        return at;
}

struct ticket_child *
ticket_child_create(struct ticket_select *sel)
{
        struct ticket_child *tc = calloc(1, sizeof(*tc));
        if (tc) {
                dublist_append(&sel->users, &tc->elem);
        }
        return tc;
}

void
ticket_child_delete(struct ticket_select *sel, struct ticket_child *tc)
{
        dublist_remove(&sel->users, &tc->elem);
        /* Any associated ticket_desc's are not closed nor freed */
        free(tc);
}

int
ticket_child_free(struct ticket_select *sel)
{
        struct ticket_child *tc = ticket_child_first(&sel->users);
        while (tc) {
                struct ticket_child *ntc = ticket_child_next(tc);
                ticket_child_delete(sel, tc);
                tc = ntc;
        }
        return 0;
}

struct ticket_child *
ticket_child_find_fd(struct ticket_select *sel, int fd, int *sd)
{
        struct ticket_child *tc = ticket_child_first(&sel->users);
        while (tc) {
                int n;
                for (n = 0; n < 3; n++) {
                        if (tc->fd[n] != fd)
                                continue;
                        if (sd)
                                *sd = n;
                        return tc;
                }
                tc = ticket_child_next(tc);
        }
        return NULL;
}

static struct ticket_child *
ticket_child_find_pid(struct ticket_select *sel, pid_t pid)
{
        struct ticket_child *tc = ticket_child_first(&sel->users);
        while (tc) {
                if (tc->pid == pid)
                        break;
                tc = ticket_child_next(tc);
        }
        return tc;
}

struct ticket_child *
ticket_child_exited(struct ticket_select *sel)
{
        int stus = 0;
        pid_t ret = waitpid(-1, &stus, WNOHANG);
        if (ret <= 0)
                return NULL;

        struct ticket_child *tc = ticket_child_find_pid(sel, ret);
        if (tc)
                tc->stus = stus;
        return tc;
}

int
ticket_readable_update(struct ticket_select *sel, uint32_t timeout)
{
        fd_set rd;
        fd_set ex;
        struct timeval ts = {
                .tv_sec = timeout / 1000,
                .tv_usec = (timeout % 1000) * 1000,
        };
        memcpy(&rd, &sel->fdset, sizeof(rd));
        memcpy(&ex, &sel->fdset, sizeof(ex));
        int events = select(sel->nfds, &rd, NULL, &ex, &ts);
        if (events < 0)
                return errno;

        memcpy(&sel->rdset, &rd, sizeof(sel->rdset));
        memcpy(&sel->exset, &ex, sizeof(sel->exset));
        sel->nevs = events;
        return 0;
}

void
ticket_selector_init(struct ticket_select *sel)
{
        FD_ZERO(&sel->fdset);
        FD_ZERO(&sel->rdset);
        FD_ZERO(&sel->exset);
}

inline void
sleep_millisec(uint32_t ms)
{
        usleep(ms * 1000);
}

inline int
wrap_execve(const char *filename, char *const *argv)
{
        return execve(filename, argv, environ);
}

#endif /* __linux */
