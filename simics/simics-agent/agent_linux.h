/* This Software is part of Wind River Simics. The rights to copy, distribute,
   modify, or otherwise make use of this Software may be licensed only
   pursuant to the terms of an applicable Wind River license agreement.

   Copyright 2012-2016 Intel Corporation */

#ifndef AGENT_LINUX_H
#define AGENT_LINUX_H

#include <stdbool.h>
#include <sys/utsname.h>
#include <sys/select.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* Default polling time, in milliseconds */
#define MATIC_POLL_TIME 10000

/* Ticket subprocess descriptor */
struct ticket_child {
        struct dublist_elem elem;       /* dublist element member */
        int fd[3];                      /* pipe file descriptor */
        uint32_t tn[3];                 /* pipe ticket number */
        pid_t pid;                      /* process id */
        int stus;                       /* process status */
};

/* Ticket select descriptor */
struct ticket_select {
        struct dublist users;   /* child subprocess list */
        fd_set fdset;           /* set of selectable file descriptors */
        fd_set rdset;           /* set of readable file descriptor */
        fd_set exset;           /* set of exception file descriptor */
        int nfds;               /* highest fd + 1 in the read set */
        int nevs;               /* number of file descriptor events */
};

#if defined(__cplusplus)
}
#endif

#endif /* AGENT_LINUX_H */
