/* This Software is part of Wind River Simics. The rights to copy, distribute,
   modify, or otherwise make use of this Software may be licensed only
   pursuant to the terms of an applicable Wind River license agreement.

   Copyright 2012-2016 Intel Corporation */

#ifndef AGENT_WIN32_H
#define AGENT_WIN32_H

#include <windows.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* Default polling time, in milliseconds, for Windows
 * This is lower than on Linux because the Windows console is graphical and
 * thus runs slower. The value is meant to give the perception of the same
 * polling interval in real time.
 */
#define MATIC_POLL_TIME 1000

/* POSIX error codes */
#ifndef ENOMSG
 #define ENOMSG 42
#endif
#ifndef EBADR
 #define EBADR 53
#endif
#ifndef EBADRQC
 #define EBADRQC 56
#endif
#ifndef ENODATA
 #define ENODATA 61
#endif
#ifndef EMSGSIZE
 #define EMSGSIZE 90
#endif
#ifndef EPROTONOSUPPORT
 #define EPROTONOSUPPORT 93
#endif

typedef int bool;
#define false 0
#define true 1

/* Override function for WIN32 specific alternative */
#define chmod(path, mode) _chmod(path, mode)
#define getcwd(buf, size) _getcwd(buf, size)

/* POSIX uname structure */
struct utsname {
        const char *sysname;    /* Operating system name (e.g., "Linux") */
        const char *nodename;   /* Name within "some implementation-defined
                                   network" */
        const char *release;    /* OS release (e.g., "2.6.28") */
        const char *version;    /* OS version */
        const char *machine;    /* Hardware identifier */
};

int uname(struct utsname *sys);

#if defined(__cplusplus)
}
#endif

#endif /* AGENT_WIN32_H */
