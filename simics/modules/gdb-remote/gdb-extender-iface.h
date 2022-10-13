/* This Software is part of Wind River Simics. The rights to copy, distribute,
   modify, or otherwise make use of this Software may be licensed only
   pursuant to the terms of an applicable license agreement.
  
   Copyright 2010-2019 Intel Corporation */

#ifndef GDB_EXTENDER_IFACE_H
#define GDB_EXTENDER_IFACE_H

#include <simics/device-api.h>
#include <simics/pywrap.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* This interface is experimental and might change at any time. Do not use
   without contacting the Simics team first. The gdb-remote module will call
   the handle_command method for an installed "extender" object with all GDB
   command it does support itself. The extender should return with an
   MM_MALLOC()/MM_STRDUP()ed string that will be sent back to GDB as reply to
   the command. If the command isn't supported by the extender, an empty string
   should be returned. */
SIM_INTERFACE(gdb_extender) {
        char *(*handle_command)(conf_object_t *obj, const char *cmd);
};
#define GDB_EXTENDER_INTERFACE "gdb_extender"

#if defined(__cplusplus)
}
#endif

#endif
