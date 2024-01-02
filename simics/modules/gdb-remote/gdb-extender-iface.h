/*
  © 2010 Intel Corporation

  This software and the related documents are Intel copyrighted materials, and
  your use of them is governed by the express license under which they were
  provided to you ("License"). Unless the License provides otherwise, you may
  not use, modify, copy, publish, distribute, disclose or transmit this software
  or the related documents without Intel's prior written permission.

  This software and the related documents are provided as is, with no express or
  implied warranties, other than those that are expressly stated in the License.
*/

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
