/*
  communication.h - Remote GDB connectivity via TCP/IP

  This Software is part of Wind River Simics. The rights to copy, distribute,
  modify, or otherwise make use of this Software may be licensed only
  pursuant to the terms of an applicable license agreement.
  
  Copyright 2010-2019 Intel Corporation
*/

#ifndef COMMUNICATION_H
#define COMMUNICATION_H

#include "gdb-remote.h"

void deactivate_gdb_notifier(gdb_remote_t *gdb);
void activate_gdb_notifier(gdb_remote_t *gdb);
void gdb_disconnect(gdb_remote_t *gdb);
void send_packet(gdb_remote_t *gdb, const char *cmd);
void send_packet_no_log(gdb_remote_t *gdb, const char *cmd);

#endif
