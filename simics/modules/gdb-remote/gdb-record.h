/*
  gdb-record.h

  © 2010 Intel Corporation

  This software and the related documents are Intel copyrighted materials, and
  your use of them is governed by the express license under which they were
  provided to you ("License"). Unless the License provides otherwise, you may
  not use, modify, copy, publish, distribute, disclose or transmit this software
  or the related documents without Intel's prior written permission.

  This software and the related documents are provided as is, with no express or
  implied warranties, other than those that are expressly stated in the License.
*/

#ifndef GDB_RECORD_H
#define GDB_RECORD_H

typedef enum {
        From_Gdb,
        To_Gdb
} gdb_direction_t;

typedef struct {
        gdb_direction_t direction;
        char *packet;
} gdb_record_t;

#endif 
