/*
  gdb-recording.c - Record/playback of socket communication (for test)

  © 2021 Intel Corporation

  This software and the related documents are Intel copyrighted materials, and
  your use of them is governed by the express license under which they were
  provided to you ("License"). Unless the License provides otherwise, you may
  not use, modify, copy, publish, distribute, disclose or transmit this software
  or the related documents without Intel's prior written permission.

  This software and the related documents are provided as is, with no express or
  implied warranties, other than those that are expressly stated in the License.
*/

#include "gdb-recording.h"
#include "gdb-record.h"

static void
record_data(gdb_remote_t *gdb, const char *buf, int len, 
            gdb_direction_t direction)
{
        char *new = MM_ZALLOC(len + 1, char); /* +1 for NUL */
        strncpy(new, buf, len);
        
        gdb_record_t record = {
                .direction = direction,
                .packet = new
        };
        VADD(gdb->record_socket.records, record);
}

/* Raw socket data that are sent from GDB.
   Used to replay a session. */
void
record_data_from_gdb(gdb_remote_t *gdb, const char *buf, int len)
{
        if (!gdb->record_socket.enabled)
                return;
        
        record_data(gdb, buf, len, From_Gdb);
}

/* Raw socket data which gdb-remote returns back to GDB.
   Used to verify a replayed session. */
void
record_data_to_gdb(gdb_remote_t *gdb, const char *buf, int len)
{
        if (!gdb->record_socket.enabled)
                return;

        record_data(gdb, buf, len, To_Gdb);
}

static set_error_t
set_record_socket_enabled(conf_object_t *obj, attr_value_t *val)
{
        gdb_remote_t *gdb = gdb_of_obj(obj);
        gdb->record_socket.enabled = SIM_attr_boolean(*val);
        return Sim_Set_Ok;
}

static attr_value_t
get_record_socket_enabled(conf_object_t *obj)
{
        gdb_remote_t *gdb = gdb_of_obj(obj);
        return SIM_make_attr_boolean(gdb->record_socket.enabled);
}

static attr_value_t
get_records(conf_object_t *obj)
{
        gdb_remote_t *gdb = gdb_of_obj(obj);
        int num_records = VLEN(gdb->record_socket.records);
        attr_value_t ret = SIM_alloc_attr_list(num_records);
        for (int i = 0; i < num_records; i++) {
                gdb_record_t *r = &VGET(gdb->record_socket.records, i);
                SIM_attr_list_set_item(
                        &ret, i,
                        VT_make_attr("[is]", r->direction, r->packet));
        }
        return ret;
}

void 
init_gdb_recording(conf_class_t *cl)
{
        SIM_register_attribute(
                cl, "record_socket_enabled",
                get_record_socket_enabled,
                set_record_socket_enabled,
                Sim_Attr_Pseudo | Sim_Attr_Internal, "b",
                "When set to true, record all socket communication"
                " in the 'records' attribute.");

        SIM_register_attribute(
                cl, "records",
                get_records,
                NULL,
                Sim_Attr_Pseudo | Sim_Attr_Internal, "[[is]*]",
                "Recorded records of the socket communication."
                " used for internal regression testing."
                " [(direction, string)*]");
}
