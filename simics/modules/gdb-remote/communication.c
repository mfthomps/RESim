/*
  communication.c - Remote GDB connectivity via TCP/IP

  © 2010 Intel Corporation

  This software and the related documents are Intel copyrighted materials, and
  your use of them is governed by the express license under which they were
  provided to you ("License"). Unless the License provides otherwise, you may
  not use, modify, copy, publish, distribute, disclose or transmit this software
  or the related documents without Intel's prior written permission.

  This software and the related documents are provided as is, with no express or
  implied warranties, other than those that are expressly stated in the License.
*/

#include "communication.h"

#include <simics/util/os.h>
#include <simics/util/vect.h>

#include "gdb-recording.h"

/* Return the length of the packet at the head of the queue, or -1 if the
   packet isn't complete. */
static int
find_packet_len(const char_queue_t *q)
{
        ASSERT(QPEEK(*q) == '$');
        int qlen = QLEN(*q);
        for (int i = 1; i < qlen; i++)
                if (QGET(*q, i) == '#')
                        return i + 3 <= qlen ? i + 3 : -1;
        return -1;
}

/* gdb serial checksum: Add the bytes mod 256. */
static uint8
packet_checksum(const char *buf, size_t len)
{
        uint8 csum = 0;
        for (size_t i = 0; i < len; i++)
                csum += buf[i];
        return csum;
}

/* Parse a hex number of the given size, and return the number, or -1 on
   error. */
static int
parse_hex(const char *s, int len)
{
        int result = 0;
        for (int i = 0; i < len; i++) {
                result <<= 4;
                char c = s[i];
                if (c >= '0' && c <= '9')
                        result |= c - '0';
                else if (c >= 'a' && c <= 'f')
                        result |= c - 'a' + 10;
                else if (c >= 'A' && c <= 'F')
                        result |= c - 'A' + 10;
                else
                        return -1;
        }
        return result;
}

int 
socket_write(gdb_remote_t *gdb, const void *buf, int len)
{
        int sent_len = CALL(gdb->server, write)(
                gdb, (bytes_t){.data = buf, .len = len});
        if (sent_len == len)
                record_data_to_gdb(gdb, buf, len);
        return sent_len;
}

/* Given a gdb command packet, execute it if it's well-formed and has a correct
   checksum; log a warning otherwise. */
static void
parse_packet(gdb_remote_t *gdb, char *buf, size_t len)
{
        ASSERT(len >= 5); /* start+stop markers, 2-digit checksum, at least 1
                             char payload */
        ASSERT(buf[0] == '$');
        ASSERT(buf[len - 3] == '#');
        int checksum_recvd = parse_hex(&buf[len - 2], 2);
        char *payload = &buf[1];
        size_t payload_len = len - 4;
        payload[payload_len] = '\0';
        int checksum_expected = packet_checksum(payload, payload_len);
        if (checksum_expected == checksum_recvd) {
                socket_write(gdb, "+", 1);
                gdb_serial_command(gdb, payload);
        } else {
                socket_write(gdb, "-", 1);
                SIM_LOG_INFO(1, &gdb->obj, 0,
                             "Got packet \"%s\" of length %llu with bad"
                             " checksum. Expected checksum 0x%x, received"
                             " checksum 0x%x; dropping packet",
                             buf, (uint64)len, checksum_expected,
                             checksum_recvd);
        }
}

/* Read some available data into the buffer. Return true if we should
   disconnect after handling any whole packets in the buffer. */
static bool
fill_buffer(gdb_remote_t *gdb)
{
        while (true) {
                uint8 buf[4096];

                /* This call can't block. */
                ssize_t len = CALL(gdb->server, read)(
                        gdb, (buffer_t){.data = buf, .len = sizeof buf});

                if (len == 0) {
                        /* We were disconnected. */
                        return true;
                } else if (len < 0) {
                        if (len == -2)
                                return false; /* no more data available yet */

                        /* Some kind of error occurred. */
                        SIM_LOG_INFO(1, &gdb->obj, 0,
                                     "Lost connection to gdb");
                        return true;
                }

                for (ssize_t i = 0; i < len; i++)
                        QADD(gdb->received, buf[i]);
                return false;
        }
}

/* Read command data from gdb, parse the packets, and carry out the commands in
   them. */
void
read_gdb_data(void *param)
{
        gdb_remote_t *gdb = param;
        bool disconnected = fill_buffer(gdb);
        while (!QEMPTY(gdb->received)) {
                char next = QPEEK(gdb->received);
                if (next == '$') {
                        int len = find_packet_len(&gdb->received);
                        if (len < 0)
                                break;
                        char buf[len];
                        for (int i = 0; i < len; i++)
                                buf[i] = QREMOVE(gdb->received);
                        record_data_from_gdb(gdb, buf, len);
                        parse_packet(gdb, buf, len);
                } else {
                        QDROP(gdb->received, 1);
                        if (next == '\3')
                                handle_ctrl_c(gdb);
                }
        }
        if (disconnected) {
                SIM_LOG_INFO(3, &gdb->obj, 0, "Disconnect request received");
                gdb_disconnect(gdb);
        }
}

void
deactivate_gdb_notifier(gdb_remote_t *gdb)
{
        CALL(gdb->server, notify)(gdb, Sim_NM_Read, Sim_EM_Global, false);
}

void
activate_gdb_notifier(gdb_remote_t *gdb)
{
        CALL(gdb->server, notify)(gdb, Sim_NM_Read, Sim_EM_Global, true);
}

static void
send_packet_common(gdb_remote_t *gdb, const char *cmd, bool do_log)
{
        if (do_log)
                SIM_LOG_INFO(4, &gdb->obj, 0, "Sending packet: \"%s\"", cmd);
        size_t cmd_len = strlen(cmd);
        size_t packet_len = cmd_len + 4;
        char buf[packet_len + 1];
        snprintf(buf, sizeof buf, "$%s#%02x", cmd,
                 (int)packet_checksum(cmd, cmd_len));
        size_t sent_packet_len = socket_write(gdb, buf, packet_len);
        if (do_log && sent_packet_len != packet_len) {
                SIM_LOG_INFO(1, &gdb->obj, 0,
                             "Failed to send packet \"%s\" of length %llu to"
                             " remote gdb", buf, (uint64)packet_len);
        }
}

void
send_packet(gdb_remote_t *gdb, const char *cmd)
{
        send_packet_common(gdb, cmd, true);
}

void
send_packet_no_log(gdb_remote_t *gdb, const char *cmd)
{
        send_packet_common(gdb, cmd, false);
}
