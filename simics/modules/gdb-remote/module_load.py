# © 2010 Intel Corporation
#
# This software and the related documents are Intel copyrighted materials, and
# your use of them is governed by the express license under which they were
# provided to you ("License"). Unless the License provides otherwise, you may
# not use, modify, copy, publish, distribute, disclose or transmit this software
# or the related documents without Intel's prior written permission.
#
# This software and the related documents are provided as is, with no express or
# implied warranties, other than those that are expressly stated in the License.


import cli
import simics

def signal_cmd(obj, signal):
    simics.SIM_set_attribute(obj, "signal", signal)

cli.new_command("signal", signal_cmd,
            [cli.arg(cli.int_t, "signal")],
            type  = "symbolic debugging commands",
            short = "tell remote gdb we got a signal",
            cls = "gdb-remote",
            doc = """
Send a <arg>signal</arg> to the remote GDB. See <cite>Using Simics with
GDB</cite> in the <cite>Simics User's Guide</cite> for a longer description
of gdb-remote.""")

def disconnect_cmd(obj):
    simics.SIM_set_attribute(obj, "disconnect", 0)

cli.new_command("disconnect", disconnect_cmd,
            [],
            type  = "symbolic debugging commands",
            short = "disconnect from the remote gdb",
            cls = "gdb-remote",
            doc = """
Disconnect from the remote GDB. See <cite>Chapter 14 - Using Simics with
GDB of Simics User's Guide</cite> for a longer description of gdb-remote.
""")

def target_cmd(obj, cpu):
    if cpu:
        obj.processor = cpu
        obj.context_object = cpu.iface.context_handler.get_current_context()
    print("Target for %s: %s" % (obj.name, obj.processor))

cli.new_command("target", target_cmd,
            [cli.arg(cli.obj_t('processor', 'processor_info'), "cpu-name", "?")],
            type = "symbolic debugging commands",
            short = "set target CPU for gdb connection",
            cls = "gdb-remote",
            doc = """
Set the target processor for the remote GDB connection to <arg>cpu-name</arg>.
A GDB connection can only debug instructions on a single CPU at a time.
""")

def follow_context_cmd(gdb, ctxt):
    if ctxt is None:
        if gdb.follow_context:
            print("Stopped following %s." % gdb.context_object)
            gdb.follow_context = 0
        else:
            print("Not following any context.")
    else:
        gdb.context_object = ctxt
        gdb.follow_context = 1
        print("Started following %s." % ctxt)

cli.new_command("follow-context", follow_context_cmd,
            [cli.arg(cli.obj_t('context', 'context'), "context", "?")],
            type = "symbolic debugging commands",
            short = "follow context",
            cls = "gdb-remote",
            deprecated_version = simics.SIM_VERSION_6,
            deprecated = True,
            doc = """
Set the GDB session to follow <arg>context</arg>.  If <arg>context</arg>
is not specified, the GDB session will stop following any context.""")

def record_start_cmd(gdb):
    gdb.record_socket_enabled = True

cli.new_unsupported_command(
    "record-start",
    "internals",
    record_start_cmd,
    args = [],
    type = "symbolic debugging commands",
    short = "record socket communication (for testing)",
    cls = "gdb-remote",
    doc = """Starts recording everything on the socket between
    gdb and gdb-remote, used for regression testing.""")

def record_stop_cmd(gdb, filename):
    # Responses from gdb-remote is often divided into two records.
    # Merge these to one element
    def merge_sequential_toGdb_messages(records):
        merged = []
        for direction, text in records:
            if (len(merged) > 0
                and direction == 1
                and direction == merged[-1][0]):
                merged[-1][1] += text
            else:
                merged.append([direction, text])
        return merged

    if filename:
        with open(filename, "w") as f:
            for (direction, packet) in merge_sequential_toGdb_messages(
                    gdb.records):
                if direction == 0:      # From gdb
                    f.write(f"<fromGdb>{packet}</fromGdb>\n")
                elif direction == 1:    # Response back to gdb
                    f.write(f"<toGdb>{packet}</toGdb>\n")
                else:
                    assert 0
    gdb.record_socket_enabled = False

cli.new_unsupported_command(
    "record-stop",
    "internals",
    record_stop_cmd,
    args = [
        cli.arg(cli.filename_t(), "file", "?", ""),
    ],
    type = "symbolic debugging commands",
    short = "stop recording socket communication",
    cls = "gdb-remote",
    doc = """Stop the recording and possibly save the recorded
    session to the <arg>file</arg>.""")

def get_info(gdb):
    """Return information about gdb object as list of (doc, value)
    tuples."""
    return ([ (None,
               [ ("Architecture",       gdb.architecture),
                 ("Listen port",        gdb.listen),
                 ("Processor",          gdb.processor),
                 ("Context",            gdb.context_object),
                 ("Follow context",     ("enabled" if gdb.follow_context
                                         else "disabled")),
                 ] )
              ])

cli.new_info_command("gdb-remote", get_info)
