from __future__ import print_function
# This Software is part of Wind River Simics. The rights to copy, distribute,
# modify, or otherwise make use of this Software may be licensed only
# pursuant to the terms of an applicable license agreement.
# 
# Copyright 2010-2019 Intel Corporation

from cli import *
from simics import *

def signal_cmd(obj, signal):
    SIM_set_attribute(obj, "signal", signal)

new_command("signal", signal_cmd,
            [arg(int_t, "signal")],
            type  = "symbolic debugging commands",
            short = "tell remote gdb we got a signal",
            cls = "gdb-remote",
            doc = """
Send a <arg>signal</arg> to the remote GDB. See <cite>Using Simics with
GDB</cite> in the <cite>Hindsight User's Guide</cite> for a longer description
of gdb-remote.""")

def disconnect_cmd(obj):
    SIM_set_attribute(obj, "disconnect", 0)

new_command("disconnect", disconnect_cmd,
            [],
            type  = "symbolic debugging commands",
            short = "disconnect from the remote gdb",
            cls = "gdb-remote",
            doc = """
Disconnect from the remote GDB. See <cite>Chapter 14 - Using Simics with
GDB of Hindsight User's Guide</cite> for a longer description of gdb-remote.
""")

def target_cmd(obj, cpu):
    if cpu:
        obj.queue = cpu
        obj.context_object = cpu.iface.context_handler.get_current_context()
    print("Target for %s: %s" % (obj.name, obj.queue))

new_command("target", target_cmd,
            [arg(obj_t('processor', 'processor_info'), "cpu-name", "?")],
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

new_command("follow-context", follow_context_cmd,
            [arg(obj_t('context', 'context'), "context", "?")],
            type = "symbolic debugging commands",
            short = "follow context",
            cls = "gdb-remote",
            doc = """
Set the GDB session to follow <arg>context</arg>.  If <arg>context</arg>
is not specified, the GDB session will stop following any context.""")

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

new_info_command("gdb-remote", get_info)
