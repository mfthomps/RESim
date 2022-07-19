from __future__ import print_function
# This Software is part of Wind River Simics. The rights to copy, distribute,
# modify, or otherwise make use of this Software may be licensed only
# pursuant to the terms of an applicable license agreement.
# 
# Copyright 2010-2019 Intel Corporation

import cli, cli_impl, simics

# Mapping between Simics classname and gdb-remote architecture in cases when
# processor_info.architecture() is not specific enough.
gdb_archs = {
    'ppce500':    'ppce500',
    'ppce500-mc': 'ppce500',
    'arc600':     'arc600',
    'arc601':     'arc600',
    'arc605':     'arc600',
    'arc710':     'arc700',
    'nios-ii-r2': 'nios2',
    }

def get_gdb_arch(cpu):
    if cpu.classname in gdb_archs:
        return gdb_archs[cpu.classname]
    else:
        return cpu.iface.processor_info.architecture()

def get_all_archs(f = lambda cpu: True):
    return set(get_gdb_arch(cpu)
               for cpu in simics.SIM_get_all_processors() if f(cpu))

def get_arch(architecture, cpu, context):
    if architecture:
        return architecture
    elif cpu:
        return get_gdb_arch(cpu)
    elif context:
        archs = get_all_archs(lambda cpu: cpu.current_context == context)
        if len(archs) == 0:
            all_archs = get_all_archs()
            if len(all_archs) == 1:
                [arch] = all_archs
                return arch
        elif len(archs) == 1:
            [arch] = archs
            return arch
    raise cli.CliError('Cannot guess processor architecture; please specify it')

def new_gdb_remote(name, port, cpu, architecture, context, no_rcmd):
    if not any([cpu, context]):
        print("Neither CPU nor context specified; using current processor.")
        cpu = cli.current_cpu_obj()
    name = cli_impl.new_object_name(name, 'gdb')
    attrs = [['processor', cpu],
             ['context_object', context],
             ['listen', port],
             ['architecture', get_arch(architecture, cpu, context)],
             ['log_level', 2],
             ['allow_remote_commands', not no_rcmd],]
    try:
        simics.SIM_create_object("gdb-remote", name, attrs)
    except LookupError as msg:
        print("Failed creating a gdb-remote object: %s" % msg)
        print("Make sure the gdb-remote module is available.")
    except Exception as msg:
        print("Could not create a gdb-remote object: %s" % msg)

def arch_expander(s): return cli.get_completions(s, get_all_archs())

cli.new_command(
    'new-gdb-remote', new_gdb_remote,
    args = [cli.arg(cli.str_t, 'name', '?', None),
            cli.arg(cli.ip_port_t, 'port', '?', 9123),
            cli.arg(cli.obj_t('processor', 'processor_info'), 'cpu', '?', None),
            cli.arg(cli.str_t, 'architecture', '?', None,
                    expander = arch_expander),
            cli.arg(cli.obj_t('context', 'context'), 'context', '?', None),
            cli.arg(cli.flag_t, '-disallow-remote-commands')],
    type = ['Symbolic Debugging', 'Debugging'],
    short = 'create a gdb session',
    doc = """
Starts listening to incoming connection requests from GDB sessions
(provided that a configuration has been loaded). Simics will listen to
TCP/IP requests on the port specified by <arg>port</arg>, or 9123 by
default. If <arg>port</arg> is set to zero, an arbitrary free port
will be selected.

The <class>gdb-remote</class> object will get a name assigned
automatically unless one is specified using <arg>name</arg>.

You can either attach the GDB session to a particular processor, or to
a particular context object. If you specify a processor (with the
<arg>cpu</arg> argument), the GDB session will follow the execution on
that particular processor. It will see all code that runs on that
processor: user processes, operating system, hypervisor, everything.

If instead you specify a context (with the <arg>context</arg>
argument), the GDB session will follow that context; this is useful in
combination with process tracking, which can make a context follow a
specific process as it moves between processors, is descheduled, etc.
The end result is that GDB sees that process no matter which process
it runs on, and does not see other processes or the operating system.

The <arg>architecture</arg> argument can be used to specify a
particular architecture for the GDB session. It should be the
architecture name used by Simics and not the GDB architecture name.
For example, if you are debugging a 32-bit program on a 64-bit x86
processor, you may want to specify <tt>x86</tt> as
<arg>architecture</arg> and run <tt>set architecture i386</tt> in GDB
before connecting. 
For 64-bit PowerPC platforms set this argument to <tt>ppc32</tt> to
debug a 32-bit program.
If not given, the architecture of the specified
processor will be used, or the architecture of the processor attached
to the specified context.

The <tt>-disallow-remote-commands</tt> argument will prevent the client from
using the <em>monitor</em> command, which sends a <em>qRcmd</em> message, to
perform any Simics CLI command over the remote connection.

In GDB, use the command <b>target remote <i>host</i>:<i>port</i></b>
to connect to Simics.
Upon connection GDB assumes that the simulation is paused. GDB also assumes
that it has full 'run control' (continue, step, next, etc.) and will be
confused if simulation also is controlled by other means, such as using Simics
commands.""")
