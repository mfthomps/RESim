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


import cli, simics, conf
from deprecation import DEPRECATED

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

def riscv_arch(cpu):
    bits = 32 if getattr(cpu, 'XLEN', 0) == 32 else 64
    return f'risc-v{bits}'

def get_gdb_arch(cpu):
    if cpu.classname in gdb_archs:
        return gdb_archs[cpu.classname]

    arch = cpu.iface.processor_info.architecture()
    if arch == 'risc-v':
        return riscv_arch(cpu)
    return arch

def get_all_archs(f = lambda cpu: True):
    return set(get_gdb_arch(cpu)
               for cpu in simics.SIM_get_all_processors() if f(cpu))

def get_arch(architecture, cpu, context):
    if architecture:
        if architecture == 'risc-v' and cpu:
            return riscv_arch(cpu)
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

def new_gdb_remote(name, port, cpu, architecture, context, no_rcmd, ipv4):
    if context:
        DEPRECATED(simics.SIM_VERSION_6,
                   "The context argument to new-gdb-remote is deprecated.",
                   "Connect using a CPU instead.");

    if not any([cpu, context]):
        print("No CPU is specified; using current processor.")
        cpu = cli.current_cpu_obj()

    gdb = simics.pre_conf_object(cli.get_available_object_name("gdb"),
                                  "gdb-remote")
    gdb.processor = cpu
    gdb.context_object = context
    gdb.architecture = get_arch(architecture, cpu, context)
    gdb.log_level = 2
    gdb.allow_remote_commands = not no_rcmd

    if ipv4:
        conf.sim.force_ipv4 = ipv4
        DEPRECATED(simics.SIM_VERSION_6,
                   "The -ipv4 flag to new-gdb-remote is deprecated.",
                   "Use sim->force_ipv4 or prefs->force_ipv4 instead.");

    try:
        simics.SIM_add_configuration([gdb], None)
        gdb = simics.SIM_get_object(gdb.name)
        gdb.tcp.port = port
        real_port = gdb.tcp.port
        simics.SIM_log_info(2, gdb, 0,
                            f"Awaiting GDB connections on port {real_port}.")
        simics.SIM_log_info(2, gdb, 0, "Connect from GDB using: \"target "
                            f"remote localhost:{real_port}\"");
    except LookupError as msg:
        raise cli.CliError(f"Failed creating a gdb-remote object: {msg}\n"
                           "Make sure the gdb-remote module is available.")
    except Exception as msg:
        raise cli.CliError(f"Could not create a gdb-remote object: {msg}")
    return cli.command_quiet_return(gdb)

def arch_expander(s): return cli.get_completions(s, get_all_archs())

cli.new_command(
    'new-gdb-remote', new_gdb_remote,
    args = [cli.arg(cli.str_t, 'name', '?', None),
            cli.arg(cli.ip_port_t, 'port', '?', 9123),
            cli.arg(cli.obj_t('processor', 'processor_info'), 'cpu', '?', None),
            cli.arg(cli.str_t, 'architecture', '?', None,
                    expander = arch_expander),
            cli.arg(cli.obj_t('context', 'context'), 'context', '?', None),
            cli.arg(cli.flag_t, '-disallow-remote-commands'),
            cli.arg(cli.flag_t, '-ipv4')],
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

A processor to connect to should be specified using the <arg>cpu</arg>
argument, the GDB session will follow the execution on that particular
processor. It will see all code that runs on that processor: user
processes, operating system, hypervisor, everything. If no
<arg>cpu</arg> argument is given the current cpu object will be used.

The <arg>architecture</arg> argument can be used to specify a
particular architecture for the GDB session. It should be the
architecture name used by Simics and not the GDB architecture name.
For example, if you are debugging a 32-bit program on a 64-bit x86
processor, you may want to specify <tt>x86</tt> as
<arg>architecture</arg> and run <tt>set architecture i386</tt> in GDB
before connecting. 
For 64-bit PowerPC platforms set this argument to <tt>ppc32</tt> to
debug a 32-bit program.
If not given, the architecture of the specified processor will be used.

The <tt>-disallow-remote-commands</tt> argument will prevent the client from
using the <em>monitor</em> command, which sends a <em>qRcmd</em> message, to
perform any Simics CLI command over the remote connection.

In GDB, use the command <b>target remote <i>host</i>:<i>port</i></b>
to connect to Simics.
Upon connection GDB assumes that the simulation is paused. GDB also assumes
that it has full 'run control' (continue, step, next, etc.) and will be
confused if simulation also is controlled by other means, such as using Simics
commands.
""")
