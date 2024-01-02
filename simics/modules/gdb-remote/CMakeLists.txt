# © 2021 Intel Corporation
#
# This software and the related documents are Intel copyrighted materials, and
# your use of them is governed by the express license under which they were
# provided to you ("License"). Unless the License provides otherwise, you may
# not use, modify, copy, publish, distribute, disclose or transmit this software
# or the related documents without Intel's prior written permission.
#
# This software and the related documents are provided as is, with no express or
# implied warranties, other than those that are expressly stated in the License.

file(GLOB gdb_arch_files RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "gdb-arch-*.c")
set(gdb_archs ${gdb_arch_files})
list(TRANSFORM gdb_archs REPLACE "gdb-arch-(.*)\\.c" "\\1")

simics_add_module(gdb-remote
    CLASSES gdb-remote
    SOURCES gdb-remote.c gdb-init-arch.c gdb-recording.c communication.c
            ${gdb_arch_files}
            module_load.py simics_start.py
    INIT_LOCAL
    SIMICS_API latest
)

add_custom_command(
    OUTPUT gdb-init-arch.c
    COMMAND ${SIMICS_PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/make_init_archs.py ${gdb_archs} > gdb-init-arch.c
    DEPENDS make_init_archs.py ${gdb_arch_files}
)

