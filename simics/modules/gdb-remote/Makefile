# -*- Makefile -*-

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

# Simics module makefile

MODULE_CLASSES = gdb-remote

GDB_ARCH_FILES = $(notdir $(wildcard $(SRC_BASE)/$(TARGET)/gdb-arch-*.c))
GDB_ARCHS = $(GDB_ARCH_FILES:gdb-arch-%.c=%)

SRC_FILES = gdb-remote.c gdb-init-arch.c gdb-recording.c communication.c \
            $(GDB_ARCH_FILES)
PYTHON_FILES := module_load.py simics_start.py

SIMICS_API := latest
THREAD_SAFE:=yes

MODULE_LDFLAGS = $(LIBWIN32) $(LIBSOCKET)

EXTRA_DIST_SRC_FILES:=make_init_archs.py PROTOCOL

include $(MODULE_MAKEFILE)

gdb-init-arch.c: make_init_archs.py $(GDB_ARCH_FILES)
	$(PYTHON) $< $(GDB_ARCHS) > $@
