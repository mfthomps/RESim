#                                                              -*- Makefile -*-
# Simics module makefile
#

MODULE_CLASSES = gdb-remote

GDB_ARCH_FILES = $(notdir $(wildcard $(SRC_BASE)/$(TARGET)/gdb-arch-*.c))
GDB_ARCHS = $(GDB_ARCH_FILES:gdb-arch-%.c=%)

SRC_FILES = gdb-remote.c gdb-init-arch.c communication.c \
            $(GDB_ARCH_FILES)
PYTHON_FILES := module_load.py simics_start.py

SIMICS_API := latest
THREAD_SAFE:=yes

MODULE_LDFLAGS = $(LIBWIN32) $(LIBSOCKET)

EXTRA_DIST_SRC_FILES:=make_init_archs.py PROTOCOL

include $(MODULE_MAKEFILE)

gdb-init-arch.c: make_init_archs.py $(GDB_ARCH_FILES)
	$(PYTHON) $< $(GDB_ARCHS) > $@
