from __future__ import print_function
# This Software is part of Wind River Simics. The rights to copy, distribute,
# modify, or otherwise make use of this Software may be licensed only
# pursuant to the terms of an applicable license agreement.
# 
# Copyright 2010-2019 Intel Corporation

import sys

archs = [a.replace('-', '_') for a in sys.argv[1:]]
structs = ["gdb_arch_" + a for a in archs]

print('#include "gdb-remote.h"')

for s in structs:
    print("extern const gdb_arch_t %s;" % (s,))
print()
print("const gdb_arch_t *const gdb_archs[] = {")
for s in structs:
    print("        &%s," % (s,))
print("        NULL")
print("};")
