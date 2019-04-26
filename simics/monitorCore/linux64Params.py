'''
 * This software was created by United States Government employees
 * and may not be copyrighted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
'''

from monitorLibs import utils
'''
Instead of simics-style .params file.  Hardcode limited number of offsets.
'''
class linux64Params():
    kernel_base = 0xffffffff80000000
    kernel_base = kernel_base & 0xFFFFFFFFFFFFFFFF
    cur_task_offset_into_gs = 0xc700
    ts_next = 0x170
    ts_prev = 0x178
    ts_comm = 0x398
    ts_pid = 0x1e4
    ts_parent = 0x200
    ts_real_parent = 0x1f8
    ts_children = 0x208
    ts_state = None
    ts_active_mm = None
    ts_mm = None
    ts_binfmt = None
    ts_tgid = 0x1e8
    ts_group_leader = None
    ts_children_list_head = 0x208
    ts_sibling_list_head = 0x218
    ts_thread_group_list_head = None
    ts_next_relative = True
