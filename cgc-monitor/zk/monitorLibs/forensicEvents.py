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
'''
enumeration of forensic events and map to printable names.
TBD:  Add read of protected memory
'''
# FROM CQE: USER_NO_X, USER_ROP, USER_SIGSEGV, USER_SIGILL, USER_SIGBUS, USER_MEM_LEAK, USER_SIGALRM, USER_BAD_SYSCALL, USER_SIGKILL, USER_SIGTRAP, USER_SIGFPE, ERRORED_SYSCALLS, POV_1, POV_2, CRITICAL_EVENT, DUCK_NAME_TEST, USER_SIGOTHER, USER_SECCOMP, PLAYER_NO_X, PLAYER_ROP, PLAYER_SIGILL, PLAYER_SIGSEGV, PLAYER_SIGBUS, PLAYER_SIGALRM, PLAYER_SIGKILL, PLAYER_SIGOTHER, PLAYER_SECCOMP, REPLAY_SIGILL, REPLAY_SIGSEGV, REPLAY_SIGALRM, REPLAY_SIGKILL, REPLAY_SIGOTHER, KERNEL_NO_X, KERNEL_ROP, KERNEL_CRED, KERNEL_NOCALL, KERNEL_PAGE_TBL, KERNEL_UNEXPECTED = range(1, 39)
USER_NO_X, USER_ROP, USER_SIGSEGV, USER_SIGILL, USER_SIGBUS, USER_MEM_LEAK, USER_SIGALRM, USER_BAD_SYSCALL, USER_SIGKILL, USER_SIGTRAP, USER_SIGFPE, ERRORED_SYSCALLS, FORCED_QUIT, LAUNCH_ERROR, POV_1, POV_2, PLAYER_NO_X, PLAYER_ROP, PLAYER_SIGILL, PLAYER_SIGSEGV, PLAYER_SIGBUS, PLAYER_SIGALRM, PLAYER_SIGKILL, PLAYER_SIGOTHER,  CRITICAL_EVENT, DUCK_NAME_TEST, USER_SIGOTHER, USER_SECCOMP,  PLAYER_SECCOMP, REPLAY_SIGILL, REPLAY_SIGSEGV, REPLAY_SIGALRM, REPLAY_SIGKILL, REPLAY_SIGOTHER, KERNEL_NO_X, KERNEL_ROP, KERNEL_CRED, KERNEL_NOCALL, KERNEL_PAGE_TBL, KERNEL_UNEXPECTED = range(1, 41)
def isScore(event):
   # note true for 3, 4 or 5.  
   if event in range(3,6):
       return True
   else:
       return False
def stringFromEvent(event):
   if event is USER_NO_X:
       return 'USER_NO_X'
   if event is USER_ROP:
       return 'USER_ROP'
   if event is USER_SIGSEGV:
       return 'USER_SIGSEGV'
   if event is USER_SIGILL:
       return 'USER_SIGILL'
   if event is USER_SIGTRAP:
       return 'USER_SIGTRAP'
   if event is USER_SIGFPE:
       return 'USER_SIGFPE'
   if event is USER_SIGBUS:
       return 'USER_SIGBUS'
   if event is USER_MEM_LEAK:
       return 'USER_MEM_LEAK'
   if event is POV_1:
       return 'POV_1'
   if event is POV_2:
       return 'POV_2'
   if event is USER_SIGKILL:
       return 'USER_SIGKILL'
   if event is ERRORED_SYSCALLS:
       return 'ERRORED_SYSCALLS'
   if event is FORCED_QUIT:
       return 'FORCED_QUIT'
   if event is LAUNCH_ERROR:
       return 'LAUNCH_ERROR'
   if event is USER_SIGALRM:
       return 'USER_SIGALRM'
   if event is USER_BAD_SYSCALL:
       return 'USER_BAD_SYSCALL'
   if event is USER_SIGOTHER:
       return 'USER_SIGOTHER'
   if event is DUCK_NAME_TEST:
       return 'DUCK_NAME_TEST'
   if event is USER_SECCOMP:
       return 'USER_SECCOMP'
   if event is PLAYER_NO_X:
       return 'PLAYER_NO_X'
   if event is PLAYER_ROP:
       return 'PLAYER_ROP'
   if event is PLAYER_SIGSEGV:
       return 'PLAYER_SIGSEGV'
   if event is PLAYER_SIGILL:
       return 'PLAYER_SIGILL'
   if event is PLAYER_SIGBUS:
       return 'PLAYER_SIGBUS'
   if event is PLAYER_SIGKILL:
       return 'PLAYER_SIGKILL'
   if event is PLAYER_SIGALRM:
       return 'PLAYER_SIGALRM'
   if event is PLAYER_SIGOTHER:
       return 'PLAYER_SIGOTHER'
   if event is PLAYER_SECCOMP:
       return 'PLAYER_SECCOMP'
   if event is REPLAY_SIGSEGV:
       return 'REPLAY_SIGSEGV'
   if event is REPLAY_SIGILL:
       return 'REPLAY_SIGILL'
   if event is REPLAY_SIGKILL:
       return 'REPLAY_SIGKILL'
   if event is REPLAY_SIGALRM:
       return 'REPLAY_SIGALRM'
   if event is REPLAY_SIGOTHER:
       return 'REPLAY_SIGOTHER'
   if event is KERNEL_NO_X:
       return 'KERNEL_NO_X'
   if event is KERNEL_ROP:
       return 'KERNEL_ROP'
   if event is KERNEL_CRED:
       return 'KERNEL_CRED'
   if event is KERNEL_NOCALL:
       return 'KERNEL_NOCALL'
   if event is KERNEL_PAGE_TBL:
       return 'KERNEL_PAGE_TBL'
   if event is KERNEL_UNEXPECTED:
       return 'KERNEL_UNEXPECTED'
