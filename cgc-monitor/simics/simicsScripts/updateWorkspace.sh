#!/bin/bash
:<<'END_COMMENT'
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
END_COMMENT

/mnt/simics/simics-4.8/simics-4.8.170/bin/workspace-setup --ignore-existing-files
ln -s ../simicsWorkspace/cgc-linux.craff
ln -s ../simicsWorkspace/cgc-linux64.craff
ln -s ../simicsWorkspace/cgc-freebsd.craff
ln -s ../simicsWorkspace/cgc1_bsd_snapshot.ckpt
ln -s ../simicsWorkspace/cgc3_bsd_snapshot.ckpt
ln -s ../simicsWorkspace/cgc1_snapshot.ckpt
ln -s ../simicsWorkspace/cgc3_snapshot.ckpt
ln -s ../simicsWorkspace/cgc3_mixed_klk_snapshot.ckpt
ln -s ../simicsWorkspace/cgc3_mixed_llk_snapshot.ckpt
ln -s ../simicsWorkspace/cgc3_mixed_lld_snapshot.ckpt
ln -s ../simicsWorkspace/cgc3_mixed_dld_snapshot.ckpt
