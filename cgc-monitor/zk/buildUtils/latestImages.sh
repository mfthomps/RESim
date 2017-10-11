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

#
# to be run on each host, ensures that the latest disk images
# and checkpoints are copied from the NFS to the local host
#
here=`pwd`
cd /mnt/simics/simicsWorkspace

doMove()
{
   DISK_IMAGE=/mnt/vmLib/bigstuff/$CKPT
   if [ -f "$DISK_IMAGE" ]; then
       atomicCp.sh $DISK_IMAGE ./$CKPT
       tar -xvf ./$CKPT
   fi
}


#CRAFF=cgc-freebsd.craff
#DISK_IMAGE=/mnt/vmLib/bigstuff/$CRAFF
#atomicCp.sh $DISK_IMAGE ./$CRAFF

CRAFF=cgc-freebsd64.craff
DISK_IMAGE=/mnt/vmLib/bigstuff/$CRAFF
atomicCp.sh $DISK_IMAGE ./$CRAFF

#CRAFF=cgc-linux.craff
#DISK_IMAGE=/mnt/vmLib/bigstuff/$CRAFF
#atomicCp.sh $DISK_IMAGE ./$CRAFF

#CRAFF=cgc-linux64.craff
#DISK_IMAGE=/mnt/vmLib/bigstuff/$CRAFF
#atomicCp.sh $DISK_IMAGE ./$CRAFF

#CKPT=cgc3_mixed_klk_snapshot.ckpt.tar
#doMove

#CKPT=cgc3_mixed_klk64_snapshot.ckpt.tar
#doMove

#CKPT=cgc3_mixed_dld_snapshot.ckpt.tar
#doMove

#CKPT=cgc3_mixed_llk_snapshot.ckpt.tar
#doMove

#CKPT=cgc3_mixed_lld_snapshot.ckpt.tar
#doMove

#CKPT=cgc3_snapshot.ckpt.tar
#doMove

#CKPT=cgc1_snapshot.ckpt.tar
#doMove

CKPT=cgc3_bsd64_snapshot.ckpt.tar
doMove

#CKPT=cgc1_bsd_snapshot.ckpt.tar
#doMove

cd $here
