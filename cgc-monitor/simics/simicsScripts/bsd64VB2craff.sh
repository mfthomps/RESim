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

#wget http://127.0.0.1:8080/~bmc/for-thompson.box
rm -f cgc-freebsd-amd64.img
mv -f cgc-freebsd-amd64.craff cgc-freebsd-amd64.craff.old
rm -f cgc-freebsd-amd64-dev.tar.gz
rm -f cgc-freebsd-amd64-dev.box
wget http://127.0.0.1:8080/boxes/cgc-freebsd-amd64-dev.box
#wget -O cgc-freebsd-dev.box http://127.0.0.1:8080/boxes/cgc-freebsd-dev-failed.box
#wget --user mfthomps --password theeaglehaslanded http://127.0.0.1:8080/jenkins/job/kangaroo-vm/lastSuccessfulBuild/artifact/build-images/cgc-freebsd-dev.box
#wget --user mfthomps --password theeaglehaslanded http://127.0.0.1:8080/jenkins/job/kangaroo-kernel/lastSuccessfulBuild/artifact/kernel.tgz
#mv for-thompson.box cgc-linux-dev.tar.gz
mv cgc-freebsd-amd64-dev.box cgc-freebsd-amd64-dev.tar.gz
tar -xvf cgc-freebsd-amd64-dev.tar.gz
VBoxManage internalcommands converthd -srcformat vmdk -dstformat raw cgc-freebsd-packer-disk1.vmdk cgc-freebsd-amd64.img
bin/craff cgc-freebsd-amd64.img -o cgc-freebsd64.craff
#tar -C /tmp -xvf kernel.tgz boot/kernel/kernel.symbols
#if nm /tmp/boot/kernel/kernel.symbols | sort > /tmp/bsd64-kernel.map; then
#    cp /tmp/bsd64-kernel.map /mnt/vmLib/cgcForensicsRepo/maps_cfe/
#fi
echo "now run ./monitorDev.sh provision_bsd64"
echo "Then run ./monitorDev.sh get_bsd64_symbols"
echo "And then update the checkpoint: ./monitorDev.sh make_snapshot"

