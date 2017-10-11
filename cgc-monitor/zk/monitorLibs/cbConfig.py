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
import subprocess
import shlex
import os
import sys
'''
    Create a CB configuration file using the readcgcef program to parse the elf header for section information
'''
def cbConfig(prog):
    if not os.path.isfile(prog):
        print 'cbConfig could not find file at %s, skipping **************.' % prog
        return None
    readcgcef = 'readcgcef-minimal.py %s' % prog
    buildCfg = 'buildCfg2.py'
    #print 'readcgcef is %s    buildCfg is %s' % (readcgcef, buildCfg)
    try:
        proc1 = subprocess.Popen(shlex.split(readcgcef),stdout=subprocess.PIPE)
        #print 'proc1 worked'
        proc2 = subprocess.Popen(shlex.split(buildCfg),stdin=proc1.stdout,
                         stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    except:
        print 'FAILURE'
        print 'could not properly run readcgcef... is it installed?  Run from host with '
        print 'the appropriate CGC packages installed.'
        print 'FAILURE'
        exit(1)

    proc1.stdout.close() # Allow proc1 to receive a SIGPIPE if proc2 exits.
    out,err=proc2.communicate()
    return out
