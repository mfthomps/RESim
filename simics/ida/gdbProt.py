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
import idaapi
import idaversion
import idc
if idaapi.IDA_SDK_VERSION <= 699:
    from idc import Eval as Eval
else:
    from idc import eval_idc as Eval
import time
MAILBOX='mailbox:'
def Evalx(cmd):
    retval = '\n'
    simicsString = Eval(cmd)
    #print "string is %s" % simicsString
    if type(simicsString) is str and simicsString.endswith('None\n'):
        l = len(simicsString) - 5
        #print "len is %d" % l
        if l != 0:
            retval = simicsString[:l]
        else:
            retval = '\n'
    else:
        retval =  simicsString
    return retval

def goToBookmark(mark):
    mark = mark.replace('"', '|')
    command = "@cgc.goToDebugBookmark('%s')" % mark
    print('command is %s' % command)
    simicsString = Evalx('SendGDBMonitor("%s");' % command)
    return simicsString
    
def stripMailbox(msg):
    '''
    intended for use only with results of getEIPWhen stopped, regular mailbox has no
    MAILBOX prefix
    '''
    lines = msg.split('\n')
    for line in reversed(lines):
        if line.startswith(MAILBOX):
            msg = line
            break
    return msg[len(MAILBOX):]

def showSimicsMessage():
    command = '@cgc.idaMessage()' 
    simics_string = Evalx('SendGDBMonitor("%s");' % command)
    print(simics_string)

def getEIPWhenStopped(delay=0, kernel_ok=False):
    done = False
    retval = None
    count = 0
    if delay == 0:
        delay = 1
    while not done:
        count += 1
        if count == 50:
            print("waiting for response from monitor...")
            #idc.Warning("may take a while")
        time.sleep(delay)
        simicsString = Evalx('SendGDBMonitor("@cgc.getEIPWhenStopped(%s)");' % kernel_ok)
        #print 'ready set'
        #print 'getEIPWhenStopped got %s of type %s' % (simicsString, type(simicsString))
        if simicsString is not None and type(simicsString) is str and simicsString != '0' and MAILBOX in simicsString:
            mail = stripMailbox(simicsString)
            #print 'mail is %s' % mail
            if mail == 'exited':
                retval = 0
                print('Process exited')
                done = True
            elif not mail.startswith('ip:'):
                done = True
                try:
                    retval = int(mail[2:], 16)
                except:
                    print('Error: %s' % mail[2:])
                #print 'getEIPWhenStopped found ip of %x, now empty mailbox' % retval
                Evalx('SendGDBMonitor("@cgc.emptyMailbox()");')
            showSimicsMessage()
        else:
            if type(simicsString) is str and not simicsString.strip().startswith('not stopped') \
               and not simicsString.strip().startswith('End of playback'):
                # hack until python logging not sent to stdout on rev module
                simicsString = simicsString.strip()
                if not (simicsString.startswith('[')) and not simicsString.startswith('SystemPerf') \
                       and not simicsString.startswith('Using virtual time'):
                    print('monitor stopped at wrong place: <%s>' % simicsString)
                    done = True
    #print('getEIPWhenStopped returning %x' % retval)
    if count > 50:
        print("Got response from monitor.")
    msg = Evalx('SendGDBMonitor("@cgc.emptyMailbox()");')
    return retval

def stepWait():
    idaversion.step_into()
    event = idaversion.wait_for_next_event(idc.WFNE_ANY, -1)

