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
import commands
import os
import szk
import hashlib
import xml.etree.ElementTree as ET
import logging
import StringIO
'''
Msc utilities used by monitoring functions
'''
#CSID_SIZE = 10
CSID_SIZE = 15
SUFFIX_SIZE = 3
# for testing failure cases, like Ducklin's EICAR AV name
TEST_DUCK_TEAM_ID = '777'
TEST_DUCK_NAME='CBDUCKL_0000101'
def numBins(cb):
    '''
    get the number of binaries in a cb by parsing its name
    '''
    retval = 1
    last_two = cb[CSID_SIZE-2:CSID_SIZE]
    try:
        retval = int(last_two, 16)
    except:
        pass
    return retval

def getMyIP():
    '''
    Very non-portable 
    '''    
    lines = commands.getoutput("/sbin/ifconfig").split("\n")
    retval = None
    for line in lines:
        #print 'line is '+line
        if line.strip().startswith('inet addr'):
            #print 'has inet addr'
            retval = line.split()[1][5:]
            break
        elif line.strip().startswith('inet '):
            #print 'has inet'
            retval = line.split()[1]
            break
    return retval

def getCSID(cb):
    if cb is not None:
        return cb[0:CSID_SIZE]
    else: 
        return None

def getCommonName(cb):
    # get common name from binary without suffix
    return cb[0:len(cb)-SUFFIX_SIZE]

def getCBSuffix(cb):
    return cb[len(cb)-SUFFIX_SIZE+1:]

def seqFromNode(node):
    base = os.path.basename(node)
    print 'base is '+base
    dum, seq = base.split('_')
    return int(seq) 

def onlyDirs(path):
    only_dirs = []
    if os.path.isdir(path):
        only_dirs = [ d for d in os.listdir(path) if os.path.isdir(os.path.join(path, d)) ]
    return only_dirs

def onlyFiles(path):
    only_files = []
    if os.path.isdir(path):
        only_files = [ f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f)) ]
    return only_files

def getSerialString(serial):
    serial_string = '%05d' % serial
    return serial_string

def pathFromCommon(name):
    '''
    CSID for mitigated is now CBCADET_0000101_MG
    Should not be called for cfe-style naming
    '''
    items  = name.split('_')
    #print 'in pathFromName, %d items, first is %s' % (len(items), items[0])
    path = None
    if not items[0].startswith(szk.CB):
        print 'bad CB name, should start with "%s" %s' % (szk.CB, name)
        return None
    cb_name = items[0]+'_'+items[1] 
    if len(items) == 3 and items[2] != szk.MG:
        print 'bad CB name, competitor CB should be CB_CMP_SER %s' % name
        return None
    if len(items) == 4:
        competitor = items[2]
        path = os.path.join(cb_name, szk.COMPETITOR, competitor, 'cbs', name)
        #path = cb_name+'/'+szk.COMPETITOR+'/'+competitor+'/cbs/'+name+'/'+name
    elif len(items) < 4:
        if len(items)>2 and items[2] == szk.MG:
            #path = cb_name+'/'+szk.AUTHOR+'/'+cb_name+'_'+szk.MG+'/'+cb_name+'_'+szk.MG
            path = os.path.join(cb_name, szk.AUTHOR, cb_name+'_'+szk.MG)
        else:
            #path = cb_name+'/'+szk.AUTHOR+'/'+cb_name+'/'+cb_name
            path = os.path.join(cb_name, szk.AUTHOR, cb_name)
    else:
        print 'bad CB name %s' % name
    return path

def getChecksum(value):
    checksum = hashlib.md5(value).hexdigest()[:16]
    return checksum

def decodePackageClient(data):
    '''
    Get client info from package
    '''
    ret_id = None
    ret_node = None
    data_file = StringIO.StringIO(data)
    tree = ET.parse(data_file)
    entry = tree.find('client')
    try:
        client_id = entry.find('client_id')
    except:
        print('no client_id in %s, data was %s' % (str(entry), data))
        return None, None
    client_node = entry.find('client_node')
    if client_id is not None and client_node is not None:
        ret_id = client_id.text
        ret_node = client_node.text
    else:
        print('utils, decodePackageClient, could not find client info in %s' % data)
    return ret_id, ret_node

def getEncodedPackage(cb, replays, checksum=None, config=None, no_timeout = False, client_id=None, client_node=None, seed = None,
        rules = None, pov_json=None, neg_json=None, team_id=None):
    '''
    Create xml representation of a replay
    '''
    doc = ET.Element('replay_package')
    cb_element = ET.SubElement(doc, 'cb_name')
    cb_element.text = cb
    for replay in replays:
        replay_type = 'pov'
        if replay.startswith(szk.POLL):
            replay_type = 'poll'
        replay_element = ET.SubElement(doc, replay_type)
        replay_element.text = replay
    if checksum is not None:
        checksum_element = ET.SubElement(doc, 'config_checksum')
        checksum_element.text = checksum
    if config is not None:
        config_element = ET.SubElement(doc, 'config_name')
        config_element.text = config
    if no_timeout:
        no_time_element = ET.SubElement(doc, 'no_timeout')
        no_time_element.text = 'TRUE'
    if client_id is not None:
        client_element = ET.SubElement(doc, 'client')
        cid = ET.SubElement(client_element, 'client_id')
        cid.text = client_id
        cn = ET.SubElement(client_element, 'client_node')
        cn.text = client_node
    if seed is not None:
        seed_element = ET.SubElement(doc, 'seed')
        seed_element.text = seed
    if rules is not None:
        rules_element = ET.SubElement(doc, 'rules')
        rules_element.text = rules
    if team_id is not None:
        team_element = ET.SubElement(doc, 'team_id')
        team_element.text = team_id
    if pov_json is not None:
        pov_json_element = ET.SubElement(doc, 'pov_json')
        pov_json_element.text = pov_json
        neg_json_element = ET.SubElement(doc, 'neg_json')
        neg_json_element.text = neg_json
    package = ET.tostring(doc)
    bs = package.encode('latin-1')
    return bs

def getSigned(val):
    if(val & 0x80000000):
        val = -0x100000000 + val
    return val

def getUnsigned(val):
    return val & 0xFFFFFFFF

def getLogger(name, logdir, level=None):
    os.umask(000)
    try:
        os.makedirs(logdir)
    except:
        pass
    lgr = logging.getLogger(name)
    #lhStdout = lgr.handlers[0]
    lgr.setLevel(logging.DEBUG)
    fh = logging.FileHandler(logdir+'/%s.log' % name)
    fh.setLevel(logging.DEBUG)
    frmt = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh.setFormatter(frmt)
    lgr.addHandler(fh)
    #lgr.removeHandler(lhStdout)
    lgr.info('Start of log from %s.py' % name)
    ch = logging.StreamHandler()
    ch.setLevel(logging.ERROR)
    ch.setFormatter(frmt)
    lgr.addHandler(ch)
    #lgr.propogate = False
    return lgr

def jdefault(o):
    return o.__dict__

class protectedAccess():
    def __init__(self, length, location, delta, cpl=1):
        self.length = length
        self.location = location
        self.delta = delta
        self.cpl = cpl
    def toString(self):
        retval = 'len: %d  location %x  delta %x cpl %d' % (self.length, self.location, self.delta, self.cpl)
        return retval

def getTagValue(a_list, tag, delim):
    for item in a_list:
        if delim in item:
            if item.split(delim)[0].strip() == tag:
                return item.split(delim)[1].strip()
    return None
    
def getCommonNameCFE(rcbs):
        '''
        derive common name from cfe-style rcb name.  If it has a second _, it is a multi bin.
        
        '''
        rcb_list = sorted(rcbs, reverse=True)
        base = os.path.basename(rcb_list[0])
        cb_name = base.split('-')[1]
        if cb_name.count('_') == 2:
            ''' multi binary, assume last is count? '''
            parts = cb_name.split('_')
            suffix = parts[2]
            num_bins = '%02d' % int(suffix)
            common = 'CB'+parts[0]+'_'+parts[1]+num_bins
        else:
            common = 'CB'+cb_name+'01'
        return common

def getBinNumFromName(name):
        '''  remove the binary counter from a name '''
        retval = '1'
        parts = name.split('-')
        if len(parts) > 1:
            cb_name = parts[1]
            new_cb_name = cb_name
            parts = cb_name.split('_')
            if len(parts) == 3:
                retval = parts[2]
        return retval

def rmBinNumFromName(name):
        '''  remove the binary counter from a name '''
        retval = name
        parts = name.split('-')
        if len(parts) > 1:
            cb_name = parts[1]
            new_cb_name = cb_name
            parts = cb_name.split('_')
            if len(parts) == 3:
                new_cb_name = parts[0]+'_'+parts[1] 
                retval = name.replace(cb_name, new_cb_name)
        return retval

def getCommonNameSub(name):
    full = getCommonNameCFE([name])
    length = len(full)
    return full[2:length-2]
                           
