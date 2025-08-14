import os
import sys
import time
import logging
import subprocess
import elfText
import json
import re
import fnmatch
import winProg
import ntpath
import targetFS
import winTargetFS
try:
    import importlib
except:
    ''' must be py 2.7 '''
    import imp 
    pass
try:
    import ConfigParser
except:
    import configparser as ConfigParser

def getLogger(name, logdir, level=None):
    os.umask(000)
    try:
        os.makedirs(logdir)
    except:
        pass

    log_level = logging.DEBUG
    log_level_env = os.getenv('RESIM_LOG_LEVEL')
    if log_level_env is not None and log_level_env.lower() == 'info':
        log_level = logging.INFO
        
    lgr = logging.getLogger(name)
    #lhStdout = lgr.handlers[0]
    lgr.setLevel(log_level)
    fh = logging.FileHandler(logdir+'/%s.log' % name)
    fh.setLevel(log_level)
    frmt = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh.setFormatter(frmt)
    lgr.addHandler(fh)
    #lgr.removeHandler(lhStdout)
    lgr.info('Start of log from %s' % name)
    ch = logging.StreamHandler()
    ch.setLevel(logging.ERROR)
    ch.setFormatter(frmt)
    lgr.addHandler(ch)
    #lgr.propogate = False
    return lgr

def isParallel():
    ''' Determine if the current workspace is a parallel clone '''
    here = os.getcwd()
    ws = os.path.basename(here)
    if ws.startswith('resim_') and os.path.exists('resim_ctl.fifo'):
        return True
    else:
        return False

def getIdaDataFromIni(prog, ini, lgr=None):
    retval = None
    resim_ida_data = os.getenv('RESIM_IDA_DATA')
    root_fs = getIniTargetValue(ini, 'RESIM_ROOT_PREFIX')
    if resim_ida_data is None:
        print('ERROR: RESIM_IDA_DATA not defined')
    elif root_fs is None:
        print('ERROR: RESIM_ROOT_PREFIX not defined')
    else:
        if '/' in prog:
            prog_relative = prog
        else:
            full_prog = getFullPath(prog, ini, lgr=lgr)
            if full_prog is None:
                print('ERROR no path found for prog %s' % prog)
                return retval
            prog_relative = full_prog[len(root_fs)+1:]
        base = os.path.basename(root_fs)
        root_parent = os.path.basename(os.path.dirname(root_fs))
        #retval = os.path.join(resim_ida_data, base, prog, prog)
        retval = os.path.join(resim_ida_data, root_parent, base, prog_relative)
    return retval

def getIdaData(full_path, root_prefix, lgr=None):
    ''' get the ida data path from various forms of full path'''
    retval = None
    resim_ida_data = os.getenv('RESIM_IDA_DATA')
    if resim_ida_data is None:
        print('ERROR: RESIM_IDA_DATA not defined')
        if lgr is not None:
            lgr.error('RESIM_IDA_DATA not defined')
            return None
    resim_image = os.getenv('RESIM_IMAGE')
    if resim_image is None:
        print('ERROR: RESIM_IMAGE not defined')
        return None
    ida_analysis = os.getenv('IDA_ANALYSIS')
    if ida_analysis is None:
        print('ERROR: IDA_ANALYSIS not defined')
        return None
    if full_path.startswith(resim_image):
        # given path was a full path relative to RESIM_IMAGE
        offset = len(resim_image)+1
        remain = full_path[offset:]
        retval = os.path.join(resim_ida_data, remain)
        if lgr is not None:
            lgr.debug('getIdaData is image path full_path %s, remain %s return %s' % (full_path, remain, retval))
    elif full_path.startswith(ida_analysis):
        # TBD just returning same path?
        offset = len(ida_analysis)+1
        remain = full_path[offset:]
        retval = os.path.join(resim_ida_data, remain)
        if lgr is not None:
            lgr.debug('getIdaData is analysis path full_path %s, remain %s return %s' % (full_path, remain, retval))

    else: 
        if lgr is not None:
            lgr.debug('full_path %s' % full_path)
        base = os.path.basename(full_path)
        root_base = os.path.basename(root_prefix)
        root_parent = os.path.basename(os.path.dirname(root_prefix))
        if lgr is not None:
            lgr.debug('root_prefix %s' % root_prefix)
        new_path = os.path.join(resim_ida_data, root_parent, root_base, base)
        if lgr is not None:
            lgr.debug('new %s' % new_path)
        if not os.path.isdir(new_path): 
            retval = os.path.join(new_path, base)
            if lgr is not None:
                lgr.debug('Using new style ida data path %s' % retval)
        else:
            retval = os.path.join(new_path, base)
            if lgr is not None:
                lgr.debug('no existing ida data path %s' % retval)
        
    return retval

def doLoad(module, path):
    #print('version is %d %d' % (sys.version_info[0], sys.version_info[1]))
    if sys.version_info[0] == 3:
        spec = importlib.util.spec_from_file_location(module, path)
        retval = importlib.util.module_from_spec(spec)
        sys.modules[module] = retval
        spec.loader.exec_module(retval)
    else: 
        retval = imp.load_source(module, path)
    return retval

def getPacketFilter(packet_filter, lgr):
    retval = None
    if packet_filter is not None:
        file_path = './%s.py' % packet_filter
        abs_path = os.path.abspath(file_path)
        if os.path.isfile(abs_path):
            retval = doLoad(packet_filter, abs_path)
            lgr.debug('afl using AFL_PACKET_FILTER %s' % packet_filter)
        else:
            file_path = './%s' % packet_filter
            abs_path = os.path.abspath(file_path)
            if os.path.isfile(abs_path):
                retval = doLoad(packet_filter, abs_path)
                lgr.debug('afl using AFL_PACKET_FILTER %s' % packet_filter)
            else:
                lgr.error('failed to find filter at %s' % packet_filter)
                raise Exception('failed to find filter at %s' % packet_filter)
    return retval

def getBasicBlocks(prog, ini=None, lgr=None, root_prefix=None, os_type=None):
    blocks = None
    lgr.debug('getBasicBlocks prog %s' % prog)
    analysis_path = getAnalysisPath(ini, prog, root_prefix=root_prefix, lgr=lgr)
    #print('analysis_path at %s' % analysis_path)
    if lgr is not None:
        lgr.debug('getBasicBlocks analysis_path %s' % analysis_path)
    prog_elf = None
    if os_type is None:
        os_type = getIniTargetValue(ini, 'OS_TYPE')
    if analysis_path is not None:
        prog_path = getProgPathFromAnalysis(analysis_path, ini, lgr=lgr, root_prefix=root_prefix) 
        if lgr is not None:
            lgr.debug('getBasicBlocks got prog_path %s' % prog_path)
        #print('getBasicBlocks got prog_path %s' % prog_path)
        if os_type.startswith('WIN'):
            if lgr is not None:
                lgr.debug('is windows')
            prog_elf = winProg.getText(prog_path, lgr)
        else:
            prog_elf = elfText.getText(prog_path, lgr)
        #print('prog addr 0x%x size %d' % (prog_elf.text_address, prog_elf.text_size))
        if lgr is not None:
            if prog_elf.text_start is not None:
                lgr.debug('prog text_start 0x%x text_size %d' % (prog_elf.text_start, prog_elf.text_size))
            else:
                lgr.debug('prog text_start is None for %s' % prog_path)
        block_file = analysis_path+'.blocks'
        #print('block file is %s' % block_file)
        if not os.path.isfile(block_file):
            if lgr is not None:
                   lgr.debug('block file not found %s, see if it is a link?' % block_file)
            if os.path.islink(prog_file):
                real = os.readlink(prog_file)
                parent = os.path.dirname(prog_file)
                block_file = os.path.join(parent, (real+'.blocks'))
                if not os.path.isfile(block_file):
                    if lgr is not None:
                       lgr.debug('block file not found %s' % block_file)
                    print('block file not found %s' % block_file)
                    return
            else:
               print('block file (or link) not found %s' % block_file)
               return
        with open(block_file) as fh:
            blocks = json.load(fh)
    return blocks, prog_elf

def getOneBasicBlock(prog, addr, os_type, root_prefix, lgr=None):
    #print('getOneBasicBloc os %s root_prefix %s' % (os_type, root_prefix))
    blocks, dumb = getBasicBlocks(prog, root_prefix=root_prefix, os_type=os_type, lgr=lgr)
    retval = None
    if blocks is not None:
        for fun in blocks:
            for bb in blocks[fun]['blocks']:
                #print('compare 0x%x to 0x%x' % (addr, bb['start_ea']))
                if bb['start_ea'] == addr:
                    retval = bb
                    break
            if retval is not None:
                break    
    else:
        print('ERROR: getOneBasicBlock, blocks was none')
    return retval

def findBB(blocks, addr):
    retval = None
    for fun in blocks:
        for bb in blocks[fun]['blocks']:
            if addr >= bb['start_ea'] and addr <= bb['end_ea']:
                retval =  bb['start_ea']
                break
    return retval

def findEndBB(blocks, addr):
    retval = None
    for fun in blocks:
        for bb in blocks[fun]['blocks']:
            #print('compare 0x%x (%s) to 0x%x (%s)' % (bb['start_ea'], type(bb['start_ea']), addr, type(addr)))
            if addr == bb['start_ea']:
                retval =  bb['end_ea']
                break
        if retval is not None:
            break
    if retval is None:
        print('failed to find 0x%x in basic blocks' % addr)
        exit(1)
    return retval
 
def isPrintable(thebytes, ignore_zero=False, lgr=None):
    gotone=False
    retval = True
    zcount = 0
    goodcount = 0
    for b in thebytes:
        if ignore_zero and b == 0 and (zcount == 0 or goodcount > 10):
            zcount = zcount + 1 
        elif b is None or b > 0x7f or (b < 0x20 and b != 0xa and b != 0xd):
            if lgr is not None:
                lgr.debug('resimUtils isPrintable failed on 0x%x zcount %d' % (b, zcount))
            retval = False
            break
        elif b >= 0x20 or b in [0xa, 0xd]:
            gotone=True
            zcount = 0
            goodcount = goodcount+1
        else:
            if lgr is not None:
                lgr.debug('what to do with byte 0x%x' % b)
    if not gotone:
        retval = False 
    return retval

def getHexDump(b):
    if len(b) == 0:
        return ""
    count = 0
    for i in reversed(b):
        if i is None or i > 0:
            break
        count = count + 1
    end = len(b) - count
    b = b[:end]
    s2 = "".join([chr(i) if i is not None and 32 <= i <= 127 else "." for i in b])
    if not isPrintable(b):
        s1 = ''
        for i in b:
            if i is None:
                break
            val = '%02x' % i
            s1 = s1+ val
        #s1 = "".join([f"{i:02x}" for i in b])
        #s1 = s1[0:23] + " " + s1[23:]
        width = 48
        #return (f"{s1:<{width}}  |{s2}|") # parameterized width
        return '%s |%s|' % (s1, s2)
    else:
        return s2


def getIniTargetValue(input_ini_file, field, target=None, lgr=None):
    retval = None
    config = ConfigParser.ConfigParser()
    config.optionxform = str
    if not input_ini_file.endswith('.ini'):
        ini_file = '%s.ini' % input_ini_file
    else:
        ini_file = input_ini_file
    if not os.path.isfile(ini_file):
        print('File not found: %s' % ini_file)
        exit(1)
    config.read(ini_file)
    if target is None:
        for name, value in config.items('ENV'):
            if name == 'RESIM_TARGET':
                target = value
                break
    if lgr is not None:
        lgr.debug('getInitTargetValue target %s' % target)
    got_target = False
    if target is not None:
        for section in config.sections():
            if section == target:
                got_target = True
                for name, value in config.items(section):
                    if name == field:
                        retval = value 
                        break
    if not got_target:
        print('ERROR filed to find target %s in ini file %s' % (target, ini_file))
        if lgr is not None:
            lgr.error('filed to find target %s in ini file %s' % (target, ini_file))
       
    if retval is not None and retval.startswith('$'):
        env, path = retval.split('/',1)
        env_value = os.getenv(env[1:]) 
        retval = os.path.join(env_value, path)
    return retval

def findPattern(path: str, glob_pat: str, ignore_case: bool = False):
    ''' only works if pattern is glob-like, does not recurse '''
    rule = re.compile(fnmatch.translate(glob_pat), re.IGNORECASE) if ignore_case \
            else re.compile(fnmatch.translate(glob_pat))
    return [n for n in os.listdir(path) if rule.match(n)]

def findFrom(name, from_dir):
    for root, dirs, files in os.walk(from_dir):
        if name in files:
            retval = os.path.join(from_dir, root, name)
            abspath = os.path.abspath(retval)
            return abspath
    return None

def findListFrom(pattern, from_dir):
    retval = []
    for root, dirs, files in os.walk(from_dir):
        flist = fnmatch.filter(files, pattern)
        for f in flist:
            retval.append(f)
    return retval

def getfileInsensitive(path, root_prefix, root_subdirs, lgr, force_look=False):
    #lgr.debug('resimUtils getfileInsensitve path %s' % path)
    got_it = False
    retval = root_prefix
    cur_dir = root_prefix
    if '/' in path:
        parts = path.split('/')
        for p in parts[:-1]:
            lgr.debug('getfileInsensitve part %s cur_dir %s' % (p, cur_dir))
            dlist = [ name for name in os.listdir(cur_dir) if os.path.isdir(os.path.join(cur_dir, name)) ]

            for d in dlist:
                lgr.debug('getfileInsensitive does %s match %s' % (d.upper(), p.upper()))
                if '~' in p:
                    tilda_parts = p.split('~')
                    if d.lower().startswith(tilda_parts[0].lower()): 
                        retval = os.path.join(retval, d)
                        cur_dir = os.path.join(cur_dir, d)
                        break
                elif d.upper() == p.upper():
                    retval = os.path.join(retval, d)
                    cur_dir = os.path.join(cur_dir, d)
                    break
        p = parts[-1]
        lgr.debug('getfileInsensitve cur_dir %s last part %s' % (cur_dir, p))
        flist = os.listdir(cur_dir)
        for f in flist:
            if f.upper() == p.upper():
                retval = os.path.join(retval, f) 
                got_it = True
                break
    else:
        if not force_look and len(root_subdirs) == 0:
            if lgr is not None:
                 lgr.warning('getfileInsensitive RELATIVE %s root: %s   NOT LOOKING, return none' % (path, root_prefix))
        else:
            lgr.debug('getfileInsensitive')
            if len(root_subdirs) > 0:
                for subpath in root_subdirs:
                    top_path = os.path.join(root_prefix, subpath)
                    lgr.debug('getfileInsensitive using subdir %s walk from %s' % (subpath, top_path))
                    for root, dirs, files in os.walk(top_path):
                        for f in files:
                            if f.upper() == path.upper():
                                retval = os.path.join(top_path, root, f)
                                abspath = os.path.abspath(retval)
                                return abspath
            else:
                top_path = os.path.join(root_prefix)
                lgr.debug('getfileInsensitive no subdirs walk from %s' % top_path)
                for root, dirs, files in os.walk(top_path):
                    for f in files:
                        if f.upper() == path.upper():
                            retval = os.path.join(top_path, root, f)
                            abspath = os.path.abspath(retval)
                            return abspath
        return None


    if not got_it:
        retval = None
    return retval

def realPath(full_path):
        retval = full_path
        if full_path is not None and os.path.islink(full_path):
            parent = os.path.dirname(full_path)
            actual = os.readlink(full_path)
            retval = os.path.join(parent, actual)
        return retval

def getProgPathFromAnalysis(full_analysis_path, ini, lgr=None, root_prefix=None):
    analysis_path = os.getenv('IDA_ANALYSIS')
    if analysis_path is None:
        if lgr is not None:
            lgr.error('getProgPathFromAnalysis no IDA_ANALYSIS defined as env variable.')
        else:
            print('ERROR getProgPathFromAnalysis no IDA_ANALYSIS defined as env variable.')
        return None
    relative = full_analysis_path[len(analysis_path)+1:] 
    if lgr is not None:
        lgr.debug('getProgPathFromAnalysis relative is %s' % relative)
    if root_prefix is None:
        root_prefix = getIniTargetValue(ini, 'RESIM_ROOT_PREFIX', lgr=lgr)
    if lgr is not None:
        lgr.debug('getProgPathFromAnalysis root_prefix %s' % root_prefix)
    retval = os.path.join(os.path.dirname(os.path.dirname(root_prefix)), relative)
    return retval

def soMatch(fname, cache, lgr):
    # look for matches to handle things like libfu.so.0 as the fname vs a cache with something like libfu.so.0.0.1.funs
    retval = None
    base = os.path.basename(fname).upper()
    for item in cache:
        upper_item = item.upper()
        #lgr.debug('soMatch upper_item %s' % upper_item)
        if upper_item.startswith(base) and upper_item.endswith('.FUNS'):
            if lgr  is not None:
                #lgr.debug('resimUtils soMatch found match %s' % item)
                retval = item
    return retval
   
def getWinPath(path, root_prefix, lgr=None): 
    if path.startswith('/??/C:/') or path.startswith('/??/c:/'):
        if os.path.isdir(os.path.join(root_prefix, 'C:')) or os.path.isdir(os.path.join(root_prefix, 'c:')):
            path = path[4:]
        else:
            path = path[7:]
    elif path.startswith('/??/D:/') or path.startswith('/??/d:/'):
        if lgr is not None:
            lgr.debug('resimUtils getWinPath is D:')
        if os.path.isdir(os.path.join(root_prefix, 'D:')) or os.path.isdir(os.path.join(root_prefix, 'd:')):
            path = path[4:]
            if lgr is not None:
                lgr.debug('resimUtils getWinPath is D: is dir path now %s' % path)
        else:
            if lgr is not None:
                lgr.debug('resimUtils getWinPath is D: but not a subdir off root')
            path = path[7:]
    elif path.startswith('/'):
        path = path[1:]
    return path

def getAnalysisRootTopDir(root_prefix):
    analysis_path = os.getenv('IDA_ANALYSIS')
    if analysis_path is None:
        lgr.error('resimUtils getAnalysisRootTopDir path IDA_ANALYSIS not defined')
        return None
    root_dir = os.path.basename(root_prefix)
    root_parent = os.path.basename(os.path.dirname(root_prefix))
    top_dir = os.path.join(analysis_path, root_parent, root_dir)
    return top_dir

def getFunListCache(ini, root_prefix=None):
    if root_prefix is None: 
        root_prefix = getIniTargetValue(ini, 'RESIM_ROOT_PREFIX')
    top_dir = getAnalysisRootTopDir(root_prefix)
    fun_list_cache = findListFrom('*.funs', top_dir)
    return fun_list_cache

def getAnalysisPath(ini, fname, fun_list_cache = [], lgr=None, root_prefix=None):
    '''
    Given the path of a program, return the path to the program analysis.
    The path may be full, starting with the root prefix.  And the path
    may include a symlink, in which case we need to get the absolute path
    per the program location relative to the root prefix.And it may
    be windows, requiring caching and other search schemes.
    '''
    retval = None
    if lgr is not None:
        lgr.debug('resimUtils getAnalyisPath find %s' % fname)
    if lgr is not None:
        lgr.debug('resimUtils getAnalysisPath fname %s' % fname)
    if root_prefix is None: 
        root_prefix = getIniTargetValue(ini, 'RESIM_ROOT_PREFIX')
    top_dir = getAnalysisRootTopDir(root_prefix)
    root_prefix_abs = os.path.realpath(root_prefix)
    lgr.debug('resimUtils getAnalysis topdir %s  root_prefix %s' % (top_dir, root_prefix))
    if fname.startswith(root_prefix):
        fname_abs = os.path.realpath(fname)
        if lgr is not None:
            lgr.debug('resimUtils getAnalysisPath %s startswith root. abs is %s' % (fname, fname_abs))
        if fname_abs.startswith(root_prefix_abs):
            relative = fname_abs[len(root_prefix_abs)+1:] 
            lgr.debug('resimUtils getAnalysisPath fname_abs started with root_prefix_abs')
        else:
            relative = fname_abs[len(root_prefix)+1:] 
        lgr.debug('resimUtils getAnalysisPath relative path %s to join onto top dir' % relative)
        analysis_path = os.path.join(top_dir, relative)+'.funs'
        lgr.debug('resimUtils getAnalysis path try from relative %s' % analysis_path)
        if os.path.isfile(analysis_path):
            retval = analysis_path[:-5]
            lgr.debug('resimUtils getAnalysis got it %s' % retval)
    else:
        if fname.startswith('/'):
            fname = fname[1:]
        # try joining with root prefix so we can check for sym links
        with_root = os.path.join(root_prefix, fname)
        fname_abs = os.path.realpath(with_root)
        if lgr is not None:
            lgr.debug('resimUtils getAnalysis fname %s did not start with root prefix.  with root would be %s, and abs of that %s' % (fname, with_root, fname_abs))
        if fname_abs.startswith(root_prefix_abs):
            relative = fname_abs[len(root_prefix_abs)+1:] 
            lgr.debug('resimUtils getAnalysisPath fname_abs started with root_prefix_abs relative %s' % relative)
        else:
            relative = fname_abs[len(root_prefix)+1:] 
            lgr.debug('resimUtils getAnalysisPath fname_abs not started root_prefix_abs relative %s' % relative)
                
        analysis_path = os.path.join(top_dir, relative)+'.funs'
        lgr.debug('resimUtils getAnalysis joined relative to top dir for %s' % analysis_path)
        if os.path.isfile(analysis_path):
            retval = analysis_path[:-5]
            lgr.debug('resimUtils getAnalysis got it not start with root_prefix %s' % retval)
    #lgr.debug('getAnalysisPath root_prefix %s  fname %s' % (root_prefix, fname))
    #if retval is None and root_prefix is not None and fname.startswith(root_prefix):
    #    rest = fname[len(root_prefix):]        
    #    analysis_path = os.path.join(top_dir, rest[1:])+'.funs'
    #    lgr.debug('resimUtils getAnalysisPath rest is %s analyis_path %s' % (rest, analysis_path))
    #    if os.path.isfile(analysis_path):
    #        retval = analysis_path[:-5]
       
    if retval is None:    
        # try looking in cache and dealing with Windows paths
        if lgr is not None:
            lgr.debug('resimUtils getAnalysisPath top_dir %s' % (top_dir))
        if len(fun_list_cache) == 0:
            fun_list_cache = findListFrom('*.funs', top_dir)
            if lgr is not None:
                lgr.debug('resimUtils getAnalysisPath loaded %d fun files into cache top_dir %s' % (len(fun_list_cache), top_dir))

        if '\\' in fname:
            fname = fname.replace('\\', '/')
            if root_prefix is None:
                if fname.startswith('/??/C:/'):
                    fname = fname[7:]
            else:
                fname = getWinPath(fname, root_prefix, lgr=lgr)

        base = os.path.basename(fname)+'.funs'
        #if base.upper() in map(str.upper, fun_list_cache):
        lgr.debug('resimUtils getAnalysisPath call soMatch for %s' % fname)
        is_match = soMatch(fname, fun_list_cache, lgr)
        if is_match is not None:
            parent = os.path.dirname(fname)
            with_funs = os.path.join(parent, is_match)
            #with_funs = fname+'.funs'
            if lgr is not None:
                lgr.debug('resimUtils getAnalysisPath look for path for %s top_dir %s' % (with_funs, top_dir))
            retval = getfileInsensitive(with_funs, top_dir, [], lgr, force_look=True)
            if retval is not None:
                if lgr is not None:
                    lgr.debug('resimUtils getAnalysisPath got %s from %s' % (retval, with_funs))
                retval = retval[:-5]
        else:
            if lgr is not None:
                lgr.debug('resimUtils getAnalysisPath %s not in cache' % base)
            pass

    return retval

clib_dep = {'libc': 0,  'libstdc': 0, 'kernelbase': 0, 'ws2_32': 0, 'msvcr': 0, 'msvcp': 0, 'kernel32': 0, 'ucrtbase': 0, 'mswsock.dll': 2, 
             'ws2_32.dll':2, 'qt5core': 5, 'qt5network':4}

def getClibIndex(fname):
    retval = None
    fname = os.path.basename(fname.lower())
    for lib_file in clib_dep:
        if fname.startswith(lib_file):
            retval = clib_dep[lib_file]
            break
    return retval
    
def isClib(in_lib_file, lgr=None):
    if in_lib_file is None:
        return False
    retval = False
    if 'c:\\windows' in in_lib_file.lower():
        retval = True
    else:
        lib_file = ntpath.basename(in_lib_file) 
        if lib_file is not None:
            lf = lib_file.lower()
            for libname in clib_dep:
                if lf.startswith(libname):
                    retval = True
                    break
            if not retval and lf.startswith('ld-'):
                # loader as libc
                retval = True
    return retval

def isWindowsCore(lib_file):
    #if 'c:\windows' in lib_file.lower():
    if 'windows' in lib_file.lower():
        return True
    else:
        return False


def getLoadOffsetFromSO(so_json, prog, lgr=None):
    retval = None
    wrong_file = False
    if prog is None:
        if lgr is not None: 
            lgr.debug('resimUtils getLoadOffsetFromSO prog is None, returning offset 0')
        return 0
    offset = 0
    if lgr is not None: 
        lgr.debug('resimUtils getLoadOffsetFromSO prog: %s  so_json[proc] %s' % (prog, so_json['prog']))
    so_prog = os.path.basename(so_json['prog'])
    prog = os.path.basename(prog)
    if so_prog == prog:
       #print('0x%x is in prog' % bb['start_ea'])  
       prog_start = so_json['prog_start']
       if 'relocate' in so_json:
           offset = prog_start 
           if lgr is not None:
               lgr.debug('resimUtils getLoadOffsetFromSO is prog: %s and is relocate, set offset to prog_start 0x%x' % (prog, prog_start))
       pass
    else:
       wrong_file = True
       for section in so_json['sections']:
           #print('section file is %s' % section['file'])
           if lgr is not None:
               lgr.debug('section file is %s' % section['file'])
           if section['file'].endswith(prog):
               offset = section['locate']
               if lgr is not None:
                   lgr.debug('got section, offset is 0x%x' % offset)
               wrong_file = False
    if not wrong_file:
        retval = offset
    return retval 

def getFree():
    cmd = "free"
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as ps:
        output = ps.communicate()
        use_available = False
        for line in output[0].decode("utf-8").splitlines():
             if 'available' in line:
                 use_available = True
             if line.startswith('Mem:'):
                 parts = line.split()
                 tot = int(parts[1])
                 if use_available:
                     free = int(parts[6])
                 else:
                     free = int(parts[3])
                 #print('tot %s   free %s' % (tot, free))             
                 percent = (free / tot) * 100
                 return int(percent)
    return None

def getExecList(ini, lgr=None):
    retval = None
    if lgr is not None:
        lgr.debug('resimUtils getExecList ini %s' % ini)
    root_prefix = getIniTargetValue(ini, 'RESIM_ROOT_PREFIX')
    top_dir = getAnalysisRootTopDir(root_prefix)
    retval = os.path.join(top_dir, 'exec_list.txt')
    return retval

def getExecDict(root_prefix, lgr=None):
    retval = None
    if lgr is not None:
        lgr.debug('resimUtils getExecDict root_prefix %s' % root_prefix)
    top_dir = getAnalysisRootTopDir(root_prefix)
    path = os.path.join(top_dir, 'exec_dict.json')
    if lgr is not None:
        lgr.debug('resimUtils getExecDict path %s' % path)
    if os.path.isfile(path):
       with open(path) as fh:
           retval = json.load(fh)
           if lgr is not None:
               lgr.debug('resimUtils getExecDict loaded %d entries' % len(retval))
    return retval

def getFullPath(prog, ini, lgr=None):
    root_prefix = getIniTargetValue(ini, 'RESIM_ROOT_PREFIX', lgr=lgr)
    root_subdirs = getIniTargetValue(ini, 'RESIM_ROOT_SUBDIRS', lgr=lgr)
    if root_subdirs is not None:
        parts = root_subdirs.split(';')
        the_subdirs = []
        for sd in parts:
            the_subdirs.append(sd.strip()) 
    else:
        the_subdirs = []
    os_type = getIniTargetValue(ini, 'OS_TYPE', lgr=lgr)
    if os_type.startswith('WIN'):
        target_fs = winTargetFS.TargetFS(None, root_prefix, the_subdirs, lgr)
    else:
        target_fs = targetFS.TargetFS(None, root_prefix, the_subdirs, lgr)
    if lgr is not None:
        lgr.debug('resimUtils getFullPath %s' % prog)
    full = target_fs.getFull(prog, lgr=lgr)
    return full

def getKeyValue(item):
    key = None
    value = None
    if '=' in item:
        parts = item.split('=', 1)
        key = parts[0].strip()
        value = parts[1].strip()
    return key, value

def yesNoTrueFalse(item):
    item = item.lower()
    if item in ['yes', 'true']:
        return True
    else:
        return False 

def isSO(prog):
    prog = prog.lower()
    if prog.endswith('.so') or '.so.' in prog or prog.endswith('.dll'):
        return True
    else:
        return False

