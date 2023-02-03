#!/usr/bin/env python3
#
# given a an AFL session named by target, compare all of the coverage
# files and de-dupe them, creating a list of the smallest queue files
# generate unique a set of hits.
#
import sys
import os
import glob
import json
import argparse
import functools
try:
    import ConfigParser
except:
    import configparser as ConfigParser
resim_dir = os.getenv('RESIM_DIR')

sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import aflPath


#for hit in hits1:
#    print('0x%x' % hit)

def getHeader(ini):
    config = ConfigParser.ConfigParser()
    config.read(ini)
    retval = None
    if not config.has_option('ENV', 'AFL_UDP_HEADER'):
        print('no AFL_UDP_HEADER in %s' % ini)
    else:
        retval = config.get('ENV', 'AFL_UDP_HEADER')
        print('found header: %s' % retval)
    return retval

def getPackets(f, header):
    retval = -1
    with open(f) as fh:
        data = fh.read()
        retval = data.count(header) 
    return retval  

def listMatch(l1, l2):
    if functools.reduce(lambda x, y : x and y, map(lambda p, q: p == q,l1,l2), True): 
        return True
    else: 
        return False
    
def saveUnique(hit_dict, target):
    flist = list(hit_dict.keys())
    afl_path = os.getenv('AFL_DATA')
    target_path = os.path.join(afl_path, 'output', target, target+'.unique') 
    with open(target_path, 'w') as fh:
        json.dump(flist, fh)

def getQFile(f):
        base = os.path.basename(f)
        parent = os.path.dirname(f)
        instance = os.path.dirname(parent)
        queue = os.path.join(instance, 'queue', base)
        if not os.path.isfile(queue):
            queue = os.path.join(instance, 'manual', base)
            if not os.path.isfile(queue):
                realqueue = os.path.join(instance, 'queue', base)
                print('No file at %s' % queue)
                print('or at %s' % realqueue)
                queue = None
        return queue
                

def checkFileFirst(f, udp_header, hit_dict, args, prefix):
    ''' get its corresponding queue file '''
    queue = getQFile(f)
    if queue is not None:
 
        queue_len = os.path.getsize(queue)

        ''' get the number of udp packets, if recorded '''
        udp_count = 0
        if udp_header is not None:
            with open(queue, 'br') as fh:
                data = fh.read()
                udp_count = data.count(udp_header)
                if udp_count > 1:
                    return

        try:
            hits = json.load(open(f))
        except:
            print('Failed loading json %s' % f)
            exit(1)

        numhits = len(hits)
        gotone = None
        for item in hit_dict:
            if len(hit_dict[item]) == numhits: 
                if listMatch(hit_dict[item], hits):
                    #print('hits in %s matches %s' % (item, f))
                    gotone = item
                    break

        rel_path = aflPath.getRelativePath(f, args.target)
        #print('rel_path is %s' % rel_path)
        if not gotone:
            #print('new hit list %d hits %s' % (numhits, rel_path))
            hit_dict[rel_path] = hits
        else:
            #print('%s hits already in %s' % (rel_path, gotone))
            full = os.path.join(prefix, rel_path)
            this_count = 0
            if udp_header is not None:
                with open(full, 'br') as fh:
                    data = fh.read()
                    this_count = data.count(udp_header)
            if udp_count < this_count:
                #print('but this one has fewer UDP headers so replace it path %s' % rel_path)
                del hit_dict[gotone]
                hit_dict[rel_path] = hits
            elif queue_len < os.path.getsize(full):
                #print('but this one is smaller, so replace it path %s' % rel_path)
                del hit_dict[gotone]
                hit_dict[rel_path] = hits

def checkMulti(flist, all_hits, udp_header, hit_dict): 
    ''' find multi-udp sessions that led to new hits '''
    multi_hits = {}
    for f in flist:
        json_hits = json.load(open(f))
        for hit in json_hits:
            if hit not in all_hits:
                if f not in multi_hits:
                    multi_hits[f] = []
                #print('new hit %s in %s' % (hit, f)) 
                multi_hits[f].append(hit)

    ''' remove subsets '''
    rm_list = []
    for f in multi_hits:
        for this_f in multi_hits:
            if f == this_f:
                continue
            got_one = False
            for hit in multi_hits[this_f]:
                if hit not in multi_hits[f]:
                    got_one = True
                    break
            if not got_one:
                ''' all hits in this_f already in f, remove one of them '''    
                if len(multi_hits[f]) == len(multi_hits[this_f]):
                    #print('same number of hits')
                    ''' same hits.  consider packet numbers '''
                    json_hits = json.load(open(f))
                    this_json_hits = json.load(open(this_f))
                    pcount = 0
                    pcount_this = 0
                    for hit in multi_hits[f]:
                        #print('len of this_json_hits: %d' % len(json_hits))
                        #print(f)
                        #print('is is %s' % str(json_hits[hit]))
                        pcount = pcount + int(json_hits[hit]['packet_num'])
                        #print('len of this_json_hits: %d' % len(this_json_hits))
                        pcount_this = pcount_this + int(this_json_hits[hit]['packet_num'])
                    #if pcount != pcount_this:
                    #    print('pcount %d  pcount_this %d' % (pcount, pcount_this))
                    if pcount < pcount_this:
                        ''' this_f hit with higher packet numbers '''
                        if this_f not in rm_list:
                            rm_list.append(this_f)
                    else:
                        if f not in rm_list:
                            rm_list.append(f)
                else:  
                    if this_f not in rm_list:
                        rm_list.append(this_f)


    for f in rm_list:
        del multi_hits[f]

    for f in multi_hits:
        q = getQFile(f)
        if udp_header is not None:
            with open(q, 'br') as fh:
                data = fh.read()
                this_count = data.count(udp_header)
        hit_dict[f] = multi_hits[f] 
        print('%d new hits and %d headers in %s' % (len(multi_hits[f]), this_count, f))
    
               

def main():
    parser = argparse.ArgumentParser(prog='dedupCoverage', description='Create a deduped file of all unique coverage files.')
    parser.add_argument('target', action='store', help='The AFL target, generally the name of the workspace.')
    parser.add_argument('ini', action='store', help='The name of the ini file.')
    args = parser.parse_args()
    if args.target.endswith('/'):
        args.target = args.target[:-1]
    ida_data = os.getenv('RESIM_IDA_DATA')
    if ida_data is None:
        print('RESIM_IDA_DATA not defined')
        exit(1)

    udp_header = getHeader(args.ini)
    if udp_header is not None:
        udp_header = udp_header.encode()

    hit_dict = {}

    flist = aflPath.getAFLCoverageList(args.target, get_all=True)

    prefix = aflPath.getTargetPath(args.target)
    print('prefix is %s' % prefix)

    ''' for each coverage file '''
    for f in flist:
        checkFileFirst(f, udp_header, hit_dict, args, prefix)

    print('after first pass %d paths' % len(hit_dict))
    ''' remove subsets '''
    remove_set = []
    all_hits = []
    for f in hit_dict:
        for this_f in hit_dict:
            if this_f == f:
                continue
            got_dif = False
            for hit in hit_dict[this_f]:
                if hit not in all_hits:
                    all_hits.append(hit)
                if hit not in hit_dict[f]:
                    got_dif = True
                    break
            if not got_dif:
                ''' no hits in this_f that are not in f, remove this_f'''
                if this_f not in remove_set:
                    #print('no hits in %s (this_f) that are not in %s (f), remove this_f' % (this_f, f))
                    remove_set.append(this_f)
    for f in remove_set:
        del hit_dict[f]
    print('after subset pass %d paths and %d hits' % (len(hit_dict), len(all_hits)))
  
    if udp_header is not None: 
        checkMulti(flist, all_hits, udp_header, hit_dict) 

    ''' report results '''
    for f in hit_dict:
        full = os.path.join(prefix, f)
        full_queue = full.replace('coverage', 'queue')
        count_str = ''
        if udp_header is not None:
            with open(full_queue, 'br') as fh:
                data = fh.read()
                this_count = data.count(udp_header)
                count_str = 'udp count: %d' % this_count
        print('hits: %d fsize: %d %s %s' % (len(hit_dict[f]), os.path.getsize(full_queue), count_str, full_queue))
    print('got %d unique hit lists' % len(hit_dict))
    saveUnique(hit_dict, args.target)

if __name__ == '__main__':
    sys.exit(main())
