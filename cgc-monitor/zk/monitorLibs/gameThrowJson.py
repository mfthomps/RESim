import os
import json
import sys
cb_map = {}

def getLocal(path, sdir):
    retval = path
    bname = os.path.basename(path)
    if not os.path.isfile(path):
        tdir = os.path.join('/tmp', sdir)
        lfile = os.path.join(tdir, bname)
        try:
            os.mkdir(tdir)
        except:
            pass
        cmd = 'scp mft-ref:%s %s' % (path, lfile)
        os.system(cmd)
        retval = lfile
    return retval

def getRCBCfg(csid, round_id, defend, thrower, round_dir):
    rcb_cfg = os.path.join(round_dir, round_id, 'team', defend, 'rcb', 'config.json')
    rcb_cfg = getLocal(rcb_cfg, 'rcb')
    rcb_def = None
    with open(rcb_cfg) as fh:
        rcb_json = json.load(fh)
        rcb_entries = rcb_json['challenge_sets']
        for rcb_def in rcb_entries:
            if rcb_def['csid'] == csid:
                return rcb_def
    print('could not get RCB config for %s' % rcb_cfg)
    return None

def getIDSCfg(csid, round_id, defend, thrower, round_dir):
    ids_cfg = os.path.join(round_dir, round_id, 'team', defend, 'ids', 'config.json')
    ids_cfg = getLocal(ids_cfg, 'ids')
    ids_def = None
    with open(ids_cfg) as fh:
        ids_json = json.load(fh)
        ids_entries = ids_json['challenges']
        return ids_entries[csid]
                
def getPovCfg(csid, round_id, defend, thrower, round_dir):
    pov_cfg_path = os.path.join(round_dir, round_id, 'team', defend, 'pov', 'config.json')
    pov_cfg = getLocal(pov_cfg_path, 'pov')
    pov_def = None
    if not os.path.isfile(pov_cfg):
        print('no pov config file at %s' % pov_cfg_path)
    else:    
        with open(pov_cfg) as fh:
            pov_json = json.load(fh)
            pov_entries = pov_json['povs']
            for pov_def in pov_entries:
                if pov_def['csid'] == csid and pov_def['team'] == int(thrower):
                    return pov_def
    print('no csid %s in pov config at %s' % (csid, pov_cfg_path))
    return None

def getNegCfg(csid, round_id, defend, thrower, round_dir):
    neg_cfg = os.path.join(round_dir, round_id, 'team', defend, 'negotiation', 'config.json')
    neg_cfg = getLocal(neg_cfg, 'neg')
    neg_def = None
    with open(neg_cfg) as fh:
        neg_json = json.load(fh)
        neg_entries = neg_json['povs']
        for neg_def in neg_entries:
            if neg_def['csid'] == csid and neg_def['team'] == int(thrower):
                return neg_def

def getJson(common, round_id, thrower, defend, alt_defend=None, alt_defend_round=None):
    rev_cb_map = {}
    cm='/etc/cgc-monitor/cbmap.txt'
    cm=getLocal(cm, 'map')
    with open(cm) as fh:
        for line in fh:
            parts = line.strip().split()
            cb_map[parts[0]] = parts[1]
            rev_cb_map[parts[1]] = parts[0]
    round_dir = '/mftdata/cgc-archive/final/cgc/run/luigi/status/round'
    csid = rev_cb_map[common]
    round_id = str(round_id)
    defend = str(defend)
    thrower = str(thrower)
    pov_cfg = getPovCfg(csid, round_id, defend, thrower, round_dir)
    
    if alt_defend is not None:
        alt_defend = str(alt_defend)
        alt_defend_round = str(alt_defend_round)
        rcb_cfg = getRCBCfg(csid, alt_defend_round, alt_defend, thrower, round_dir)
    else:
        rcb_cfg = getRCBCfg(csid, round_id, defend, thrower, round_dir)
    if rcb_cfg is None:
        print('error getting rcb config')
        exit(1)
    
    if alt_defend is not None:
        ids_cfg = getIDSCfg(csid, alt_defend_round, alt_defend, thrower, round_dir)
    else:
        ids_cfg = getIDSCfg(csid, round_id, defend, thrower, round_dir)
    
    neg_cfg = getNegCfg(csid, round_id, defend, thrower, round_dir)
    
    #print ids_cfg   
    forensics = {}
    forensics['rcb'] = rcb_cfg['cbs']
    try:
        forensics['pov'] = os.path.basename(pov_cfg['pov_file'])
    except:
        print('could not find pov in pov_config: %s' % str(pov_cfg))
        exit(1)
    forensics['ids'] = os.path.basename(ids_cfg['config'])
    forensics['pov_config'] = {}
    forensics['pov_config']['cb_seeds'] = neg_cfg['cb_seeds']
    forensics['pov_config']['pov_seeds'] = neg_cfg['pov_seeds']
    
    forensics['pov_config']['negotiate_seeds'] = neg_cfg['negotiate_seeds']
    if alt_defend is not None:
        forensics['team_id'] = alt_defend
    else:
        forensics['team_id'] = defend
    return forensics

