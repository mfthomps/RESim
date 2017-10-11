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
import json
import random
import string
import hashlib
'''
generate pov json files for forensic replays
'''
start_seed = 'f34c6463546a2fad8c1d15a0bfa7951f097f49fdd979475dd0e95dd3ff7979a5d5c5723915e34518b36ed8c5e30d242c'
a_pov_pov = '\
      {\
         "team": "1",\
         "csid": "KPRCA_00062",\
         "src_ip": "172.16.128.200",\
         "dest_ip": "172.16.128.1",\
         "dest_port": "9999",\
         "throws": 1,\
         "pov_file": "/home/mfthomps/cgc-challenges/KPRCA_00062/pov/pov_1.pov",\
          "pov_seeds": [\
          ],\
          "cb_seeds": [\
          ]\
      } \
'
pov_json = '\
{\
  "round" : 10,\
  "round_length" : 10,\
  "rand_seed" : "f34c6463546a2fad8c1d15a0bfa7951f097f49fdd979475dd0e95dd3ff7979a5d5c5723915e34518b36ed8c5e30d242c",\
  "negotiation_server" : "172.16.128.1",\
  "negotiation_port" : "20000",\
  "logfile": "/tmp/pov.log",\
  "povs": [\
        ]\
}\
'
a_neg_pov = '\
      {\
         "team": "1",\
         "csid": "KPRCA_00062",\
         "throws": 1,\
          "pov_seeds": [\
          ],\
          "cb_seeds": [\
          ],\
          "negotiate_seeds": [\
          ]\
      } \
'
neg_json = '\
{\
  "round" : 10,\
  "round_length" : 10,\
  "readyfile" : "/tmp/ready.txt",\
  "logfile": "/tmp/pov.log",\
  "povs": [\
        ]\
}\
'
def getSeeds(start_seed, count, team_num):
    retval = []
    m = hashlib.md5()
    for i in range(count):
        m.update(start_seed+str(i)+str(team_num))
        h = m.digest()
        random.seed(h)
        lst = [random.choice(string.hexdigits) for n in range(96)]
        retval.append(("".join(lst)))
    return retval

def addSeeds(the_pov, seed_count, seed_types, team_num):
    seed_list = getSeeds(start_seed, seed_count, team_num)
    for seed in seed_list:
        for seed_type in seed_types:
            the_pov[seed_type].append(seed)
    the_pov['throws'] = seed_count


def addSeedsFromConfig(the_pov, seed_types, pov_config, i):
    print('addSeedsFromConfig index %d, type %s' % (i, str(seed_types)))
    for seed_type in seed_types:
        try:
            seed = pov_config[seed_type][i]
        except:
            print('could not get field %s, index %d from %s' % (seed_type, i, str(pov_config)))
            exit(1)
        the_pov[seed_type].append(seed)

def getPovJson(cb, pov, pov_config=None, seed_count=1, team_count=1, seed_index=0):
    the_json = json.loads(pov_json)
    #the_pov = the_json['povs'][0]
    for i in range(1, team_count+1):
        the_pov = json.loads(a_pov_pov)
        the_pov['csid'] = cb
        the_pov['team'] = str(i)
        the_pov['pov_file'] = pov
        if pov_config is None:
            print('no pov_config')
            addSeeds(the_pov, seed_count, ['pov_seeds','cb_seeds'], i)
        else:
            print('using pov_config')
            addSeedsFromConfig(the_pov, ['pov_seeds','cb_seeds'], pov_config, seed_index)
        the_json['povs'].append(the_pov)
     
    retval = json.dumps(the_json, indent=4)
    return retval

def getNegJson(cb, pov_config=None, seed_count=1, team_count=1, seed_index=0):
    print('getNegJson seed_count is %d' % seed_count)
    the_json = json.loads(neg_json)
    #the_pov = the_json['povs'][0]
    for i in range(1, team_count+1):
        the_pov = json.loads(a_neg_pov)
        the_pov['csid'] = cb
        the_pov['team'] = str(i)
        if pov_config is None:
            addSeeds(the_pov, seed_count, ['pov_seeds','cb_seeds','negotiate_seeds'], i)
        else:
            addSeedsFromConfig(the_pov, ['pov_seeds','cb_seeds','negotiate_seeds'], pov_config, seed_index)
        the_json['povs'].append(the_pov)
    retval = json.dumps(the_json, indent=4)
    return retval
