#!/usr/bin/python
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

'''
Ad-hoc reporting on defensive responses to being scored upon.
'''
import MySQLdb as mdb
import sys
import os
import json
import glob
import json
import ghostScores
from monitorLibs import configMgr
from monitorLibs import szk

import rcbsSQL
class react():
    def __init__(self):
        self.con = None
        here=os.getcwd()
        try:
            self.con = mdb.connect('localhost', 'cgc', 'password')
        except mdb.Error, e:
            print "scoresSQL, init, error %d: %s" % (e.args[0], e.args[1])
        self.rcbs = rcbsSQL.rcbsSQL(self.con)
        here=os.getcwd()
        self.rcbs.scheduleLoad(os.path.join(here,'schedule.json'))

    def get_json(self, team, csid, round_id, end_round, rcb_round):
        done = False
        path = '/mnt/vmLib/bigstuff/auto_analysis/'
        supress_silent = False
        if rcb_round == 0:
            rcb_round = 999
        #print('round_id %d  rcb_round %d  end_round %d' % (round_id, rcb_round, end_round))
        while not done and round_id < end_round and round_id < rcb_round:
            pattern = '%s-*-%d-%d*.json' % (csid, team, round_id)
            fset = glob.glob(path+pattern)
            for analysis in fset:
                #print('check %s' % analysis)
                with open(analysis) as fh:
                    j = json.load(fh)
                    if not self.show_attack_type(j, supress_silent):
                        done = True
                    else:
                        supress_silent = True
            round_id += 1

    def show_attack_type(self, j, supress_silent):
        ''' and return true if silent '''
        retval = False
        control_corrupt = ''
        round_id = j['throw_info']['round']
        throw_team = j['throw_info']['throw_team']
        if 'control_corrupt_return' in j or 'control_corrupt_call' in j :
            control_corrupt = 'control_corrupt'
        if 'pov' in j:
            pov_event = j['pov']
            #print('type %s' % pov_event['type'])
            if 'segv' in j or pov_event['type'] == 1:
                print('\tround:%s throw_team:%s %s SEGV' % (round_id, throw_team, control_corrupt))
            else:
                if not supress_silent:
                    print('\tround:%s throw_team:%s %s silent' % (round_id, throw_team, control_corrupt))
                retval = True

        elif 'no_event' in j:
            print('No event found in ')
        else:
            print('no pov in ')
        return retval
        
    def for_team(self, team):
        r_cur = self.con.cursor()
        s_cur = self.con.cursor()
        #print('%15s %5s %s' % ('csid', 'count', 'type'))    
        try:
            cmd = "SELECT DISTINCT csid FROM pov_scores_db.cb_map ORDER BY csid"
            r_cur.execute(cmd)
            csid_list = r_cur.fetchall()
            team = int(team)
            for csid in csid_list:
                csid = csid[0]
                first_round = self.rcbs.firstRound(csid)
                if first_round is None:
                    print('no first round for %s' % csid)
                    exit(1)
                last_round = first_round + self.rcbs.numRounds(csid) - 1
                cmd = "SELECT rcb_round, fail_round, score_round FROM pov_scores_db.react_defend WHERE csid = '%s' AND defend_team = %d" % (csid, team)
                s_cur.execute(cmd)
                row = s_cur.fetchone()
                rcb_round = int(row[0])
                fail_round = int(row[1])
                score_round = int(row[2])
                if (rcb_round > fail_round and fail_round != 0) or (rcb_round == 0 and fail_round > 0):
                    delta = rcb_round - fail_round
                    react_window = last_round - fail_round
                    if react_window > 1:
                        if delta < 0:
                            delta = 999
                   
                        print('%s start:%2d end:%2d first_rcb:%2d first_fail:%2d first_score:%2d  DELTA:%2d' % (csid, first_round, last_round, rcb_round, fail_round, score_round, delta))
                        j = self.get_json(team, csid, fail_round, last_round, rcb_round)
                    #print('%s start:%d end:%d first_rcb:%d first_fail:%d first_score:%d' % (csid, first_round, last_round, rcb_round, fail_round, score_round))
                
        except mdb.Error, e:
            print "react, for_team, error %d: %s" % (e.args[0], e.args[1])

if __name__ == '__main__':
    r = react()
    r.for_team(sys.argv[1])
