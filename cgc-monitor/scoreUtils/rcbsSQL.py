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
import MySQLdb as mdb
import sys
import os
import json
from monitorLibs import configMgr
from monitorLibs import szk
'''
Utilities for identifying RCBs deployed by teams in rounds
e.g., what percentage of possible rounds was a patched version run by a team.
'''
class rcbsSQL():
    def __init__(self, con=None):
        self.con = con
        self.schedule = None
        if con is None:
            try:
                self.con = mdb.connect('localhost', 'cgc', 'password')
            except mdb.Error, e:
                print "rcbsSQL, init, error %d: %s" % (e.args[0], e.args[1])

    def getReference(self, csid):
        retval = []
        first_round = self.firstRound(csid)
        if first_round is None:
            print(' no first round for %s' % csid)
            return retval
        try:
            t_cur = self.con.cursor()
            cmd = "SELECT hash FROM pov_scores_db.cb_map WHERE csid = '%s'" % csid
            t_cur.execute(cmd)
            row = t_cur.fetchone()
            hash_value = row[0].strip()
            cmd = "SELECT rcb FROM pov_scores_db.rcbs_by_round WHERE hash = '%s' AND round = %d AND team = 1 ORDER BY rcb" % (hash_value, first_round)
            t_cur.execute(cmd)
            rows = t_cur.fetchall()
            if rows is None:
                print('getReference, nothing from %s' % cmd)
                return retval
            for (rcb) in rows:
                retval.append(rcb[0])
            
        except mdb.Error, e:
            print "rcbsSQL, teamsScoredOnCB query, error %d: %s" % (e.args[0], e.args[1])
        return retval
        
    def csetDown(self, csid, team):
        ''' count the rounds that a patched version of the given csid was run by the given team '''
        retval = 0
        try:
            t_cur = self.con.cursor()
            cmd = "SELECT hash FROM pov_scores_db.cb_map WHERE csid = '%s'" % csid
            t_cur.execute(cmd)
            row = t_cur.fetchone()
            hash_value = row[0].strip()
            cmd = "SELECT rcb, round FROM pov_scores_db.rcbs_by_round WHERE hash = '%s' AND team = '%d' ORDER BY round, rcb" % (hash_value, team)
            t_cur.execute(cmd)
            rows = t_cur.fetchall()
            previous_round = self.firstRound(csid) -1
            previous_set = self.getReference(csid)
            current_set = []
            #print('ref len is %d' % len(previous_set))
            for (rcb, round_id) in rows:
                if round_id != previous_round:
                    ''' change in round, see if sets match '''
                    #print('%s team %d round %d is new, prev was %d' % (csid, team, round_id, previous_round))
                    for i in range(0, len(previous_set)):
                        if previous_set[i] != current_set[i]:
                            #print('%s changed for team %d in round %d  %s  %s' % (csid, team, round_id, previous_set[i], current_set[i]))
                            retval += 1
                    previous_set = list(current_set)
                    current_set = []
                    previous_round = round_id 
                current_set.append(rcb)
    
        except mdb.Error, e:
            print "rcbsSQL, teamsScoredOnCB query, error %d: %s" % (e.args[0], e.args[1])
        return retval
    
    def csetReplaced(self, csid, team):
        ''' get the percentage of rounds that a patched version of the given csid was run by the given team '''
        replaced_count = 0
        round_count = 0
        try:
            t_cur = self.con.cursor()
            cmd = "SELECT hash FROM pov_scores_db.cb_map WHERE csid = '%s'" % csid
            t_cur.execute(cmd)
            row = t_cur.fetchone()
            hash_value = row[0].strip()
            cmd = "SELECT rcb, round FROM pov_scores_db.rcbs_by_round WHERE hash = '%s' AND team = '%d' ORDER BY round, rcb" % (hash_value, team)
            t_cur.execute(cmd)
            rows = t_cur.fetchall()
            previous_round = self.firstRound(csid) -1
            previous_set = self.getReference(csid)
            current_set = []
            #print('ref len is %d' % len(previous_set))
            for (rcb, round_id) in rows:
                if round_id != previous_round:
                    ''' change in round, see if sets match '''
                    #print('%s team %d round %d is new, prev was %d' % (csid, team, round_id, previous_round))
                    for i in range(0, len(previous_set)):
                        if previous_set[i] != current_set[i]:
                            #print('%s changed for team %d in round %d  %s  %s' % (csid, team, round_id, previous_set[i], current_set[i]))
                            replaced_count += 1
                    current_set = []
                    previous_round = round_id 
                    round_count += 1
                current_set.append(rcb)
    
        except mdb.Error, e:
            print "rcbsSQL, teamsScoredOnCB query, error %d: %s" % (e.args[0], e.args[1])
        retval = float (float(replaced_count)/float(round_count-2)) * 100.0
        return retval
    

    def allRef(self):
        try:
            t_cur = self.con.cursor()
            cmd = "SELECT csid FROM pov_scores_db.cb_map"
            t_cur.execute(cmd)
            rows = t_cur.fetchall()
            for (csid) in rows:
                ref = self.getReference(csid[0])
                first = self.firstRound(csid[0])
                num = self.numRounds(csid[0])
                for r in ref:
                    print('%s %d %d' % (r.strip(), first, num))
        except mdb.Error, e:
            print "rcbsSQL, teamsScoredOnCB query, error %d: %s" % (e.args[0], e.args[1])
    
    def scheduleLoad(self, fname):
        with open(fname) as fh:
            self.schedule = json.load(fh)
            #print('loaded jason, len %d' % len(self.schedule))

    def firstRound(self, csid):
        round_id = 1
        for round_sets in self.schedule:
            #print('look for <%s> in %s' % (csid, str(round_sets)))
            if csid in round_sets:
                return round_id
            round_id += 1
        return None

    def numRounds(self, csid):
        retval = 0
        for round_sets in self.schedule:
            #print str(round_sets)
            if csid in round_sets:
                retval += 1
        ''' do not count the consensus round '''
        return retval-1

    def listDown(self):
        line = '%11s' % ' '
        for i in range(1,8):
            line = line + '%5s' % str(i)
        line = line + ' || '
        print(line)
        try:
            t_cur = self.con.cursor()
            cmd = "SELECT csid FROM pov_scores_db.cb_map"
            t_cur.execute(cmd)
            rows = t_cur.fetchall()
            for (csid) in rows:
                line = '%10s' % (csid[0])
                for i in range(1,8):
                    changed_count = self.csetDown(csid[0], i)
                    line = line + '%5d' % changed_count
                print(line)
                     
                #print('%s team: %d replaced: %d' % (csid[0], i, changed_count))
        except mdb.Error, e:
            print "rcbsSQL, teamsScoredOnCB query, error %d: %s" % (e.args[0], e.args[1])
        
if __name__ == "__main__":

    ss = rcbsSQL()
    here=os.getcwd()
    ss.scheduleLoad(os.path.join(here,'schedule.json'))
    ss.allRef()
