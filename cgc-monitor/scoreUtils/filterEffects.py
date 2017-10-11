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
'''
identify POVs that succeded against filters
'''
class failedD():
    def __init__(self):
        self.con = None
        self.schedule = None
        here=os.getcwd()
        try:
            self.con = mdb.connect('localhost', 'cgc', 'password')
        except mdb.Error, e:
            print "failedD, init, error %d: %s" % (e.args[0], e.args[1])
   
    def showDefended(self): 
        try:
            r_cur = self.con.cursor()
            t_cur = self.con.cursor()
            s_cur = self.con.cursor()
            cmd = 'SELECT DISTINCT csid, rcb, round, throw_team, defend_team, pov_file FROM pov_scores_db.pov_rcb_scores ORDER BY csid, round, defend_team'
            t_cur.execute(cmd)
            rows = t_cur.fetchall()
            #print('len of counts is %d' % len(counts))
            for (csid, rcb, round_id, throw_team, def_team, pov_file) in rows:
                cmd = "SELECT hash FROM pov_scores_db.cb_map WHERE csid = '%s'" % csid
                r_cur.execute(cmd)
                hash_id = r_cur.fetchone()[0]
                cmd = 'SELECT filter FROM pov_scores_db.filters_by_round WHERE hash="%s" AND round = %d AND team = %d' % (hash_id, round_id, def_team)
                s_cur.execute(cmd)
                result = s_cur.fetchone()
                if result is None:
                    #print('\nsuccessful pov, no filter with %s  round: %d defend: %d thrower: %d %s' % (rcb, round_id, def_team, throw_team, pov_file))
                    w_cur = self.con.cursor()
                    cmd = 'SELECT round, team, filter FROM pov_scores_db.filter_rcbs_by_round WHERE rcb = "%s"' %  rcb
                    w_cur.execute(cmd)
                    filtered = w_cur.fetchall()
                    for (defend_round_id, team, filter_id) in filtered:
                        print('\tround %d, team %d defended %s with filter: %s ' % (defend_round_id, team, rcb, filter_id))
                        print('\twas scored on by team %d against %d in round %d with no filter' % (throw_team, def_team, round_id))
                        cmd = "SELECT throw_team FROM pov_scores_db.pov_rcb_scores WHERE csid = '%s' AND defend_team = %d AND round = %d" % (csid, team, defend_round_id) 
                        r_cur.execute(cmd)
                        wrong = r_cur.fetchall()
                        for other_throw_team in wrong:
                            print('wrong: %s scored on them' % str(other_throw_team))
                    
        except mdb.Error, e:
            print "failedD, showAll, error %d: %s" % (e.args[0], e.args[1])

    def showAll(self): 
        try:
            r_cur = self.con.cursor()
            t_cur = self.con.cursor()
            s_cur = self.con.cursor()
            cmd = 'SELECT DISTINCT csid, round, throw_team, defend_team, pov_file FROM pov_scores_db.pov_scores ORDER BY csid, round, defend_team'
            t_cur.execute(cmd)
            rows = t_cur.fetchall()
            #print('len of counts is %d' % len(counts))
            for (csid, round_id, throw_team, def_team, pov_file) in rows:
                cmd = "SELECT hash FROM pov_scores_db.cb_map WHERE csid = '%s'" % csid
                r_cur.execute(cmd)
                hash_id = r_cur.fetchone()[0]
                cmd = 'SELECT filter FROM pov_scores_db.filters_by_round WHERE hash="%s" AND round = %d AND team = %d' % (hash_id, round_id, def_team)
                s_cur.execute(cmd)
                result = s_cur.fetchone()
                if result is not None:
                    print('\n%s  round: %d defend: %d thrower: %d %s' % (csid, round_id, def_team, throw_team, pov_file))
                    print('\tfilter: t%s' % str(result[0]))
                    w_cur = self.con.cursor()
                    cmd = 'SELECT DISTINCT defend_team, round FROM pov_scores_db.pov_scores WHERE csid="%s" AND round = %d and pov_file = "%s" AND defend_team != %d' % (csid, 
                       round_id, pov_file, def_team)
                    w_cur.execute(cmd)
                    others = w_cur.fetchall()
                    for (throw_team, round_id) in others:
                        print('\tpov also scored against %d in round %d' % (throw_team, round_id))
                    
        except mdb.Error, e:
            print "failedD, showAll, error %d: %s" % (e.args[0], e.args[1])

fd = failedD()
fd.showDefended()
#fd.showAll()
