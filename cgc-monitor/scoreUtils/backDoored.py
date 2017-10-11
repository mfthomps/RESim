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
import rcbsSQL
class backDoored():
    def __init__(self):
        self.con = None
        try:
            self.con = mdb.connect('localhost', 'cgc', 'password')
            t_cur = self.con.cursor()
            t_cur.execute('USE pov_scores_db')
        except mdb.Error, e:
            print "backDoored, init, error %d: %s" % (e.args[0], e.args[1])
        self.rcbs = rcbsSQL.rcbsSQL(self.con)
        here=os.getcwd()
        self.rcbs.scheduleLoad(os.path.join(here,'schedule.json'))

    def doAll(self):
        did_that = []
        try:
            q_cur = self.con.cursor()
            t_cur = self.con.cursor()
            r_cur = self.con.cursor()
            s_cur = self.con.cursor()
            cmd = "SELECT csid FROM pov_scores_db.cb_map"
            t_cur.execute(cmd)
            rows = t_cur.fetchall()
            for (csid) in rows:
                cmd = "SELECT hash FROM pov_scores_db.cb_map WHERE csid = '%s'" % csid
                r_cur.execute(cmd)
                hash_id = r_cur.fetchone()[0]
                ref = self.rcbs.getReference(csid[0])
                print('try %s, ref is %s' % (str(csid), str(ref)))
                cmd = "SELECT rcb, team, round FROM rcbs_by_round WHERE hash = '%s' AND team != 0  ORDER BY round, team" % (hash_id)
                s_cur.execute(cmd)
                a_row = s_cur.fetchall()
                for (rcb, team, round_id) in a_row:
                    if rcb not in ref and rcb not in did_that:
                        print('%s %d %d' % (rcb, team, round_id))
                        did_that.append(rcb)
                        #cmd = "SELECT defend_team, throw_team, round, throw_number FROM pov_rcb_scores WHERE rcb = '%s' AND defend_team != %d" % (rcb, team)
                        cmd = "SELECT team, round FROM rcbs_by_round WHERE rcb = '%s' AND team != %d" % (rcb, team)
                        q_cur.execute(cmd)
                        q_rows = q_cur.fetchall()
                        for (team, round_id) in q_rows:
                            print('RE USED: team: %d round: %d' % (team, round_id))
                        #for (defend_team, pov_team, round_id, throw) in q_rows:
                        #    print('BACK DOORED: def:%d pov:%d round %d %d' % (defend_team, pov_team, round_id, throw))
        except mdb.Error, e:
            print "rcbsSQL, teamsScoredOnCB query, error %d: %s" % (e.args[0], e.args[1])

bd = backDoored()
bd.doAll()
