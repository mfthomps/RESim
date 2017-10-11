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
from monitorLibs import configMgr
from monitorLibs import szk
class createScoreViews():
    def __init__(self):
        self.con = None
        try:
            self.con = mdb.connect('localhost', 'cgc', 'password')
            t_cur = self.con.cursor()
            t_cur.execute('USE pov_scores_db')

        except mdb.Error, e:
            print "createScoreViews, init, error %d: %s" % (e.args[0], e.args[1])

    def dropViews(self):
        try:
            t_cur = self.con.cursor()
            t_cur.execute("DROP VIEW IF EXISTS pov_hash_scores")
            t_cur.execute("DROP VIEW IF EXISTS pov_rcb_scores")
            t_cur.execute("DROP VIEW IF EXISTS pov_thrown")
            t_cur.execute("DROP VIEW IF EXISTS scores_by_round")
            t_cur.execute("DROP VIEW IF EXISTS filter_rcbs_by_round")
            t_cur.execute("DROP VIEW IF EXISTS avail_scores")
            t_cur.execute("DROP VIEW IF EXISTS avail_rcb")
            t_cur.execute("DROP VIEW IF EXISTS perform_rcb")
        except mdb.Error, e:
            print "doViews, drop, error %d: %s" % (e.args[0], e.args[1])


    def createViews(self):
        try:
            t_cur = self.con.cursor()
            cmd =  "CREATE VIEW pov_hash_scores AS \
                      SELECT cb_map.csid, throw_team, defend_team, pov_type, round, throw_number, pov_file, hash FROM pov_scores, cb_map \
                            WHERE pov_scores.csid = cb_map.csid"
            t_cur.execute(cmd)
            cmd = "CREATE VIEW pov_rcb_scores AS \
                      SELECT pov_hash_scores.csid, throw_team, defend_team, pov_type, pov_hash_scores.round, throw_number, pov_hash_scores.hash, rcb, pov_file \
                          FROM pov_hash_scores, rcbs_by_round WHERE pov_hash_scores.round = rcbs_by_round.round \
                          AND pov_hash_scores.hash = rcbs_by_round.hash AND team = defend_team"
            t_cur.execute(cmd)
            ''' povs that were actually thrown '''
            cmd = "CREATE VIEW pov_thrown AS \
                      SELECT pov_file, pov_hash, povs_by_round.round, povs_by_round.hash, throw_team, povs_by_round.team, rcb, num_throws FROM povs_by_round, rcbs_by_round WHERE \
                         povs_by_round.team = rcbs_by_round.team AND povs_by_round.round = rcbs_by_round.round AND povs_by_round.hash = rcbs_by_round.hash"
            t_cur.execute(cmd)
            cmd = "CREATE VIEW scores_by_round AS \
                      SELECT DISTINCT csid, throw_team, defend_team, pov_type, round, pov_file FROM pov_scores"
            t_cur.execute(cmd)
            cmd = "CREATE VIEW filter_rcbs_by_round AS \
                      SELECT rcbs_by_round.round, rcbs_by_round.hash, rcbs_by_round.team, rcb, filter  FROM rcbs_by_round, filters_by_round WHERE \
                         rcbs_by_round.hash = filters_by_round.hash AND rcbs_by_round.team = filters_by_round.team AND rcbs_by_round.round = filters_by_round.round"
            t_cur.execute(cmd)
            cmd =  "CREATE VIEW avail_scores AS \
                      SELECT cb_map.csid, round, team, avail FROM avail_by_round, cb_map \
                            WHERE avail_by_round.hash = cb_map.hash"
            t_cur.execute(cmd)
            cmd =  "CREATE VIEW avail_rcb AS \
                      SELECT avail_by_round.round, avail_by_round.team, avail, avail_by_round.hash, rcb FROM avail_by_round, rcbs_by_round \
                            WHERE avail_by_round.hash = rcbs_by_round.hash AND avail_by_round.team = rcbs_by_round.team and avail_by_round.round = rcbs_by_round.round"
            t_cur.execute(cmd)
            cmd =  "CREATE VIEW perform_rcb AS \
                      SELECT perform_by_round.round, perform_by_round.team, ref_cycles, cpu_cycles, filesize, minflt, maxrss, walltime, exectime, perform_by_round.hash, rcb FROM perform_by_round, rcbs_by_round \
                            WHERE perform_by_round.hash = rcbs_by_round.hash AND perform_by_round.team = rcbs_by_round.team and perform_by_round.round = rcbs_by_round.round"
            t_cur.execute(cmd)
        except mdb.Error, e:
            print "doViews, create, error %d: %s" % (e.args[0], e.args[1])
sv = createScoreViews()
sv.dropViews()
sv.createViews()
