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
'''
Drop and create all of the tables within the pov_scores_db --
A poor name choice, also contains rcbs by round and team.
'''
class rebuildScoreTables():
    def __init__(self):
        self.con = None
        try:
            self.con = mdb.connect('localhost', 'cgc', 'password')
        except mdb.Error, e:
            print "rebuildScoreTables, init, error %d: %s" % (e.args[0], e.args[1])

    def dropAll(self):
        retval = False
        try:
            t_cur = self.con.cursor()
            t_cur.execute("DROP TABLE IF EXISTS pov_scores_db.pov_scores")
            t_cur.execute("DROP TABLE IF EXISTS pov_scores_db.cb_map")
            t_cur.execute("DROP TABLE IF EXISTS pov_scores_db.rcbs_by_round")
            t_cur.execute("DROP TABLE IF EXISTS pov_scores_db.filters_by_round")
            t_cur.execute("DROP TABLE IF EXISTS pov_scores_db.povs_by_round")
            t_cur.execute("DROP TABLE IF EXISTS pov_scores_db.function_fails")
            t_cur.execute("DROP TABLE IF EXISTS pov_scores_db.avail_by_round")
            t_cur.execute("DROP TABLE IF EXISTS pov_scores_db.map_to_forensics")
            t_cur.execute("DROP TABLE IF EXISTS pov_scores_db.react_defend")
            t_cur.execute("DROP TABLE IF EXISTS pov_scores_db.perform_by_round")
        except mdb.Error, e:
            print "error in dropAll %d: %s" % (e.args[0], e.args[1])

    def povScores(self):
        retval = False
        try:
            t_cur = self.con.cursor()
            cmd = "CREATE DATABASE IF NOT EXISTS pov_scores_db CHARACTER SET latin1"
            print 'command is %s' % cmd
            t_cur.execute(cmd)
            cmd =  "CREATE TABLE pov_scores_db.pov_scores (\
                      csid VARCHAR(128), \
                      throw_team INT,\
                      defend_team INT,\
                      pov_type INT,\
                      round INT,\
                      throw_number INT,\
                      pov_file VARCHAR(128))"
            t_cur.execute(cmd)
            cmd =  "CREATE TABLE pov_scores_db.rcbs_by_round (\
                      round INT,\
                      team INT,\
                      hash VARCHAR(128), \
                      rcb VARCHAR(128),\
                      INDEX(round, team, hash))"
            t_cur.execute(cmd)
            cmd =  "CREATE TABLE pov_scores_db.avail_by_round (\
                      round INT,\
                      team INT,\
                      hash VARCHAR(128), \
                      avail float, \
                      INDEX(round, team, hash))"
            t_cur.execute(cmd)
            cmd =  "CREATE TABLE pov_scores_db.filters_by_round (\
                      round INT,\
                      team INT,\
                      hash VARCHAR(128), \
                      filter VARCHAR(128),\
                      INDEX(round, team, hash))"
            t_cur.execute(cmd)
            cmd =  "CREATE TABLE pov_scores_db.povs_by_round (\
                      round INT,\
                      team INT,\
                      hash VARCHAR(128), \
                      throw_team INT,\
                      num_throws INT,\
                      pov_file VARCHAR(128),\
                      pov_hash VARCHAR(128),\
                      INDEX(round, team, hash))"
            t_cur.execute(cmd)
            cmd =  "CREATE TABLE pov_scores_db.function_fails (\
                      hash VARCHAR(128), \
                      round INT,\
                      team INT,\
                      percent INT,\
                      INDEX(round, team, hash))"
            t_cur.execute(cmd)
            cmd =  "CREATE TABLE pov_scores_db.map_to_forensics (\
                      common VARCHAR(128), \
                      pov_team INT,\
                      defend_team INT,\
                      round INT,\
                      json VARCHAR(128))"
            t_cur.execute(cmd)
            cmd =  "CREATE TABLE pov_scores_db.react_defend (\
                      csid VARCHAR(128), \
                      defend_team INT,\
                      rcb_round INT,\
                      fail_round INT,\
                      score_round INT)"
            t_cur.execute(cmd)
            cmd =  "CREATE TABLE pov_scores_db.perform_by_round (\
                      round INT,\
                      team INT,\
                      hash VARCHAR(128), \
                      ref_cycles LONG, \
                      cpu_cycles LONG, \
                      filesize INT, \
                      minflt INT, \
                      maxrss INT, \
                      walltime float, \
                      exectime float, \
                      INDEX(round, team, hash))"
            t_cur.execute(cmd)

        except mdb.Error, e:
            print "error pov_scores, %d: %s" % (e.args[0], e.args[1])
            exit(1)

    def cbMap(self):
        try:
            t_cur = self.con.cursor()
            cmd = "CREATE TABLE pov_scores_db.cb_map(\
                      hash VARCHAR(128), \
                      csid VARCHAR(128))"
            t_cur.execute(cmd)

        except mdb.Error, e:
            print "error cbMap, %d: %s" % (e.args[0], e.args[1])
            exit(1)

    def loadScores(self, fname):
        ''' mysql LOAD from file crippled due to security issues'''
        try:
            t_cur = self.con.cursor()
            t_cur.execute('USE pov_scores_db')
            with open(fname) as fh:
                for line in fh:
                    csid, throw_team, defend_team, pov_type, round_id, throw_number, pov_file = line.split(',')
                    cmd = 'INSERT INTO pov_scores_db.pov_scores (csid, throw_team, defend_team, pov_type, round, throw_number, pov_file) VALUES ("%s", %d, %d, %d, %d, %d, "%s") ' % (csid, int(throw_team), int(defend_team), int(pov_type), int(round_id), int(throw_number), pov_file)
                    #print 'command is %s' % cmd
                    t_cur.execute(cmd)
            self.con.commit()
        except mdb.Error, e:
            print "error pov_scores, %d: %s" % (e.args[0], e.args[1])
                
    def loadMap(self, fname):
        try:
            t_cur = self.con.cursor()
            t_cur.execute('USE pov_scores_db')
            with open(fname) as fh:
                for line in fh:
                    hash_id, csid = line.split(' ')
                    cmd = 'INSERT INTO pov_scores_db.cb_map (hash, csid) VALUES("%s","%s")' % (hash_id.strip(), csid.strip())
                    #print 'command is %s' % cmd
                    t_cur.execute(cmd)
            self.con.commit()
        except mdb.Error, e:
            print "error pov_scores, %d: '%s'" % (e.args[0], e.args[1])

    def loadRCBs(self, fname):
        try:
            t_cur = self.con.cursor()
            t_cur.execute('USE pov_scores_db')
            with open(fname) as fh:
                for line in fh:
                    round_id, team, hash_id, rcb = line.split(',')
                    cmd = 'INSERT INTO pov_scores_db.rcbs_by_round (round, team, hash, rcb) VALUES(%d, %d, "%s", "%s")' % (int(round_id), int(team), hash_id.strip(), rcb.strip())
                    #print 'command is %s' % cmd
                    t_cur.execute(cmd)
            self.con.commit()
        except mdb.Error, e:
            print "error pov_scores, %d: %s" % (e.args[0], e.args[1])

    def loadFilters(self, fname):
        try:
            t_cur = self.con.cursor()
            t_cur.execute('USE pov_scores_db')
            with open(fname) as fh:
                for line in fh:
                    round_id, team, hash_id, rules = line.split(',')
                    cmd = 'INSERT INTO pov_scores_db.filters_by_round (round, team, hash, filter) VALUES(%d, %d, "%s", "%s")' % (int(round_id), int(team), hash_id.strip(), rules.strip())
                    #print 'command is %s' % cmd
                    t_cur.execute(cmd)
            self.con.commit()
        except mdb.Error, e:
            print "error pov_scores, %d: %s" % (e.args[0], e.args[1])

    def loadAvail(self, fname):
        try:
            t_cur = self.con.cursor()
            t_cur.execute('USE pov_scores_db')
            with open(fname) as fh:
                for line in fh:
                    round_id, team, hash_id, avail_str = line.split(',')
                    try:
                        avail = float(avail_str.strip())     
                    except:
                        print('cannot convert <%s> to float' % avail_str)
                        continue
                    cmd = 'INSERT INTO pov_scores_db.avail_by_round (round, team, hash, avail) VALUES(%d, %d, "%s", %f)' % (int(round_id), int(team), hash_id.strip(), avail)
                    #print 'command is %s' % cmd
                    t_cur.execute(cmd)
            self.con.commit()
        except mdb.Error, e:
            print "error loadAvail, %d: %s" % (e.args[0], e.args[1])

    def loadPerform(self, fname):
        try:
            t_cur = self.con.cursor()
            t_cur.execute('USE pov_scores_db')
            with open(fname) as fh:
                for line in fh:
                    round_id, team, hash_id, ref_cycle_str, cpu_cycle_str, file_str, minflt_str, maxrss_str, walltime_str, exectime_str = line.split(',')
                    try:
                        ref_cycles = long(ref_cycle_str.strip())     
                        cpu_cycles = long(cpu_cycle_str.strip())     
                        filesize = int(file_str.strip())     
                        minflt = int(minflt_str.strip())     
                        maxrss = int(maxrss_str.strip())     
                        walltime = float(walltime_str.strip())     
                        exectime = float(exectime_str.strip())     
                    except:
                        print('cannot convert %s' % line)
                        continue
                    cmd = 'INSERT INTO pov_scores_db.perform_by_round (round, team, hash, ref_cycles, cpu_cycles, filesize, minflt, maxrss, walltime, exectime) VALUES(%d, %d, "%s", %d, %d, %d, %d, %d, %f, %f)' % (int(round_id), int(team), hash_id.strip(), ref_cycles, cpu_cycles, filesize, minflt, maxrss, walltime, exectime)
                    #print 'command is %s' % cmd
                    t_cur.execute(cmd)
            self.con.commit()
        except mdb.Error, e:
            print "error loadPerform, %d: %s" % (e.args[0], e.args[1])

    def loadPovs(self, fname):
        try:
            t_cur = self.con.cursor()
            t_cur.execute('USE pov_scores_db')
            with open(fname) as fh:
                for line in fh:
                    round_id, team, hash_id, throw_team, num_throws, pov_file = line.split(',')
                    parts = pov_file.strip().split('-')
                    try:
                        pov_hash = parts[1]
                    except:
                        print('wtf %s' % pov_file)
                        print('wtf %s' % str(pov_file.split('-')))
                        continue
                    cmd = 'INSERT INTO pov_scores_db.povs_by_round (round, team, hash, throw_team, num_throws, pov_file, pov_hash) VALUES(%d, %d, "%s", %d, %d, "%s", "%s")' % (int(round_id), int(team), hash_id.strip(), int(throw_team), int(num_throws), pov_file.strip(), pov_hash.strip())
                    #print 'command is %s' % cmd
                    t_cur.execute(cmd)
            self.con.commit()
        except mdb.Error, e:
            print "error pov_scores, %d: %s" % (e.args[0], e.args[1])

    def loadFunctionFails(self, fname):
        try:
            t_cur = self.con.cursor()
            t_cur.execute('USE pov_scores_db')
            with open(fname) as fh:
                for line in fh:
                    hash_id, round_id, team, percent = line.split(',')
                    cmd = 'INSERT INTO pov_scores_db.function_fails (hash, round, team, percent) VALUES("%s", %d, %d, %d)' % (hash_id.strip(), int(round_id), int(team), int(percent))
                    #print 'command is %s' % cmd
                    t_cur.execute(cmd)
            self.con.commit()
        except mdb.Error, e:
            print "error functionFails, %d: %s" % (e.args[0], e.args[1])

    def loadMapToForensics(self, fname):
        try:
            t_cur = self.con.cursor()
            t_cur.execute('USE pov_scores_db')
            with open(fname) as fh:
                for line in fh:
                    common, pov_team, defend_team, round_id, json_file = line.split(',')
                    cmd = 'INSERT INTO pov_scores_db.map_to_forensics (common, pov_team, defend_team, round, json) VALUES("%s", %d, %d, %d, "%s")' % (common, int(pov_team), int(defend_team),
                                 int(round_id), json_file)
                    #print 'command is %s' % cmd
                    t_cur.execute(cmd)
            self.con.commit()
        except mdb.Error, e:
            print "error map_to_forensics, %d: %s" % (e.args[0], e.args[1])
   
rst = rebuildScoreTables()
rst.dropAll()
rst.povScores() 
rst.cbMap() 
cwd = os.getcwd()
rst.loadScores(os.path.join(cwd,'scores_full.csv'))
rst.loadMap(os.path.join(cwd,'cbmap.txt'))
rst.loadRCBs(os.path.join(cwd,'rcbs_by_round.csv'))
rst.loadFilters(os.path.join(cwd,'filters_by_round.csv'))
rst.loadPovs(os.path.join(cwd,'povs_by_round.csv'))
rst.loadFunctionFails(os.path.join(cwd,'functionality.csv'))
rst.loadAvail(os.path.join(cwd,'avail_by_round.csv'))
rst.loadPerform(os.path.join(cwd,'perform_by_round.csv'))
rst.loadMapToForensics(os.path.join(cwd,'map_to_forensics.csv'))
