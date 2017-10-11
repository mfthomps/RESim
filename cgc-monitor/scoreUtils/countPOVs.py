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
import ghostScores
from monitorLibs import configMgr
from monitorLibs import szk

import rcbsSQL
'''
For each CSET, display percentage of rounds that each team
landed a POV, the percentage in which it failed to defend, and the
percentage of rounds in which a patched RCB was fielded.
'''
class povTest():
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

    def hashes_thrown(self):
        try:
            t_cur = self.con.cursor()
            s_cur = self.con.cursor()
            cmd = 'SELECT distinct pov_hash FROM pov_scores_db.pov_thrown'
            t_cur.execute(cmd)
            rows = t_cur.fetchall()
            #print('len of counts is %d' % len(counts))
            for (pov_file) in rows:
                print('file: %s' % (pov_file))
            print('%d records' % len(rows))
        except mdb.Error, e:
            print "scoresSQL, query, error %d: %s" % (e.args[0], e.args[1])

    def hashes_requested(self):
        try:
            t_cur = self.con.cursor()
            s_cur = self.con.cursor()
            cmd = 'SELECT distinct pov_hash FROM pov_scores_db.povs_by_round'
            t_cur.execute(cmd)
            rows = t_cur.fetchall()
            #print('len of counts is %d' % len(counts))
            for (pov_file) in rows:
                print('file: %s' % (pov_file))
        except mdb.Error, e:
            print "scoresSQL, query, error %d: %s" % (e.args[0], e.args[1])

    def scores_by_csid(self):
        print('%15s %5s %s' % ('csid', 'count', 'type'))    
        try:
            t_cur = self.con.cursor()
            s_cur = self.con.cursor()
            cmd = 'SELECT csid, pov_type, count(*) FROM pov_scores_db.scores_by_round GROUP BY csid, pov_type'
            t_cur.execute(cmd)
            rows = t_cur.fetchall()
            #print('len of counts is %d' % len(counts))
            for (csid, pov_type, count) in rows:
                print('%15s %5d %d' % (csid, count, pov_type))
        except mdb.Error, e:
            print "scoresSQL, query, error %d: %s" % (e.args[0], e.args[1])

    def load_red(self, f_name):
        rcb_list = []
        with open(f_name) as fh:
            for line in fh:
                if line.startswith('#'):
                    continue
                if line.strip().startswith('YES'):
                    parts = line.split()
                    rcb_list.append(parts[2])
        return rcb_list

    def didThisRCBSet(self, rcb_list, list_of_lists): 
        if len(list_of_lists) > 0:
            #print('didThis for %s len of list_of_lists is %d' % (str(rcb_list), len(list_of_lists)))
            pass
        if len(list_of_lists) == 0:
            return False
        for did_list in list_of_lists:
            found_set = True
            #print('check list %s' % str(did_list))
            for did in did_list:
                #print('is %s in %s' % (did, str(rcb_list)))
                if did not in rcb_list:
                    found_set = False
            if found_set:
                return True
        return False

    def defend_by_team(self, team):
        #print('%15s %5s %s' % ('csid', 'count', 'type'))    
        red_file = './deepRedDefend.txt'
        red_honey = []
        team = int(team)
        ghost_scores = None
        did_list = {}
        did_segv_list = {}
        if team == 3 and os.path.isfile(red_file):
            red_honey = self.load_red(red_file)
            fname = 'ghost_scores.txt'
            ghost_scores = ghostScores.ghostScores(fname)
            fname = 'ghost_segv.txt'
            ghost_segv = ghostScores.ghostScores(fname)
            print('# Summary of Deep Red defenses.  Each CB service is presented separately below.')
            print('# RCBs are listed with their round numbers, availability, and with an ')
            print('# indication of whether they contained a honeypot')
            print('# Occurrences of POVs causing SEGV without a score and POVs "scoring" on a honeypot are noted')
            print('# As are POVs actually scoring')
        else:
            print('# Summary of team %d defenses.  Each CB service is presented separately below.' % team)
            print('# RCBs are listed with their round numbers and availability.  Scores against RCBs are noted.')
        ''' display the rcbs deployed by a given team and successful povs thrown against them'''
        try:
            r_cur = self.con.cursor()
            t_cur = self.con.cursor()
            s_cur = self.con.cursor()
            w_cur = self.con.cursor()
            y_cur = self.con.cursor()
            cmd = "SELECT DISTINCT csid FROM pov_scores_db.cb_map ORDER BY csid"
            r_cur.execute(cmd)
            csid_list = r_cur.fetchall()
            for csid in csid_list:
                did_rcb_sets = []
                did_react = False
                csid = csid[0]
                ''' Annotate CSID line with info on introduction round, first fail, first score... '''
                first_round = self.rcbs.firstRound(csid)
                last_round = first_round + self.rcbs.numRounds(csid) - 1
                cmd = 'SELECT MIN(round) FROM pov_scores_db.pov_scores WHERE csid = "%s" AND defend_team = %d' % (csid, team)
                y_cur.execute(cmd)
                first_score = y_cur.fetchone()
                first_fail = ''
                fail_round = 0
                score_round = 0
                if first_score is not None and first_score[0] is not None:
                    first_fail = 'First failed defense in %s.' % first_score[0] 
                    fail_round = first_score[0]
                cmd = 'SELECT MIN(round) FROM pov_scores_db.pov_scores WHERE csid = "%s" AND throw_team = %d' % (csid, team)
                y_cur.execute(cmd)
                first_score = y_cur.fetchone()
                first_by_red = ''
                if first_score is not None and first_score[0] is not None:
                    first_by_red = 'First score by this team (%d) in %s' % (team, first_score[0]) 
                    score_round = first_score[0]
                print('\n\n%s, introduced in round %d, through %d. %s %s' % (csid, first_round, last_round, first_fail, first_by_red))
                ''' Look at RCBs deployed for each round for this csid '''
                ref = self.rcbs.getReference(csid)
                hash_id = self.hash_from_csid(csid)
                cmd = 'SELECT DISTINCT round FROM pov_scores_db.rcbs_by_round WHERE hash = "%s" AND team = %d AND round > 0 ORDER BY round' % (hash_id, team)
                t_cur.execute(cmd)
                round_list = t_cur.fetchall()
                prev_rcb = None
                prev_filter = None
                round_index = 0
                using_ref = True
                for round_id in round_list:
                    found_a_pov = False
                    round_id = round_id[0]
                    cmd = 'SELECT avail FROM pov_scores_db.avail_by_round WHERE hash = "%s" AND team = %d AND round = %d' % (hash_id, team, int(round_id))
                    w_cur.execute(cmd)
                    avail = 999.999
                    try:
                        avail = w_cur.fetchone()[0]
                    except:
                        print('no avail for %s' % cmd)
                    #print('ROUND %d *************************' % round_id)
                    cmd = 'SELECT filter FROM pov_scores_db.filters_by_round WHERE hash = "%s" AND team = %d AND round = %d' % (hash_id, team, int(round_id))
                    w_cur.execute(cmd)
                    result = w_cur.fetchone()
                    if result is not None:
                        filter_id = result[0]
                        if prev_filter is None or prev_filter != filter_id:
                            print('     %d deployed filter %s  avail: %f' % (round_id, filter_id, avail)) 
                            prev_filter = filter_id
                    elif prev_filter is not None:
                        print('     %d reverted filter to null' % round_id)
                        prev_filter = None
                    cmd = 'SELECT rcb FROM pov_scores_db.rcbs_by_round WHERE hash = "%s" AND team = %d AND round = %d' % (hash_id, team, int(round_id))
                    w_cur.execute(cmd)
                    rows = w_cur.fetchall()
                    next_round_id = 9999
                    round_index += 1
                    if len(round_list) > round_index:
                        next_round_id = int(round_list[round_index][0])
                    if len(rows) == 0:
                        print('no rcb for %s' % cmd)
                        continue
                    is_ref = True
                    rcb_list = []
                    for (rcb) in rows:
                        rcb = rcb[0]
                        if rcb not in ref:
                            is_ref = False
                        rcb_list.append(rcb)
                    if not is_ref:
                        using_ref = False
                        if not self.didThisRCBSet(rcb_list, did_rcb_sets):
                            did_rcb_sets.append(rcb_list)
                            #print('appended %s, should not be %s' % (str(rcb_list), str(did_rcb_sets)))

                            is_honey = ''
                            for (rcb) in rows:
                                rcb = rcb[0]
                                if rcb in red_honey:
                                    is_honey="(honey_pot)"
                                if True or rcb != prev_rcb:
                                    print('    %3d %20s availability: %f %s' % (round_id, rcb, avail, is_honey))
                                    if not did_react:
                                        self.addReactDefend(csid, team, round_id, fail_round, score_round)
                                        did_react = True
                                prev_rcb = rcb
                            if ghost_scores is not None:
                                if rcb_list[0] not in did_list:
                                    did_list[rcb_list[0]] = []
                                if rcb_list[0] not in did_segv_list:
                                    did_segv_list[rcb_list[0]] = []
                                pov_list = ghost_scores.getHoneyPOVs(csid, rcb_list)
                                for pov in pov_list:
                                    if pov.pov_file not in did_list[rcb_list[0]]:
                                        rounds_pov_thrown = self.rounds_thrown(csid, pov.thrower, 3, pov.pov_file, rcb_list[0]) 
                                        #hash_name = pov.pov_file.split('-')[1][:8]
                                        print('\t  team %s ate honey in rounds %s' % (pov.thrower, rounds_pov_thrown))
                                        did_list[rcb_list[0]].append(pov.pov_file)
                                pov_list = ghost_segv.getHoneyPOVs(csid, rcb_list)
                                for pov in pov_list:
                                    if pov.pov_file not in did_segv_list[rcb_list[0]]:
                                        rounds_pov_thrown = self.rounds_thrown(csid, pov.thrower, 3, pov.pov_file, rcb_list[0]) 
                                        #hash_name = pov.pov_file.split('-')[1][:8]
                                        print('\t  team %s SEGV in rounds %s' % (pov.thrower, rounds_pov_thrown))
                                        did_segv_list[rcb_list[0]].append(pov.pov_file)
    
                        cmd = 'SELECT round, throw_team, pov_file, COUNT(*) FROM pov_scores_db.pov_scores WHERE defend_team = %d and round >= %d and round < %d and csid = "%s" GROUP BY round, throw_team, csid' % (team, int(round_id), next_round_id, csid)
                        #print cmd
                        s_cur.execute(cmd)
                        throw_list = s_cur.fetchall()
                        prev_round = 0
                        if len(throw_list) == 0:
                            #ghost_scores.printScores(csid, 0, 999)
                            pass
                        else:

                            for (throw_round, throw_team, pov_file, count) in throw_list:
                                #if not found_a_pov:
                                #    ghost_scores.printScores('any before throw round?', csid, round_id, throw_round)
                                found_a_pov = True
                                #print('\t  %d (%d) %s <%s>' % (throw_round, count, throw_team, pov_file.strip()))
                                print('\t  round %2d  team %d scored %d times' % (throw_round, throw_team, count))
                                #if prev_round != throw_round:
                                #    ghost_scores.printScores('round change', csid, throw_round, next_round_id)
                                prev_round = throw_round
                                #print throw_team
                    else:
                        if not using_ref:
                            print('     %d Reverted to Reference CB' % round_id)
                            using_ref = True
                        
                if not did_react:
                    self.addReactDefend(csid, team, 0, fail_round, score_round)
                              

        except mdb.Error, e:
            print "scoresSQL, query, error %d: %s" % (e.args[0], e.args[1])

    def listCSID(self):

        try:
            r_cur = self.con.cursor()
            t_cur = self.con.cursor()
            s_cur = self.con.cursor()
            w_cur = self.con.cursor()
            y_cur = self.con.cursor()
            cmd = "SELECT DISTINCT csid FROM pov_scores_db.cb_map ORDER BY csid"
            r_cur.execute(cmd)
            csid_list = r_cur.fetchall()
            for csid in csid_list:
                version = 0
                csid = csid[0]
                print csid
        except mdb.Error, e:
            print "scoresSQL, query, error %d: %s" % (e.args[0], e.args[1])
    def perform(self, team):
        team = int(team)
        print('cpu cycle & memory ratios (rcb/ref) for team %d RCBs with function >= 99%%' % team)
        print('these are averages over all rounds')
        try:
            r_cur = self.con.cursor()
            t_cur = self.con.cursor()
            s_cur = self.con.cursor()
            w_cur = self.con.cursor()
            y_cur = self.con.cursor()
            cmd = "SELECT DISTINCT csid FROM pov_scores_db.cb_map ORDER BY csid"
            r_cur.execute(cmd)
            csid_list = r_cur.fetchall()
            for csid in csid_list:
                version = 0
                csid = csid[0]
                hash_id = self.hash_from_csid(csid)
                ref = self.rcbs.getReference(csid)
                cmd = "SELECT DISTINCT round, ref_cycles, filesize, minflt, maxrss, walltime, exectime FROM pov_scores_db.perform_rcb WHERE team = %d AND hash = '%s' ORDER BY round" % (team, hash_id)
                y_cur.execute(cmd)
                result = y_cur.fetchall()
                cycle_list = []
                mem_list = []
                a_mem_list = []
                walltime_list = []
                exectime_list = []
                for (round_id, cycles, filesize, minflt, maxrss, walltime, exectime) in result:

                    cmd = "SELECT DISTINCT percent FROM pov_scores_db.function_fails WHERE hash = '%s' AND team = '%d' AND round = %d" % (hash_id, team, round_id)
                    t_cur.execute(cmd)
                    percent = t_cur.fetchone()
                    if percent is not None:
                        #print('fail poll %f' % percent[0])
                        if percent[0] < 99.0:
                            continue


                    cmd = 'SELECT rcb FROM pov_scores_db.rcbs_by_round WHERE hash = "%s" AND team = %d AND round = %d' % (hash_id, team, round_id)
                    w_cur.execute(cmd)
                    rows = w_cur.fetchall()
                    is_ref = True
                    for (rcb) in rows:
                        rcb = rcb[0]
                        if rcb not in ref:
                            is_ref = False
                    if is_ref:
                        continue


                    cmd = "SELECT ref_cycles, filesize, minflt, maxrss, walltime FROM pov_scores_db.perform_by_round WHERE team = 0 AND hash = '%s' AND round = %d" % (hash_id, round_id)
                    t_cur.execute(cmd)
                    baseline = t_cur.fetchone()
                    if baseline is None:
                        print('nothing for %s' % cmd)
                        exit(1)
                    b_cycles, b_filesize, b_minflt, b_maxrss, b_walltime = baseline
                    #print('maxrss %f  b_maxrss %f' % (maxrss, b_maxrss))
                    #print('minflt %f  b_minflt %f' % (minflt, b_minflt))
                    cycles = long(cycles)
                    b_cycles = long(b_cycles)
                    r_cycles = float(cycles)/float(b_cycles)
                    r_memory = float(minflt+maxrss)/float(b_minflt+b_maxrss)
                    a_memory = (minflt+maxrss) - (b_minflt+b_maxrss)
                    r_filesize = float(filesize)/float(b_filesize)
                    r_walltime = walltime/b_walltime
                    cycle_list.append(r_cycles)
                    mem_list.append(r_memory)
                    a_mem_list.append(a_memory)
                    walltime_list.append(r_walltime)
                    exectime_list.append(exectime)
                    #print('csid: %s round %d cycles %f file %f, memory %f a_memory %d walltime %f' % (csid, round_id, r_cycles, r_filesize, r_memory, a_memory, r_walltime))
                if len(cycle_list) > 0:
                    
                    print('csid:%s cycles:%f  memory:%f abs_memory:%d walltime:%f exectime:%f' % (csid, sum(cycle_list)/len(cycle_list), sum(mem_list)/len(mem_list), sum(a_mem_list)/len(a_mem_list), sum(walltime_list)/len(walltime_list), sum(exectime_list)/len(exectime_list)))
        except mdb.Error, e:
            print "scoresSQL, perform, error %d: %s" % (e.args[0], e.args[1])

    def chart(self, team):
        team = int(team)
        print('RCB versions for team %d by round ("1" is reference)' % team)
        print('   x--was scored on')
        print('   y--this team scored')
        print('   z--both')
        print('   0 -- above the rcb line indicates availability < 30%')
        try:
            r_cur = self.con.cursor()
            t_cur = self.con.cursor()
            s_cur = self.con.cursor()
            w_cur = self.con.cursor()
            y_cur = self.con.cursor()
            cmd = "SELECT DISTINCT csid FROM pov_scores_db.cb_map ORDER BY csid"
            r_cur.execute(cmd)
            csid_list = r_cur.fetchall()
            for csid in csid_list:
                version = 0
                rcb_set = {}
                csid = csid[0]
                first_round = self.rcbs.firstRound(csid)
                last_round = first_round + self.rcbs.numRounds(csid) - 1
                line = ''
                pov_line = ''
                avail_line = ''
                #print('first %d last %d' % (first_round, last_round))
                for round_id in range(first_round, last_round+1):
                    cmd = 'SELECT COUNT(*) FROM pov_scores_db.pov_scores WHERE csid = "%s" AND defend_team = %d AND round = %d' % (csid, team, round_id)
                    y_cur.execute(cmd)
                    result = y_cur.fetchone()[0]
                    #print('result %s' % str(result))
                    pov = ' '
                    if result > 0:
                        pov = 'x'
                    cmd = 'SELECT COUNT(*) FROM pov_scores_db.pov_scores WHERE csid = "%s" AND throw_team = %d AND round = %d' % (csid, team, round_id)
                    y_cur.execute(cmd)
                    result = y_cur.fetchone()[0]
                    if result > 0:
                        if pov == 'x':
                            pov = 'z'
                        else:
                            pov = 'y'
                        #print('%s owned in round %d' % (csid, round_id))
                    '''
                    cmd = 'SELECT filter FROM pov_scores_db.filters_by_round WHERE hash = "%s" AND team = %d AND round = %d' % (hash_id, team, int(round_id))
                    w_cur.execute(cmd)
                    result = w_cur.fetchone()
                    if result is not None:
                        filter_id = result[0]
                        if prev_filter is None or prev_filter != filter_id:
                            print('     %d deployed filter %s  avail: %f' % (round_id, filter_id, avail)) 
                            prev_filter = filter_id
                    elif prev_filter is not None:
                        print('     %d reverted filter to null' % round_id)
                        prev_filter = None
                    '''
                    hash_id = self.hash_from_csid(csid)
                    cmd = 'SELECT rcb FROM pov_scores_db.rcbs_by_round WHERE hash = "%s" AND team = %d AND round = %d' % (hash_id, team, int(round_id))
                    w_cur.execute(cmd)
                    result = w_cur.fetchall()
                    if len(result) > 0:
                        rcb = result[0]
                        if rcb not in rcb_set:
                            #print('rcb for %s is %s' % (csid, rcb))
                            version = str(len(rcb_set)+1)
                            rcb_set[rcb] = version
                        else:
                            version = rcb_set[rcb] 
                    else:
                        version = '-'
                    cmd = 'SELECT avail FROM pov_scores_db.avail_by_round WHERE hash = "%s" AND team = %d AND round = %d' % (hash_id, team, int(round_id))
                    w_cur.execute(cmd)
                    result = w_cur.fetchone()[0]
                    avail = ' '
                    if result < 0.3 and version != '-':
                        avail = '0'
                    line = "%s%s" % (line,version)
                    pov_line = "%s%s" % (pov_line, pov)
                    avail_line = "%s%s" % (avail_line, avail)
                print('%11s %s' % (' ', avail_line))
                print('%10s %s' % (csid, line))
                print('%11s %s' % (' ', pov_line))
                 
        except mdb.Error, e:
            print "scoresSQL, chart, error %d: %s" % (e.args[0], e.args[1])
 
                    
    def hash_from_csid(self, csid):
        hash_id = None
        try:
            r_cur = self.con.cursor()
            cmd = "SELECT hash FROM pov_scores_db.cb_map WHERE csid = '%s'" % csid
            r_cur.execute(cmd)
            r_cur.execute(cmd)
            hash_id = r_cur.fetchone()[0]
            #print('hash_id is %s' % hash_id)
        except:
           print "ountPovs, hash_from_csid, query, error %d: %s" % (e.args[0], e.args[1])
        return hash_id

    def csid_from_hash(self, hash_id):
        csid = None
        try:
            r_cur = self.con.cursor()
            cmd = "SELECT csid FROM pov_scores_db.cb_map WHERE hash = '%s'" % hash_id
            r_cur.execute(cmd)
            r_cur.execute(cmd)
            csid = r_cur.fetchone()[0]
            #print('csid is %s' % csid)
        except:
           print "ountPovs, csid_from_hash, query, error %d: %s" % (e.args[0], e.args[1])
        return csid

    def is_contiguous(self, a_list):
        if len(a_list) < 2:
            return False
        prev = a_list[0]
        for entry in a_list[1:]:
            if entry != (prev + 1): 
                return False
            prev = entry
        return True
   
    def rounds_thrown(self, csid, throw_team, defend_team, pov_file, rcb):
        retval = ""
        the_rounds = []
        try:
            hash_id = self.hash_from_csid(csid)
            r_cur = self.con.cursor()
            #cmd = "SELECT round FROM pov_scores_db.povs_by_round WHERE hash = '%s' AND throw_team = %d and team = %d and pov_file = '%s' ORDER BY round" % (hash_id, throw_team, defend_team, pov_file)
            cmd = "SELECT round FROM pov_scores_db.pov_thrown WHERE hash = '%s' AND throw_team = %d and team = %d and pov_file = '%s' AND rcb = '%s' ORDER BY round" % (hash_id, throw_team, defend_team, pov_file, rcb)
            r_cur.execute(cmd)
            result = r_cur.fetchall()
            for round_id in result:
                the_rounds.append(round_id[0]) 
            
            if self.is_contiguous(the_rounds):
                retval = '%d - %d' % (the_rounds[0], the_rounds[len(the_rounds)-1]) 
            elif len(the_rounds) > 0:
                retval = '%d' % the_rounds[0]
                for round_id in the_rounds[1:]:
                    retval = retval + ", " + '%d' % round_id
            return retval

        except mdb.Error, e:
            print "scoresSQL, query, error %d: %s" % (e.args[0], e.args[1])


    def povs_thrown(self, csid, throw_team, defend_team):
        print('POVS thrown by %d against %d for %s' % (throw_team, defend_team, csid))
        try:
            hash_id = self.hash_from_csid(csid)
            r_cur = self.con.cursor()
            cmd = "SELECT DISTINCT round, pov_file FROM pov_scores_db.povs_by_round WHERE hash = '%s' AND throw_team = %d and team = %d ORDER BY round" % (hash_id, throw_team, defend_team)
            r_cur.execute(cmd)
            rows = r_cur.fetchall()
            for (round_id, pov_file) in rows:
                print('%d %s' % (round_id, pov_file))

        except mdb.Error, e:
            print "scoresSQL, query, error %d: %s" % (e.args[0], e.args[1])

    
    def povs_by_csid(self, csid):
        #print('%15s %5s %s' % ('csid', 'count', 'type'))    
        try:
            r_cur = self.con.cursor()
            cmd = "SELECT hash FROM pov_scores_db.cb_map WHERE csid = '%s'" % csid
            r_cur.execute(cmd)
            hash_id = r_cur.fetchone()[0]
            #print('hash is %s' % hash_id)

            t_cur = self.con.cursor()
            s_cur = self.con.cursor()
            #cmd = 'SELECT round, throw_team, pov_file, SUM(num_throws) FROM pov_scores_db.povs_by_round WHERE hash = "%s" GROUP BY round, throw_team, pov_file ORDER BY round' % hash_id
            cmd = 'SELECT round, throw_team, pov_file, SUM(num_throws) FROM pov_scores_db.pov_thrown WHERE hash = "%s" GROUP BY round, throw_team, pov_file ORDER BY round' % hash_id
            t_cur.execute(cmd)
            rows = t_cur.fetchall()
            #print('len of counts is %d' % len(counts))
            for (round_id, throw_team, pov_file, count) in rows:
                print('%3d %d %20s %4d' % (round_id, throw_team, pov_file, count))
        except mdb.Error, e:
            print "scoresSQL, query, error %d: %s" % (e.args[0], e.args[1])

    def avail_score(self, csid, round_id, team):
        round_id = int(round_id)
        team = int(team)
        #print('%15s %5s %s' % ('csid', 'count', 'type'))    
        try:
            r_cur = self.con.cursor()
            cmd = "SELECT avail from pov_scores_db.avail_scores WHERE csid = '%s' AND round = %d and team = %d" % (csid, round_id, team)
            r_cur.execute(cmd)
            result = r_cur.fetchone()
            if result is None:
                print('no result for %s' % cmd)
            else:
                print('%s round %d team %d avail: %f' % (csid, round_id, team, result[0]))
        except mdb.Error, e:
            print "scoresSQL, query, error %d: %s" % (e.args[0], e.args[1])

    def avail_by_rcb(self, team, round_id, csid):
        ''' find availability of rcb used by team, where rcb matches that used in given round '''
        hash_id = self.hash_from_csid(csid)
        y_cur = self.con.cursor()
        r_cur = self.con.cursor()
        w_cur = self.con.cursor()
        round_id = int(round_id)
        team = int(team)
        retval = ""
        #print('%15s %5s %s' % ('csid', 'count', 'type'))    
        try:
            cmd = "SELECT DISTINCT rcb from pov_scores_db.rcbs_by_round WHERE hash = '%s' AND round = %d and team = %d" % (hash_id, round_id, team)
            y_cur.execute(cmd)
            rcb_list = y_cur.fetchall()
            for rcb in rcb_list:
                cmd = "SELECT round, avail FROM pov_scores_db.avail_rcb WHERE hash = '%s' AND team = %d ORDER BY round" % (hash_id, team)
                r_cur.execute(cmd)
                avail_list = r_cur.fetchall()
                for (round_id, avail) in avail_list:
                    add = ' round_%d:%4.3f' % (round_id, avail)
                    retval = retval+add 
        except mdb.Error, e:
            print "scoresSQL, query, error %d: %s" % (e.args[0], e.args[1])
        return retval

    def avail_round(self, round_id, team):
        y_cur = self.con.cursor()
        r_cur = self.con.cursor()
        w_cur = self.con.cursor()
        round_id = int(round_id)
        team = int(team)
        #print('%15s %5s %s' % ('csid', 'count', 'type'))    
        try:
            cmd = "SELECT DISTINCT csid FROM pov_scores_db.cb_map ORDER BY csid"
            r_cur.execute(cmd)
            csid_list = r_cur.fetchall()
            team = int(team)
            for csid in csid_list:
                hash_id = self.hash_from_csid(csid)
                csid = csid[0]
                ref = self.rcbs.getReference(csid)
                y_cur = self.con.cursor()
                cmd = "SELECT avail from pov_scores_db.avail_scores WHERE csid = '%s' AND round = %d and team = %d" % (csid, round_id, team)
                y_cur.execute(cmd)
                result = y_cur.fetchone()
                if result is None:
                    #print('no result for %s' % cmd)
                    pass
                else:
                    cmd = 'SELECT filter FROM pov_scores_db.filters_by_round WHERE hash = "%s" AND team = %d AND round = %d' % (hash_id, team, int(round_id))
                    w_cur.execute(cmd)
                    filter_result = w_cur.fetchone()
                    filter_display = ''
                    if filter_result is not None:
                        filter_display = 'filter '+filter_result[0]
                    avail_this = self.avail_by_rcb(team, round_id, csid)

                    print('%s %s round %d team %d avail: %f %s %s' % (csid, hash_id, round_id, team, result[0], avail_this, filter_display))
        except mdb.Error, e:
            print "scoresSQL, query, error %d: %s" % (e.args[0], e.args[1])

    def avail_ref(self, team): 
      print('# Team %s deployed reference CBs availability by round (zero may be down for filter)' % team)
      try:
        y_cur = self.con.cursor()
        r_cur = self.con.cursor()
        w_cur = self.con.cursor()
        z_cur = self.con.cursor()
        cmd = "SELECT DISTINCT csid FROM pov_scores_db.cb_map ORDER BY csid"
        r_cur.execute(cmd)
        csid_list = r_cur.fetchall()
        team = int(team)
        for csid in csid_list:
            csid = csid[0]
            ref = self.rcbs.getReference(csid)
            hash_id = self.hash_from_csid(csid)
            cmd = 'SELECT DISTINCT round FROM pov_scores_db.rcbs_by_round WHERE hash = "%s" AND team = %d AND round > 0 ORDER BY round' % (hash_id, team)
            y_cur.execute(cmd)
            round_list = y_cur.fetchall()
            for round_id in round_list:
                round_id = round_id[0]
                cmd = 'SELECT rcb FROM pov_scores_db.rcbs_by_round WHERE hash = "%s" AND team = %d AND round = %d' % (hash_id, team, round_id)
                w_cur.execute(cmd)
                rows = w_cur.fetchall()
                is_ref = True
                rcb_list = []
                for (rcb) in rows:
                    rcb = rcb[0]
                    if rcb not in ref:
                        is_ref = False
                    rcb_list.append(rcb)
                if is_ref:
                    z_cur = self.con.cursor()
                    cmd = "SELECT avail from pov_scores_db.avail_scores WHERE csid = '%s' AND round = %d and team = %d" % (csid, round_id, team)
                    z_cur.execute(cmd)
                    result = z_cur.fetchone()
                    if result is None:
                        print('no result for %s' % cmd)
                    elif result[0] < 0.95:
                        cmd = 'SELECT filter FROM pov_scores_db.filters_by_round WHERE hash = "%s" AND team = %d AND round = %d' % (hash_id, team, int(round_id))
                        w_cur.execute(cmd)
                        filter_result = w_cur.fetchone()
                        filter_display = ''
                        if filter_result is not None:
                            filter_display = 'filter '+filter_result[0]
                        print('%s %s round %d team %d avail: %f %s' % (csid, hash_id, round_id, team, result[0], filter_display))
      except mdb.Error, e:
          print "scoresSQL, query, error %d: %s" % (e.args[0], e.args[1])
         
    def rcb_around(self, round_id, team): 
      round_id = int(round_id)
      team = int(team)
      print('# Deployed rcbs before, during and after round %d for team %d' % (round_id, team))

      try:
        y_cur = self.con.cursor()
        r_cur = self.con.cursor()
        w_cur = self.con.cursor()
        z_cur = self.con.cursor()
        cmd = "SELECT DISTINCT csid FROM pov_scores_db.cb_map ORDER BY csid"
        r_cur.execute(cmd)
        csid_list = r_cur.fetchall()
        team = int(team)
        before = round_id -1
        after = round_id +1
        round_list = [before-1,before, round_id, after, after+1]
        for csid in csid_list:
            csid = csid[0]
            ref = self.rcbs.getReference(csid)
            hash_id = self.hash_from_csid(csid)
            pline = 'csid '
            prev = None
            for round_id in round_list:
                cmd = 'SELECT rcb FROM pov_scores_db.rcbs_by_round WHERE hash = "%s" AND team = %d AND round = %d' % (hash_id, team, round_id)
                w_cur.execute(cmd)
                row = w_cur.fetchone()
                if row is not None:
                    if prev is not None and prev != row[0]:
                        print('*************change*')
                    prev = row[0]
                    add = 'round:%d %s' % (round_id, row[0])
                    pline = pline+' '+add
                else:
                    pass
                    #print(' no rcb for %s' % cmd)
            if len(pline) > 6:
                print pline
      except mdb.Error, e:
          print "scoresSQL, query, error %d: %s" % (e.args[0], e.args[1])

    def avail_after(self, start_round_id, team): 
      start_round_id = int(start_round_id)
      team = int(team)
      print('# Service availability after round %d for team %d' % (start_round_id, team))
      try:
        y_cur = self.con.cursor()
        r_cur = self.con.cursor()
        w_cur = self.con.cursor()
        z_cur = self.con.cursor()
        cmd = "SELECT DISTINCT csid FROM pov_scores_db.cb_map ORDER BY csid"
        r_cur.execute(cmd)
        csid_list = r_cur.fetchall()
        team = int(team)
        max_round = start_round_id+10
        head = '%12s' % 'csid'
        for round_id in range(start_round_id, max_round):
            head = head + '%5d' % round_id
        print head 
        for csid in csid_list:
            csid = csid[0]
            ref = self.rcbs.getReference(csid)
            hash_id = self.hash_from_csid(csid)
            pline = '%12s ' % csid
            prev = None
            for round_id in range(start_round_id, max_round):
                cmd = 'SELECT avail FROM pov_scores_db.avail_by_round WHERE hash = "%s" AND team = %d AND round = %d' % (hash_id, team, round_id)
                w_cur.execute(cmd)
                row = w_cur.fetchone()
                if row is not None:
                    add = '%4.2f' % row[0]
                    pline = pline+' '+add
                else:
                    pline = pline+'     '
                    #print(' no avail for %s' % cmd)
                    pass
            if len(pline.strip()) > 12:
                print pline
      except mdb.Error, e:
          print "scoresSQL, query, error %d: %s" % (e.args[0], e.args[1])

    def scored_on(self, team):
      try:
        r_cur = self.con.cursor()
        cmd = 'SELECT DISTINCT csid, round, throw_team, pov_type FROM pov_scores_db.pov_scores WHERE defend_team = %s ORDER BY CSID, round' % (team)
        r_cur.execute(cmd)
        results = r_cur.fetchall()
        for (csid, round_id, throw_team, pov_type) in results:
            print('%s  %d  %d  type:%d' % (csid, round_id, throw_team, pov_type))
      except mdb.Error, e:
          print "scoresSQL, query, error %d: %s" % (e.args[0], e.args[1])

    def exploited_rcbs(self):
      try:
        r_cur = self.con.cursor()
        cmd = 'SELECT DISTINCT rcb FROM pov_scores_db.pov_rcb_scores ORDER BY CSID' 
        r_cur.execute(cmd)
        results = r_cur.fetchall()
        for (csid) in results:
            print csid[0]
      except mdb.Error, e:
          print "scoresSQL, query, error %d: %s" % (e.args[0], e.args[1])

    def addReactDefend(self, csid, defend_team, rcb_round, fail_round, score_round):
        try:
            t_cur = self.con.cursor()
            t_cur.execute('USE pov_scores_db')
            cmd = 'INSERT INTO pov_scores_db.react_defend (csid, defend_team, rcb_round, fail_round, score_round) VALUES("%s", %d, %d, %d, %d)' % (csid, defend_team, rcb_round, fail_round, score_round)
            t_cur.execute(cmd)
            self.con.commit()
        except mdb.Error, e:
            print "error addReactDefend, %d: %s" % (e.args[0], e.args[1])

def usage():
    print('countPOVs thrown | csid | povs_by_csid [csid] | defend [team] | povs_thrown csid thrower defender | avail_ref team | rcb_around [round] [team] | avail_after')
    exit(0)
ss = povTest()
if len(sys.argv) == 1:
    usage()
if sys.argv[1] == 'thrown':
    ss.hashes_thrown()
elif sys.argv[1] == 'csid':
    ss.scores_by_csid()
elif sys.argv[1] == 'povs_by_csid':
    ss.povs_by_csid(sys.argv[2])
elif sys.argv[1] == 'defend':
    ss.defend_by_team(sys.argv[2])
elif sys.argv[1] == 'povs_thrown':
    ss.povs_thrown(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
elif sys.argv[1] == 'avail':
    ss.avail_score(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'avail_ref':
    ss.avail_ref(sys.argv[2])
elif sys.argv[1] == 'avail_round':
    ss.avail_round(sys.argv[2], sys.argv[3])
elif sys.argv[1] == 'rcb_around':
    ss.rcb_around(sys.argv[2], sys.argv[3])
elif sys.argv[1] == 'avail_after':
    ss.avail_after(sys.argv[2], sys.argv[3])
elif sys.argv[1] == 'scored_on':
    ss.scored_on(sys.argv[2])
elif sys.argv[1] == 'exploited_rcbs':
    ss.exploited_rcbs()
elif sys.argv[1] == 'chart':
    ss.chart(sys.argv[2])
elif sys.argv[1] == 'perform':
    ss.perform(sys.argv[2])
elif sys.argv[1] == 'list':
    ss.listCSID()
else:
    usage()

     
