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
'''
For each CSET, display percentage of rounds that each team
landed a POV, the percentage in which it failed to defend, and the
percentage of rounds in which a patched RCB was fielded.
'''
class scoreSQL():
    def __init__(self):
        self.con = None
        self.schedule = None
        self.rcbs_sql = rcbsSQL.rcbsSQL()
        here=os.getcwd()
        self.rcbs_sql.scheduleLoad(os.path.join(here,'schedule.json'))
        try:
            self.con = mdb.connect('localhost', 'cgc', 'password')
        except mdb.Error, e:
            print "scoresSQL, init, error %d: %s" % (e.args[0], e.args[1])

    def CBScoreCounts(self):
        try:
            t_cur = self.con.cursor()
            cmd = 'SELECT csid, COUNT(*) as land_count FROM pov_scores_db.pov_scores GROUP BY csid ORDER BY land_count'
            t_cur.execute(cmd)
            counts = t_cur.fetchall()
            #print('len of counts is %d' % len(counts))
            for (csid, count) in counts:
                print('%s  %d' % (csid, count))
        except mdb.Error, e:
            print "scoresSQL, query, error %d: %s" % (e.args[0], e.args[1])

    def teamsThatScoredOnCB(self, csid):
        first_round = self.firstRound(csid)
        ''' cannot score on first round a CB is fielded '''
        num_rounds = self.numRounds(csid) - 1 
        retval = self.scoringTeams(csid, first_round, num_rounds)
        try:
            t_cur = self.con.cursor()
            cmd = "SELECT DISTINCT throw_team FROM pov_scores_db.pov_scores WHERE csid = '%s'" % csid
            t_cur.execute(cmd)
            rows = t_cur.fetchall()
            for throw_team in rows:
                team_id = throw_team[0]
                retval.addTeam(team_id)
                r_cur = self.con.cursor()
                cmd = "SELECT DISTINCT round FROM pov_scores_db.pov_scores WHERE csid = '%s' AND throw_team = '%d'" % (csid, throw_team[0])
                r_cur.execute(cmd)
                rounds_scored = r_cur.fetchall()
                for round_num in rounds_scored:
                    retval.addRound(team_id, round_num[0])
        except mdb.Error, e:
            print "scoresSQL, teamsScoredOnCB query, error %d: %s" % (e.args[0], e.args[1])
        return retval

    class scoringTeams():
        def __init__(self, csid, first_round, num_rounds):
            self.csid = csid
            self.teams = {}
            self.first_round = first_round
            self.num_rounds = num_rounds
            #print('first round for %s is %d' % (self.csid, self.first_round))

        def addTeam(self, team_id):
            self.teams[team_id] = []

        def addRound(self, team_id, round_id):
            self.teams[team_id].append(round_id)

        def countScores(self, team_id):
            if team_id in self.teams:
                return len(self.teams[team_id])
            else:
                return 0

        def percentScores(self, team_id):
            count = float(self.countScores(team_id))
            retval = float(count/float(self.num_rounds)) * 100.0
            #print('%s team %d scored on %d of %d rounds' % (self.csid, team_id, count, self.num_rounds))
            return retval
    
    class failedTeams():
        def __init__(self, csid, first_round, num_rounds):
            self.csid = csid
            self.teams = {}
            self.teams_function = {}
            self.first_round = first_round
            self.num_rounds = num_rounds
            #print('first round for %s is %d' % (self.csid, self.first_round))

        def addTeam(self, team_id):
            self.teams[team_id] = []
            self.teams_function[team_id] = []

        def addRound(self, team_id, round_id):
            ''' but only if after first live round '''
            if round_id == self.first_round:
                #print('team %d scored on %s in first round %d' % (team_id, self.csid, round_id))
                #self.teams[team_id].append(round_id)
                pass
            else:
                self.teams[team_id].append(round_id)

        def addFunctionRound(self, team_id, round_id):
            ''' but only if after first live round '''
            if round_id == self.first_round:
                #print('team %d scored on %s in first round %d' % (team_id, self.csid, round_id))
                #self.teams[team_id].append(round_id)
                pass
            else:
                self.teams_function[team_id].append(round_id)

        def countFailedFunction(self, team_id):
            ''' count number of rounds the team failed 75% or more polls while not being owned '''
            count = 0
            if team_id in self.teams_function and self.teams_function[team_id]:
                #print('team %d failed %s' % (team_id, self.csid))
                for round_id in self.teams_function[team_id]:
                    if team_id not in self.teams:
                        #print('team %d failed %s' % (team_id, self.csid))
                        count += 1
                    else: 
                        if round_id not in self.teams[team_id]:
                            #print('team %d failed %s' % (team_id, self.csid))
                            count += 1
            return count
                         
        def countOwned(self, team_id):
            if team_id in self.teams:
                return len(self.teams[team_id])
            else:
                return 0

        def percentOwned(self, team_id):
            count = float(self.countOwned(team_id))
            rounds_functioning = self.num_rounds - self.countFailedFunction(team_id)
            retval = 0
            if rounds_functioning != 0:
                retval = float(count/float(rounds_functioning)) * 100.0
            #print('%s team %d failed on %d of %d rounds' % (self.csid, team_id, count, self.num_rounds))
            return retval
    
        def percentFailedFunction(self, team_id):
            count = float(self.countFailedFunction(team_id))
            retval = float(count/float(self.num_rounds)) * 100.0
            #print('%s team %d failed on %d of %d rounds' % (self.csid, team_id, count, self.num_rounds))
            return retval
    
    def teamsThatFailedOnCB(self, csid):

        ''' Find teams that were scored on for a given CB, but only in rounds subsequent to
            the CSET first going live (i.e., after they've had a chance to defend '''
        first_round = self.firstRound(csid)
        num_rounds = self.numRounds(csid) - 2
        retval = self.failedTeams(csid, first_round, num_rounds)
        try:
            t_cur = self.con.cursor()
            cmd = "SELECT DISTINCT defend_team FROM pov_scores_db.pov_scores WHERE csid = '%s'" % csid
            t_cur.execute(cmd)
            rows = t_cur.fetchall()
            for defend_team in rows:
                team_id = defend_team[0]
                retval.addTeam(team_id)
                r_cur = self.con.cursor()
                cmd = "SELECT DISTINCT round FROM pov_scores_db.pov_scores WHERE csid = '%s' AND defend_team = '%d'" % (csid, defend_team[0])
                r_cur.execute(cmd)
                rounds_scored = r_cur.fetchall()
                for round_num in rounds_scored:
                    retval.addRound(team_id, round_num[0])
                cmd = "SELECT hash FROM pov_scores_db.cb_map WHERE csid = '%s'" % csid
                r_cur.execute(cmd)
                hash_id = r_cur.fetchone()[0]
                #print('hash id is <%s>' % hash_id)
                cmd = "SELECT DISTINCT round FROM pov_scores_db.function_fails WHERE hash = '%s' AND team = '%d' AND percent < 75" % (hash_id.strip(), defend_team[0])
                #print cmd
                r_cur.execute(cmd)
                rounds_failed_function = r_cur.fetchall()
                for round_num in rounds_failed_function:
                    retval.addFunctionRound(team_id, round_num[0])
                    #print('csid: %s team %d failed round %d' % (csid, defend_team[0], round_num[0], ))
        except mdb.Error, e:
            print "scoresSQL, teamsScoredOnCB query, error %d: %s" % (e.args[0], e.args[1])
        return retval


    def teamsThatScored(self):
        line = '%15s' % ' '
        line = line+'%-31s' % '% rounds landed a POV'
        line = line + ' ||    '
        line = line + '%-32s' % '% rounds failed to defend[1][2]'
        line = line + ' ||    '
        line = line + '%-32s' % '% rounds with patched[1]'
        line = line + ' ||    '
        line = line + '%-47s' % '% rounds with <75% functionality'
        print(line)
        line = '%11s' % ' '
        for i in range(1,8):
            line = line + '%5s' % str(i)
        line = line + ' || '
        for i in range(1,8):
            line = line + '%5s' % str(i)
        line = line + ' || '
        for i in range(1,8):
            line = line + '%5s' % str(i)
        line = line + ' || '
        for i in range(1,8):
            line = line + '%5s' % str(i)
        print(line)
        line = '%15s' % ' '
        line = line+"="*31
        line = line + ' ||    '
        line = line+"="*31
        line = line + '  ||    '
        line = line+"="*31
        line = line + '  ||    '
        line = line+"="*31
        print(line)
        try:
            t_cur = self.con.cursor()
            cmd = "SELECT DISTINCT csid FROM pov_scores_db.pov_scores ORDER BY csid"
            t_cur.execute(cmd)
            rows = t_cur.fetchall()
            for csid in rows:
                #first_round = self.firstRound(csid[0])
                #line = '%10s %d' % (csid[0], first_round)
                line = '%10s' % (csid[0])
                teams = self.teamsThatScoredOnCB(csid[0])
                for i in range(1,8):
                    scored = teams.percentScores(i)
                    if scored > 0:
                        line = line + '%5.0f' % scored
                    else:
                        line = line + '%5s' % ' '

                line = line + ' || '
    
                teams = self.teamsThatFailedOnCB(csid[0])
                for i in range(1,8):
                    #scored_on = teams.countOwned(i)
                    scored_on = teams.percentOwned(i)
                    if scored_on > 0:
                        line = line + '%5.0f' % scored_on
                    else:
                        line = line + '%5s' % ' '

                line = line + ' || '
    
                for i in range(1,8):
                    #scored_on = teams.countOwned(i)
                    #changed_rcbs = self.rcbs_sql.csetDown(csid[0], i)
                    changed_rcbs = self.rcbs_sql.csetReplaced(csid[0], i)
                    line = line + '%5.0f' % changed_rcbs

                line = line + ' || '
                for i in range(1,8):
                    #scored_on = teams.countOwned(i)
                    failed_function = teams.percentFailedFunction(i)
                    if failed_function > 0:
                        line = line + '%5.0f' % failed_function
                    else:
                        line = line + '%5s' % ' '

                line = line + ' || '
   
                print(line)
            print('\n[1] Not counting first two rounds of the CSET')
            print('\n[2] Count rounds w/ > 75% functionality that were not scored on')
        except mdb.Error, e:
            print "scoresSQL, teamsThatScored query, error %d: %s" % (e.args[0], e.args[1])

    def scheduleLoad(self, fname):
        with open(fname) as fh:
            self.schedule = json.load(fh)
            #print('loaded jason, len %d' % len(self.schedule))

    def firstRound(self, csid):
        round_id = 1
        for round_sets in self.schedule:
            #print str(round_sets)
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
        return retval
   
            
    
ss = scoreSQL()
here=os.getcwd()
ss.scheduleLoad(os.path.join(here,'schedule.json'))
print('\n')
ss.CBScoreCounts()
print('\n')
ss.teamsThatScored()

     
