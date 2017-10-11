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
try:
    import MySQLdb as mdb
except:
    import pymysql as mdb
import xml.etree.ElementTree as ET
import sys
import StringIO
import bitArray
import json
import traceback
'''
    Access methods to the MySQL database.  Tables created in monitorUtils/rebuildSqlTables
    NOTE: csi & team tables are only created when submittals are used.  
'''
class accessSQL():
    def __init__(self, db_name, lgr):
        self.lgr = lgr
        self.con = None
        self.cc_con = None
        if db_name is not None:
            try:
                self.con = mdb.connect('master', 'cgc', 'password', db_name)
            except mdb.Error, e:
                print("accessSQL error %d: %s" % (e.args[0], e.args[1]))
                self.lgr.error("accessSQL error %d: %s" % (e.args[0], e.args[1]))
                exit(1)
 
    def connectCC(self, cc_db_name):
        self.cc_con = None
        try:
            self.cc_con = mdb.connect('master', 'cgc', 'password', cc_db_name)
        except mdb.Error, e:
            self.lgr.error("accessSQL connectCC error %d: %s" % (e.args[0], e.args[1]))
        return self.cc_con

    def close(self):
        try:
            self.con.close()
        except mdb.Error, e:
            self.lgr.error("accessSQL error %d: %s" % (e.args[0], e.args[1]))

    def close_cc(self):
        if self.cc_con is not None:
            try:
                self.cc_con.close()
            except mdb.Error, e:
                self.lgr.error("accessSQL error %d: %s" % (e.args[0], e.args[1]))

    def addTeam(self, team_name):
        retval = False
        try:
            t_cur = self.con.cursor()
            t_cur.execute("SELECT COUNT(1) FROM teams where name = '%s'" % team_name)
            if not t_cur.fetchone()[0]:
                cur = self.con.cursor()
                cur.execute("INSERT INTO teams(name) VALUES('%s')" % team_name)
                self.con.commit()
                retval = True
        except mdb.Error, e:
            self.lgr.error("accessSQL error adding team %d: %s" % (e.args[0], e.args[1]))
        return retval

    def addCSI(self, csi):
        retval = False
        try:
            t_cur = self.con.cursor()
            t_cur.execute("SELECT COUNT(1) FROM csi where name = '%s'" % csi)
            if not t_cur.fetchone()[0]:
                cur = self.con.cursor()
                cur.execute("INSERT INTO csi(name) VALUES('%s')" % csi)
                self.con.commit()
                retval = True
        except mdb.Error, e:
            self.lgr.error("addCSI error adding CSI %d: %s" % (e.args[0], e.args[1]))
        return retval
        
    def delSetByTeam(self, team_name):
        try:
            cur = self.con.cursor()
            cur.execute("DELETE FROM sets WHERE team = '%s'" % (team_name))
            cur.execute("DELETE FROM teams WHERE name = '%s'" % (team_name))
            self.con.commit()
        except mdb.Error, e:
            self.lgr.error("accessSQL delSetByTeam error %d: %s" % (e.args[0], e.args[1]))
         
    def addSet(self, team_name, common, version, rcb, pov):
        try:
            cur = self.con.cursor()
            cur.execute("SELECT COUNT(1) FROM sets WHERE team = '%s' AND csi = '%s' and version = %d" % (team_name, common, version))
            if not cur.fetchone()[0]:
                cur.execute("INSERT INTO sets(team, csi, version, rcb, pov, start_time) VALUES('%s', '%s', %d, '%s', '%s', NOW())" % \
                    (team_name, common, version, rcb, pov))
                self.con.commit()
            else:
                self.lgr.debug('accessSQL, addSet %s %s %d already in db' % (team_name, common, version))
        except mdb.Error, e:
            self.lgr.error("accessSQL addSet error %d: %s" % (e.args[0], e.args[1]))

    def addSetCFE(self, team_set, cfg_file, csi, team, pov_team, rcb, pov, round_id):
        try:
            cur = self.con.cursor()
            cur.execute("SELECT COUNT(1) FROM sets WHERE team_set = '%s'" % (team_set))
            if not cur.fetchone()[0]:
                cur.execute("INSERT INTO sets(team_set, cfg_file, csi, team, pov_team, rcb, pov, round_id, start_time) VALUES('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', NOW())" % \
                    (team_set, cfg_file, csi, team, pov_team, rcb, pov, round_id))
                self.con.commit()
            else:
                self.lgr.debug('accessSQL, addSetCFE %s %s already in db' % (team, cfg_file))
        except mdb.Error, e:
            self.lgr.error("accessSQL addSetCFE error %d: %s" % (e.args[0], e.args[1]))

    def setDoneCFE(self, cfg_file, rcb_cleared, pov_cleared, record, logged_to_scoring):
        self.lgr.debug('accessSQL, setDone for %s rcb_cleared: %r pov_cleared: %r' % (cfg_file, rcb_cleared, pov_cleared))
        try:
            cur = self.con.cursor()
            cmd = "UPDATE sets SET done = TRUE, record = '%s', rcb_cleared = %r, pov_cleared = %r, logged_to_scoring = %r WHERE cfg_file = '%s'" % (record, 
                rcb_cleared, pov_cleared, logged_to_scoring, cfg_file)
            #print cmd
            cur.execute(cmd)
            self.con.commit()
            cur.close()
        except mdb.Error, e:
            self.lgr.error("accessSQL setDoneCFE error %d: %s" % (e.args[0], e.args[1]))

    def setDone(self, team_name, common, version, rcb_cleared, pov_cleared, record, logged_to_scoring):
        self.lgr.debug('accessSQL, setDone for %s %s rcb_cleared: %r pov_cleared: %r' % (team_name, common, rcb_cleared, pov_cleared))
        try:
            cur = self.con.cursor()
            cmd = "UPDATE sets SET done = TRUE, record = '%s', rcb_cleared = %r, pov_cleared = %r, logged_to_scoring = %r WHERE team = '%s' AND csi = '%s' AND version = %s " % (record, rcb_cleared, pov_cleared, logged_to_scoring, team_name, common, version)
            #print cmd
            cur.execute(cmd)
            self.con.commit()
            cur.close()
            #cur.execute("SELECT rcb_cleared, pov_cleared FROM sets WHERE team = '%s' AND csi = '%s' AND version = %s " % (team_name, common, version))
            #row = cur.fetchone()
            #self.lgr.debug('accessSQL setDone now %r %r' % (row[0], row[1]))
        except mdb.Error, e:
            self.lgr.error("accessSQL error %d: %s" % (e.args[0], e.args[1]))

    def getConfig(self, checksum):
        retval = None
        try:
            cur = self.con.cursor()
            cur.execute("SELECT config FROM configs_db.configs where hash = '%s'" % checksum)
            row = cur.fetchone()
            if row is not None and len(row) > 0:
                retval = row[0]
            else:
                self.lgr.debug('ERROR, getConfig called for checksum %s, record not found' % checksum)
            cur.close()
        except mdb.Error, e:
            self.lgr.error("accessSQL getConfig error %d: %s" % (e.args[0], e.args[1]))
            traceback.print_exc()
            exit(1)
        return retval
        

    def addConfig(self, config, checksum):
        if self.getConfig(checksum) is None:
            try:
                cur = self.con.cursor()
                dum_line = config[:30]
                cmd="INSERT INTO configs_db.configs(config, hash) VALUES('%s', '%s')" % (dum_line, checksum)
                print 'cmdx is %s' % cmd
                print('now execute')
                cur.execute(cmd)
                print 'finished cmd is %s' % cmd
                self.con.commit()
                print 'commited '
                cur.close()
            except mdb.Error, e:
                self.lgr.error("accessSQL addConfig error %d: %s" % (e.args[0], e.args[1]))
                print str(e)
                traceback.print_exc()
                exit(1)
            print 'done addConfig '
     
    def delReplayByCSID(self, csid): 
        try:
            cur = self.con.cursor()
            cmd = "DELETE FROM replays where cb LIKE '%s" % csid
            cur.execute(cmd+"%'")
            self.con.commit()
            cur.close()
        except mdb.Error, e:
            self.lgr.error("accessSQL delReplayByCSID error %d: %s" % (e.args[0], e.args[1]))

    def getDefense(self, cb):
        '''
        Return number of PoVs thrown, and number landed for a cb
        '''
        rows = []
        try:
            cur = self.con.cursor()
            cur.execute("SELECT replay, is_score, display_event from replays WHERE cb = '%s' AND is_pov = TRUE" % (cb))
            rows = cur.fetchall()
        except mdb.Error, e:
            self.lgr.error("accessSQL getDefense error %d: %s" % (e.args[0], e.args[1]))
            return retval 
        landed = 0
        sig_alarm = False
        for row in rows:
            self.lgr.debug('replay %s, landed: %r' % (row[0], row[1]))
            if row[1]:
                landed += 1
            else:
                if 'USER_SIGALRM' in row[2]:
                    sig_alarm = True
        return len(rows), landed, sig_alarm
            
       
    def getReplays(self, cb):
        retval = []
        try:
            cur = self.con.cursor()
            cur.execute("SELECT replay from replays WHERE cb = '%s'" % (cb))
        except mdb.Error, e:
            self.lgr.error("accessSQL getReplays error %d: %s" % (e.args[0], e.args[1]))
            return retval 
        rows = cur.fetchall()
        for row in rows:
            retval.append(row[0].strip())
        cur.close()
        return retval

    def getCBs(self):
        retval = []
        try:
            cur = self.con.cursor()
            cur.execute("SELECT DISTINCT cb FROM replays")
        except mdb.Error, e:
            self.lgr.error("getCBs accessSQL error %d: %s" % (e.args[0], e.args[1]))
            return
        rows = cur.fetchall()
        cur.close()
        for row in rows:
            retval.append(row[0].strip())
        return retval

    def addReplay(self, cb, replay, entry, raw):
        #print 'wall time is %f' % entry['wall_time']
        rules = ''
        if ':' in replay:
            replay, rules = replay.split(':')
        retval = True
        is_pov = False
        if replay.lower().startswith('pov') or replay.lower().endswith('.pov'):
            is_pov = True
        load_failed = False
        load_fail = entry['load_fail']
        if load_fail is not None:
            load_failed = True 
        fmt = '%Y-%m-%d %H:%M:%S'
        #time_start = datetime.datetime(entry['time_start'], fmt)
        #time_end = datetime.datetime(entry['time_end'], fmt)
        statement = "INSERT INTO replays(cb, replay, rules, config, duration, cb_calls, cb_wrote, cb_read, replay_sys_calls, cb_cycles, \
                     cb_user_cycles, cb_faults, replay_faults, wall_time, untouched_blocks, display_event, is_pov, \
                     is_score, load_fail, poll_fail, drone, team_set, time_start, time_end, raw) \
                     VALUES ('%s', '%s', '%s', '%s', %f, %d, %d, %d, %d, %d, %d, %d, %d, %f, %d, '%s', %r, %r, %r, %d, '%s', '%s', '%s', '%s', '%s')" % (cb, 
                     replay, rules, entry['config'], entry['duration'], entry['cb_calls'], entry['cb_wrote'], entry['cb_read'], 
                     entry['replay_sys_calls'], entry['cb_cycles'], 
                     entry['cb_user_cycles'], entry['cb_faults'], entry['replay_faults'], 
                     entry['wall_time'], entry['untouched_blocks'], entry['display_event'], is_pov, entry['is_score'], 
                     load_failed, entry['poll_fail'], entry['drone'], entry['team_set'], entry['time_start'], entry['time_end'], raw)
        #print statement
        last_id = None
        try:
            cur = self.con.cursor()
            cur.execute(statement)
            self.con.commit()
            last_id = cur.lastrowid
            cur.close()
        except mdb.Error, e:
            self.lgr.error("accessSQL error %d: %s" % (e.args[0], e.args[1]))
            return False
        if len(entry['protected_access']) > 0:
            try:
                cur = self.con.cursor()
                for pa in entry['protected_access']:
                    try:
                        a = json.loads(pa)
                    except:
                        self.lgr.error('accessSQL, addReplay, could not load json from protected_access %s' % pa)
                        continue
                    statement = "INSERT INTO protected_access(replay_id, length, location, delta, cpl) VALUES(%d, %d, %d, %lu, %d)" % (last_id,
                       a['length'], a['location'], a['delta'], a['cpl'])
                    cur.execute(statement)
                self.con.commit()
                cur.close()
            except mdb.Error, e:
                self.lgr.error("accessSQL error adding protected access %d: %s" % (e.args[0], e.args[1]))
        
        return retval

    def addSubmission(self, team_name, common, version, pov):
        self.lgr.debug('accessSQL addSubmission, team %s common %s version is %d' % (team_name, common, version))
        #statement = '''INSERT INTO submissions(team, csi, version, pov) VALUES ('%s', '%s', %d, '%s')'''
       
        half_hack = "INSERT INTO submissions(team, csi, version, pov) VALUES ('%s', '%s', %d, " % (team_name, common, version)
        statement= half_hack+''' %s)'''
        #statement = '''INSERT INTO submissions(team, csi, version, pov) VALUES (%s, %s, %d, %s)'''
        #print('statment is: %s' % statement)
        try:
            cur = self.con.cursor()
            #print 'version is %d' % version
            
            #cur.execute(statement, (team_name, common, version, pov,))
            cur.execute(statement, (pov,))
            self.con.commit()
            cur.close()
        except mdb.Error, e:
            self.lgr.error("addSubmission error %d: %s" % (e.args[0], e.args[1]))

    def addSubmissionBin(self, team_name, common, version, bin_num, b):
        #print('team %s common %s version is %d' % (team_name, common, version))
        #statement = '''INSERT INTO submissions(team, csi, version, pov) VALUES ('%s', '%s', %d, '%s')'''
       
        half_hack = "INSERT INTO bins(team, csi, version, bin_num, bin) VALUES ('%s', '%s', %d, %d, " % (team_name, common, version, bin_num)
        statement= half_hack+''' %s)'''
        #statement = '''INSERT INTO submissions(team, csi, version, pov) VALUES (%s, %s, %d, %s)'''
        #print('statment is: %s' % statement)
        try:
            cur = self.con.cursor()
            #print 'version is %d' % version
            
            #cur.execute(statement, (team_name, common, version, pov,))
            cur.execute(statement, (b,))
            self.con.commit()
            cur.close()
        except mdb.Error, e:
            self.lgr.error("addSbumissionBin error %d: %s" % (e.args[0], e.args[1]))
       
    ''' simulate that fdb/python types ''' 
    class submissionType():
        def __init__(self, team, csi, version, pov, bins):
            self.competitor_id = team
            self.cs_id = csi
            self.timestamp = version
            self.pov = pov
            self.bins = bins
         
    def getAllSubmissions(self):
        retval = []
        statement = "SELECT team, csi, version, pov FROM submissions"
        try:
            cur = self.con.cursor()
            cur.execute(statement)
            rows = cur.fetchall()
            for row in rows:
                b_cur = self.con.cursor()
                statement = "SELECT bin_num, bin FROM bins WHERE team='%s' AND csi='%s' AND version=%d" % (row[0], row[1], row[2])
                b_cur.execute(statement)
                b_rows = b_cur.fetchall()
                bins = []
                for b_row in b_rows: 
                    bins.append(b_row[1])
                retval.append(self.submissionType(row[0], row[1], row[2], row[3], bins))
            cur.close()
            
        except mdb.Error, e:
            self.lgr.error("error %d: %s" % (e.args[0], e.args[1]))
        return retval

    def totalBlockCount(self, csi, csi_bin, cc_con):
        total_count = None
        try:
            u_cur = cc_con.cursor()
            u_cur.execute("SELECT COUNT(*) FROM basic_blocks WHERE csi = '%s' and csi_bin = '%s'" % (csi, csi_bin))
            total_count = u_cur.fetchone()[0]
        except mdb.Error, e:
            self.lgr.error("accessSQL updateCsiCoverage select count error %d: %s" % (e.args[0], e.args[1]))
        return total_count 

    def getScores(self): 
        r_cur = None
        try:
            r_cur = self.con.cursor()
            r_cur.execute("SELECT replay, cb FROM replays WHERE is_pov IS TRUE ORDER BY replay, cb")
        except mdb.Error, e:
            self.lgr.error("error %d: %s" % (e.args[0], e.args[1]))
        return r_cur

    def bestPolls(self, csi, cc_db=None, cc_con=None):
        '''
        Return the best polls for the given CSI, or an empty list if none defined
        '''
        retval = []
        self.lgr.debug('updateAllBestPolls for cc db %s' % cc_db)
        if cc_db is None:
            return retval
        if cc_con is None:
            try:
                cc_con = mdb.connect('master', 'cgc', 'password', cc_db)
            except mdb.Error, e:
                self.lgr.error("updateAllBestPolls accessSQL error %d: %s" % (e.args[0], e.args[1]))
                return
        r_cur = None
        try:
            r_cur = cc_con.cursor()
            r_cur.execute("SELECT replay FROM best_polls WHERE csi = %s" % csi)
        except mdb.Error, e:
            self.lgr.error("error %d: %s" % (e.args[0], e.args[1]))
            return retval
        polls = r_cur.fetchall()  
        r_cur.close()
        for p in polls:
            retval.append(p[0]) 
        return retval

    def updateCsiPolls(self, csi, cc_db, cc_con=None):
        '''
        Get all the replay logs for a given CSI, extract the code coverage value for each binary,
        and store that in the code_coverage table.
        '''
        self.lgr.debug('updateCsiPolls for csi %s' % csi)
        if cc_con is None:
            try:
                cc_con = mdb.connect('master', 'cgc', 'password', db_name)
            except mdb.Error, e:
                self.lgr.error("accessSQL error %d: %s" % (e.args[0], e.args[1]))
                return
        try:
            r_cur = cc_con.cursor()
            r_cur.execute("DELETE FROM code_coverage WHERE csi = '%s'" % csi)
            cc_con.commit()
        except mdb.Error, e:
            self.lgr.error("error %d: %s" % (e.args[0], e.args[1]))
            return
        try:
            s_cur = self.con.cursor()
            s_cur.execute("SELECT replay, raw FROM replays WHERE cb = '%s'" % csi)
        except mdb.Error, e:
            self.lgr.error("error %d: %s" % (e.args[0], e.args[1]))
            return
        rows = s_cur.fetchall()
        s_cur.close()
        self.lgr.debug('updateCsiPolls for csi %s found %d rows' % (csi, len(rows)))
        for r in rows:
            replay = r[0]
            #print('raw for %s is %s' % (r[0], r[1]))
            root = ET.XML(r[1])
            cb_entries = root.findall('cb_entry')
            for cb_bin in cb_entries:
                tb = cb_bin.find('touched_blocks')
                if tb is not None:
                    touched_blocks = tb.text
                    cb_bin = cb_bin.find('cb_name').text
                    t_cur = cc_con.cursor()
                    try:
                        t_cur.execute("INSERT INTO code_coverage(csi, csi_bin, replay, touched_blocks) VALUES('%s', '%s', '%s', '%s')" % (csi,
                             cb_bin, replay, touched_blocks))
                        t_cur.close()
                    except mdb.Error, e:
                        self.lgr.error("error %d: %s" % (e.args[0], e.args[1]))
                        return


    def updateBestPollsXX(self, csi, cc_db, cc_con=None):
        self.lgr.debug('updateBestPolls for csi %s' % csi)
        if cc_con is None:
            try:
                cc_con = mdb.connect('master', 'cgc', 'password', db_name)
            except mdb.Error, e:
                self.lgr.error("accessSQL error %d: %s" % (e.args[0], e.args[1]))
                return
        try:
            r_cur = cc_con.cursor()
            r_cur.execute("DELETE FROM best_polls WHERE csi = '%s'" % csi)
            cc_con.commit()
            r_cur.close()
        except mdb.Error, e:
            self.lgr.error("error %d: %s" % (e.args[0], e.args[1]))
            return
        try:
            s_cur = self.con.cursor()
            s_cur.execute("SELECT replay, untouched_blocks FROM replays WHERE cb = '%s' ORDER BY untouched_blocks" % csi)
        except mdb.Error, e:
            self.lgr.error("error %d: %s" % (e.args[0], e.args[1]))
            return
        rows = s_cur.fetchall()
        s_cur.close()
        self.lgr.debug('updateBestPolls for csi %s found %d rows' % (csi, len(rows)))
        for i in range(2):
            t_cur = cc_con.cursor()
            try:
                t_cur.execute("INSERT INTO best_polls(csi, replay, untouched_blocks) VALUES('%s', '%s', %d)" % (csi, rows[i][0], rows[i][1]))
            except mdb.Error, e:
                self.lgr.error("error %d: %s" % (e.args[0], e.args[1]))
                return
            self.lgr.debug('updateBestPolls adding %s %s missing: %d' % (csi, rows[i][0], rows[i][1]))
            print('updateBestPolls adding %s %s missing: %d' % (csi, rows[i][0], rows[i][1]))
        cc_con.commit()
        #
        #  Just for display of totals basic blocks
        t_cur = cc_con.cursor()
        try:
            t_cur.execute("SELECT COUNT(*), csi_bin FROM basic_blocks WHERE csi = '%s' GROUP BY csi_bin" % (csi))
        except mdb.Error, e:
            self.lgr.error("get count of csi_bin error %d: %s" % (e.args[0], e.args[1]))
            return
        rows = t_cur.fetchall()
        t_cur.close()
        for r in rows:
            print('count: %d  bin: %s' % (r[0], r[1]))

    def updateBestPolls(self, csi, cc_db, cc_con=None):
        '''
        Find the best polls for a give csi in terms of basic block coverage.  The best poll is the 
        one that hits the most blocks in the aggregate of the cb binaries.  The second best is the
        replay hits the most blocks neglected by the best poll.  The untouched_blocks value stored
        in the database is cumulative.
        '''
        self.lgr.debug('updateBestPolls for csi %s' % csi)
        if cc_con is None:
            try:
                cc_con = mdb.connect('master', 'cgc', 'password', db_name)
            except mdb.Error, e:
                self.lgr.error("accessSQL error %d: %s" % (e.args[0], e.args[1]))
                return
        try:
            r_cur = cc_con.cursor()
            r_cur.execute("DELETE FROM best_polls WHERE csi = '%s'" % csi)
            cc_con.commit()
            r_cur.close()
        except mdb.Error, e:
            self.lgr.error("error %d: %s" % (e.args[0], e.args[1]))
            return

        try:
            b_cur = self.con.cursor()
            b_cur.execute("SELECT replay, untouched_blocks FROM replays WHERE cb = '%s' ORDER BY untouched_blocks" % csi)
        except mdb.Error, e:
            self.lgr.error("error %d: %s" % (e.args[0], e.args[1]))
            return
        row = b_cur.fetchone()
        b_cur.close()
        best_replay = row[0]
        untouched_blocks = row[1]
        self.lgr.debug('updateBestPolls for csi %s best replay %s  %d untouched blocks' % (csi, best_replay, untouched_blocks))
        print('updateBestPolls adding best for %s replay %s missing: %d' % (csi, best_replay, untouched_blocks))
        t_cur = cc_con.cursor()
        try:
            t_cur.execute("INSERT INTO best_polls(csi, replay, untouched_blocks) VALUES('%s', '%s', %d)" % (csi, 
               best_replay, untouched_blocks))
            cc_con.commit()
            t_cur.close()
        except mdb.Error, e:
            self.lgr.error("error %d: %s" % (e.args[0], e.args[1]))
            return
        '''
        We have the best poll.  Second best is one that covers the most uncovered by the best
        '''
        csi_bins = None
        try:
            s_cur = cc_con.cursor()
            s_cur.execute("SELECT DISTINCT csi_bin FROM code_coverage WHERE csi = '%s' ORDER BY csi_bin" % csi)
            csi_bins = s_cur.fetchall()
            s_cur.close()
        except mdb.Error, e:
            self.lgr.error("accessSQL updateBastPolls select csi_bin error %d: %s" % (e.args[0], e.args[1]))
            return
        best_untouched = {} 
        for item in csi_bins: 
            binary = item[0]
            t_cur = cc_con.cursor()
            try:
                t_cur.execute("SELECT touched_blocks FROM code_coverage WHERE csi = '%s' and csi_bin = '%s' and replay = '%s'" % (csi, 
                     binary, best_replay))
            except mdb.Error, e:
                self.lgr.error("accessSQL updateBestPolls select untouched error %d: %s" % (e.args[0], e.args[1]))
                return
            val = t_cur.fetchone()
            if val is not None:
                best_touched = bitArray.load(val[0])
                best_untouched[binary] = bitArray.do_not(best_touched)
                self.lgr.debug('best_touched for %s is %s, ~that is %s' % (binary, bitArray.dump(best_touched), 
                      bitArray.dump(best_untouched[binary])))
                print('best_touched for %s is %s, ~that is %s' % (binary, bitArray.dump(best_touched), 
                      bitArray.dump(best_untouched[binary])))
            else:
                print('select empty for bin: %s replay: %s' % (binary, best_replay))
            t_cur.close()
        csi_bin_replays = None
        try:
            s_cur = cc_con.cursor()
            s_cur.execute("SELECT csi_bin, replay, touched_blocks FROM code_coverage WHERE csi = '%s' ORDER BY replay, csi_bin" % csi)
            csi_bin_replays = s_cur.fetchall()
            s_cur.close()
        except mdb.Error, e:
            self.lgr.error("accessSQL updateBestPolls select csi_bin, replay error %d: %s" % (e.args[0], e.args[1]))
            return
        ''' load dictionary to easy code review '''
        all_replays = {}
        for item in csi_bin_replays:
            binary = item[0]
            replay = item[1]
            touched = item[2]
            if replay not in all_replays:
                all_replays[replay] = {}
            all_replays[replay][binary] = bitArray.load(touched)
        '''  find second best replay based on total for all binaries'''
        second_best_replay = None
        second_best_count = 0
        for replay in all_replays:
            count = 0
            for b in all_replays[replay]:
                if b in best_untouched:
                    exclusive = bitArray.do_and(best_untouched[b], all_replays[replay][b])
                    count = count+bitArray.countbits(exclusive)
                    #if count > 0:
                    #    print('do replay %s' % replay)
                    #    print('\tdo binary %s' % b)
                    #    print('count for %d all_replay[replay][b] is %s' % (count, bitArray.dump(all_replays[replay][b])))
                else:
                    print('binary: %s has no best_untouched' % (b))
            if count > second_best_count:
                second_best_count = count
                second_best_replay = replay
        ''' add second best to db '''
        if second_best_replay is not None:
            remaining_untouched = untouched_blocks - second_best_count
            t_cur = cc_con.cursor()
            try:
                t_cur.execute("INSERT INTO best_polls(csi, replay, untouched_blocks) VALUES('%s', '%s', %d)" % (csi, 
                     second_best_replay, remaining_untouched))
                cc_con.commit()
                t_cur.close()
            except mdb.Error, e:
                self.lgr.error("error %d: %s" % (e.args[0], e.args[1]))
                return
            self.lgr.debug('updateBestPolls adding second best for %s replay %s missing: %d' % (csi, 
                second_best_replay, remaining_untouched))
            print('updateBestPolls adding second best for %s replay %s missing: %d' % (csi, second_best_replay, remaining_untouched))

        else:
            # no other poll hits blocks not already hit by best.  just use another good poll
            row = b_cur.fetchone()
            best_replay = row[0]
            untouched_blocks = row[1]
            self.lgr.debug('no additional blocks, updateBestPolls for csi %s second best replay %s  %d untouched blocks' % (csi, 
                 best_replay, untouched_blocks))
            print('updateBestPolls adding second best for %s replay %s missing: %d' % (csi, best_replay, untouched_blocks))
            t_cur = cc_con.cursor()
            try:
                t_cur.execute("INSERT INTO best_polls(csi, replay, untouched_blocks) VALUES('%s', '%s', %d)" % (csi, 
                   best_replay, untouched_blocks))
                cc_con.commit()
                t_cur.close()
            except mdb.Error, e:
                self.lgr.error("error %d: %s" % (e.args[0], e.args[1]))
                return

             
        #
        #  Just for display of totals basic blocks
        t_cur = cc_con.cursor()
        try:
            t_cur.execute("SELECT COUNT(*), csi_bin FROM basic_blocks WHERE csi = '%s' GROUP BY csi_bin" % (csi))
        except mdb.Error, e:
            self.lgr.error("get count of csi_bin error %d: %s" % (e.args[0], e.args[1]))
            return
        rows = t_cur.fetchall()
        t_cur.close()
        for r in rows:
            print('count: %d  bin: %s' % (r[0], r[1]))

    def updateAllBestPolls(self, cc_db):            
        cc_con = None
        self.lgr.debug('updateAllBestPolls for cc db %s' % cc_db)
        try:
            cc_con = mdb.connect('master', 'cgc', 'password', cc_db)
        except mdb.Error, e:
            self.lgr.error("updateAllBestPolls accessSQL error %d: %s" % (e.args[0], e.args[1]))
            return
        rows = []
        try:
            t_cur = self.con.cursor()
            t_cur.execute("SELECT DISTINCT cb FROM replays")
            rows = t_cur.fetchall()
            t_cur.close()
        except mdb.Error, e:
            self.lgr.error("updateAllBestPolls accessSQL error %d: %s" % (e.args[0], e.args[1]))
            return
        self.lgr.debug("updateAllBestPolls found %d csi's" % len(rows))
        for r in rows:
            self.updateBestPolls(r[0], cc_db, cc_con)
              
    def updateAllPolls(self, cc_db):            
        '''
        Update the code_coverage table for each CSI by reading the replay logs for each poll and extracting the 
        coverage value for each binary.
        '''
        cc_con = None
        self.lgr.debug('updateAllPolls for cc db %s' % cc_db)
        try:
            cc_con = mdb.connect('master', 'cgc', 'password', cc_db)
        except mdb.Error, e:
            self.lgr.error("updateAllBestPolls accessSQL error %d: %s" % (e.args[0], e.args[1]))
            return
        rows = []
        try:
            t_cur = self.con.cursor()
            t_cur.execute("SELECT DISTINCT cb FROM replays")
            rows = t_cur.fetchall()
            t_cur.close()
        except mdb.Error, e:
            self.lgr.error("updateAllPolls accessSQL error %d: %s" % (e.args[0], e.args[1]))
            return
        self.lgr.debug("updateAllPolls found %d csi's" % len(rows))
        for r in rows:
            self.updateCsiPolls(r[0], cc_db, cc_con)
               
    def updateTotalCoverage(self, cc_db):            
        '''
        For each binary in each CSI, compute the total coverage by anding the coverage of all polls for that CSI
        '''
        cc_con = None
        self.lgr.debug('updateTotalCoverage for cc db %s' % cc_db)
        try:
            cc_con = mdb.connect('master', 'cgc', 'password', cc_db)
        except mdb.Error, e:
            self.lgr.error("updateTotalCoverage accessSQL error %d: %s" % (e.args[0], e.args[1]))
            return
        rows = []
        try:
            t_cur = self.con.cursor()
            t_cur.execute("SELECT DISTINCT cb FROM replays")
            rows = t_cur.fetchall()
            t_cur.close()
        except mdb.Error, e:
            self.lgr.error("updateTotalCoverage accessSQL error %d: %s" % (e.args[0], e.args[1]))
            return
        self.lgr.debug("updateTotalCoverage found %d csi's" % len(rows))
        for r in rows:
            self.updateCsiCoverage(r[0], cc_db, cc_con)
               
    def updateCsiCoverage(self, csi, cc_db, cc_con=None):
        '''
        For each binary in a CSI, compute the total coverage by anding the coverage of all polls for that CSI
        '''
        self.lgr.debug('updateCsiCoverage for csi %s' % csi)
        if cc_con is None:
            try:
                cc_con = mdb.connect('master', 'cgc', 'password', db_name)
            except mdb.Error, e:
                self.lgr.error("accessSQL updateCsiCoverage connect error %d: %s" % (e.args[0], e.args[1]))
                return
        try:
            r_cur = cc_con.cursor()
            r_cur.execute("DELETE FROM total_code_coverage WHERE csi = '%s'" % csi)
            r_cur.close()
            cc_con.commit()
        except mdb.Error, e:
            self.lgr.error("accessSQL updateCsiCoverage delete error %d: %s" % (e.args[0], e.args[1]))
            return

        csi_bins = None
        try:
            s_cur = cc_con.cursor()
            s_cur.execute("SELECT DISTINCT csi_bin FROM code_coverage WHERE csi = '%s'" % csi)
            csi_bins = s_cur.fetchall()
            s_cur.close()
        except mdb.Error, e:
            self.lgr.error("accessSQL updateCsiCoverage selecct csi_bin error %d: %s" % (e.args[0], e.args[1]))
            return
        
        for binary in csi_bins: 
            covered = 0
            try:
                t_cur = cc_con.cursor()
                self.lgr.debug('select for csi %s and bin of %s' % (csi, binary[0]))
                t_cur.execute("SELECT replay, touched_blocks FROM code_coverage WHERE csi = '%s' and csi_bin = '%s'" % (csi,
                     binary[0]))
            except mdb.Error, e:
                self.lgr.error("accessSQL updateCsiCoverage select from code_coverage error %d: %s" % (e.args[0], e.args[1]))
                return

            rows = t_cur.fetchall()
            t_cur.close()
            self.lgr.debug('updateCsiCoverage for csi_bin %s found %d rows' % (binary, len(rows)))
            for r in rows:
                poll_covered = bitArray.load(r[1])
                covered = bitArray.do_or(poll_covered, covered)
                print('bin: %s add %d get  %d %s' % (binary[0], bitArray.countbits(poll_covered), bitArray.countbits(covered), poll_covered))
            cstring = bitArray.dump(covered)
            total_count = self.totalBlockCount(csi, binary[0], cc_con)
            active = bitArray.activebits(covered)
            print('total coverage for %s is %s' % (binary, cstring))
            print('which is %d of %d numactive: %d' % (bitArray.countbits(covered), total_count, len(active)))
            self.lgr.debug('total coverage for %s is %s' % (binary, cstring))
            self.lgr.debug('which is %d of %d numactive: %d' % (bitArray.countbits(covered), total_count, len(active)))
            try:
                t_cur.execute("INSERT INTO total_code_coverage(csi, csi_bin, touched_blocks) VALUES('%s', '%s', '%s')" % (csi, 
                    binary[0], cstring))
                t_cur.close()
            except mdb.Error, e:
                self.lgr.error("updateCsiCoverage error %d: %s" % (e.args[0], e.args[1]))
                return

    def rmBasicBlocks(self, csi): 
        t_cur = self.cc_con.cursor()
        try:
            t_cur.execute("DELETE FROM basic_blocks WHERE csi = '%s'" % csi)
        except mdb.Error, e:
            self.lgr.error("rmBasicBlocks error %d: %s" % (e.args[0], e.args[1]))

    def addBasicBlock(self, csi, csi_bin, block):
        t_cur = self.cc_con.cursor()
        try:
            t_cur.execute("INSERT INTO basic_blocks(csi, csi_bin, block) VALUES('%s', '%s', %d)" % (csi, csi_bin, block))
        except mdb.Error, e:
            self.lgr.error("addBasicBlock error %d: %s" % (e.args[0], e.args[1]))
            return
        self.cc_con.commit()
        t_cur.close()

    def rmReplaysFromDB(self, cb):
 
        try:
            r_cur = self.con.cursor()
            match = cb+'%'
            r_cur.execute("SELECT id FROM replays WHERE cb like '%s'" % match)
            p_cur = self.con.cursor()
            for (id) in r_cur:
                p_cur.execute("DELETE FROM protected_access WHERE replay_id = %d" % id)
            p_cur.close()
            r_cur.execute("DELETE FROM replays WHERE cb like '%s'" % match)
            r_cur.close()
        except mdb.Error, e:
            print("rmReplaysFromDB, error %d: %s" % (e.args[0], e.args[1]))
        print('removed database replays for %s*' % cb)

    def dropDatabases(self, prefix):
        try:
            r_cur = self.con.cursor()
            r_cur.execute('SHOW DATABASES')
            print("** Databases to drop **")
            got_one = False
            for (db) in r_cur:
                dname = db[0]
                if dname.startswith(prefix):
                    print dname
                    got_one = True
            if not got_one:
                print('no databases match %s' % prefix)
                return
            answer = raw_input('drop those? (y/n)')
            if answer.lower() == 'y':
                d_cur = self.con.cursor()
                for (db) in r_cur:
                    dname = db[0]
                    if dname.startswith(prefix):
                        d_cur.execute('DROP DATABASE %s' % dname)
                        print('dropped %s' % dname)
                self.con.commit()
            else:
                print('nothing dropped')
           
        except mdb.Error, e:
            print("dropDatabases, error %d: %s" % (e.args[0], e.args[1]))

    def listDatabases(self):
        try:
            r_cur = self.con.cursor()
            r_cur.execute('SHOW DATABASES')
            for (db) in r_cur:
                print db[0]
        except mdb.Error, e:
            print("listDatabases, error %d: %s" % (e.args[0], e.args[1]))
      
    def mostRecentDatabase(self):
        retval = None
        try:
            r_cur = self.con.cursor()
            r_cur.execute('SHOW DATABASES')
            for (db) in sorted(r_cur):
                if db[0].startswith('db_'):
                    retval = db[0]
            e_cur = self.con.cursor()
            e_cur.execute('USE %s' % retval)
        except mdb.Error, e:
            print("mostRecentDatabase, error %d: %s" % (e.args[0], e.args[1]))
        return retval
