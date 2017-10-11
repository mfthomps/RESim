#!/usr/bin/python
from models import * 
import logging
from monitorLibs import configMgr
'''
Set the verifiy flag in a submission
And clear (or not) the rcb and pov
'''
class pgVet():
    def __init__(self, lgr, cfg, no_db=False):
        self.lgr = lgr
        self.db = None
        if not no_db:
            try:
                self.db = db_init(host=cfg.scoring_server, database=cfg.cgc_event_db)
            except:
                return
            event = cfg.cgc_event
            if self.db is None:
                print('pgVet db init failed')
                self.lgr.error('pgVet failed to connect to database')
                return
            try: 
                self.event_id = Event.get(event).event_id
            except:
                print('failed to get database event id for %s' % event)
                self.lgr.error('pgVet failed to connect to database')
                self.db = None
                return
            self.lgr.debug('pgVet using database: %s event: %s' % (cfg.cgc_event_db, event))
        else:
            self.lgr.debug('pgVet with no_db, must be testing')
        

    def salright(self, team_id, csid, version, rcb_failed_vet, pov_failed_vet):
        '''
        Record vetting results in the scoring database
        '''
        retval = True
        print self.db
        if self.db is None:
            self.lgr.debug('pgVet, salright, but no database connected')
            return False
        cs = Competitor.select()
        comp_id = int(team_id)
        #competitor = Competitor.get(team_name)
        #print('competitor id is %d' % competitor.competitor_id)
        cset_name = csid[2:len(csid)-2]
        self.lgr.debug('pgVet, salright, think cset name is %s ' % cset_name)
        cset = Cset.select(name = cset_name)[0]
        self.lgr.debug('pgVet, salright, cset_id is %d' % cset.cset_id)
        submits = Submission.select(event_id = self.event_id, competitor_id = comp_id, cset_id = cset.cset_id)
        self.lgr.debug('pgVet, salright,  got %d submits' % len(submits))
        sorted_subs = []
        for sub in submits:
            #key = sub.timestamp
            key = sub.submission_id
            sorted_subs.append((key, sub))
        sorted_subs.sort()
        sub = sorted_subs[version-1][1]
        self.lgr.debug('pgVet, salright, our sub_id is %d, timestamp: %s before call, verified is %r.  rcb_failed_vet: %r  pov_failed_vet: %r' % (sub.submission_id, 
            str(sub.timestamp), sub.verified, rcb_failed_vet, pov_failed_vet))
        if not sub.verified:
            if not rcb_failed_vet:
                Submission.clear_rbs(sub)
            if not pov_failed_vet:
                Submission.clear_pov(sub)
            Submission.verify(sub)
        else:
            self.lgr.debug('pgVet, salright, entry already verified, do not verify again')

        #Submissions.verify(sub.submission_id)
        return retval

if __name__ == "__main__":
    ps = pgVet(logging)
    ps.salright('testbot', 1, 'CBTESTR_0000101')
