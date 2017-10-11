#!/usr/bin/python
"""
@author Kyle
"""

from sqlalchemy import Column, String, Integer, ForeignKey, DateTime, LargeBinary, Boolean, Float, Numeric
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.schema import ForeignKeyConstraint
from sqlalchemy.dialects import postgresql
import json
import datetime
import hashlib
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import atexit
from sqlalchemy.sql.schema import Index
#mz single connection, please
import sqlalchemy.pool

# Connect to DB
Base = declarative_base()
engine = None
session = None
db = None

def db_init(host='10.10.10.30', user='postgres', password='computerpassword', database='cgcdb2'):
    global engine
    global session
    global db
    global Base

    #mz sanity check
    if db is None:
        #engine = create_engine('postgresql://%s:%s@%s/%s' % (user, password, host, database), poolclass=sqlalchemy.pool.StaticPool)
        engine = create_engine('postgresql+psycopg2://%s:%s@%s/%s' % (user, password, host, database), pool_size=1, max_overflow=2)
        session = sessionmaker()
        session.configure(bind=engine)
        db = session()
        #Base.metadata.create_all(engine)

    return db

def db_exit():
    pass
    #global db
    #if db:
    #    db.close()
    #    db = None

atexit.register(db_exit)
# this will print out all the sql statements
#import logging
#logging.basicConfig()
#logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

#cw -- moved to scoring/score.py 17 Feb. 2015
def get_singleton(query_result):
    """
    There are way too many places where models.py returns a list but I want
    just a value.  And a way to assert that the list should be a singleton.
    """
    assert len(query_result) == 1
    return query_result.pop()


################################################################################
class DatabaseException(Exception):
    pass

################################################################################
class DuplicateEntryException(Exception):
    pass

################################################################################
class SubmissionData(Base):
    """ Class to hold submission data messages produced from S3 and sent to SQS"""
    __tablename__ =  'submissiondata'
    submissiondata_id = Column(Integer, primary_key=True)
    bucketname = Column(String)
    event_id = Column(Integer, ForeignKey('events.event_id'), nullable=False)
    eventName = Column(String)
    # XXX - is there a proper type for this time string?
    eventTime = Column(String)
    sourceIPAddress = Column(postgresql.INET)
    eTag = Column(String)
    key = Column(String)
    size = Column(String)
    fullRecord = Column(String, nullable=False)

    @staticmethod
    def insert(subdata):
        db.add(subdata)
        db.commit()

    @staticmethod
    def insertEx(event_id, subdata_jsonstring):
        subdata = json.loads(subdata_jsonstring)

        #records is a list
        for record in subdata['Records']:
            SD = SubmissionData(bucketname=record['s3']['bucket']['name'],
                            event_id=event_id,
                            eventName=record['eventName'],
                            eventTime=record['eventTime'],
                            sourceIPAddress=record['requestParameters']['sourceIPAddress'],
                            eTag=record['s3']['object']['eTag'],
                            key=record['s3']['object']['key'],
                            size=record['s3']['object']['size'],
                            fullRecord=subdata_jsonstring
                            )
            SubmissionData.insert(SD)


    @staticmethod
    def delete(subdata):
        db.delete(subdata)
        db.commit()

    @staticmethod
    def select(**kwargs):
        return db.query(SubmissionData).filter_by(**kwargs).all()

    @staticmethod
    def get(eventname):
        return db.query(SubmissionData).join(Event).filter(Event.event_name == eventname).all()

################################################################################
class EventCset(Base):
    __tablename__ = "eventcsets"
    eventcset_id = Column(Integer, primary_key=True)
    event_id = Column(Integer, ForeignKey('events.event_id'))
    cset_id = Column(Integer, ForeignKey('csets.cset_id'))
    
    @staticmethod
    def insert(ec):
        db.add(ec)
        db.commit()

    @staticmethod
    def delete(ec):
        db.delete(ec)
        db.commit()
    
    @staticmethod
    def get(name):
        return db.query(EventCset).join(Event).filter(Event.event_name == name).all()

################################################################################
class Event(Base):
    __tablename__ = 'events'
    event_id = Column(Integer, primary_key=True)
    event_name = Column(String)
    event_bundle_pass = Column(String)
    svn_version = Column(String)
    svn_path = Column(String)
    cb_replay_version = Column(String)
    cb_test_version = Column(String)
    cb_server_version = Column(String)
    scoring_vm_version = Column(String)

    def __repr__(self):
        data = {}
        data['event_id'] = self.event_id
        data['event_name'] = self.event_name
        data['event_bundle_pass'] = self.event_bundle_pass
        data['svn_version'] = self.svn_version
        data['svn_path'] = self.svn_path
        data['cb_replay_version'] = self.cb_replay_version
        data['cb_test_version'] = self.cb_test_version
        data['cb_server_version'] = self.cb_server_version
        data['scoring_vm_version'] = self.scoring_vm_version
        return json.dumps(data)
    
    @staticmethod
    def select(**kwargs):
        return db.query(Event).filter_by(**kwargs).all()

    @staticmethod
    def insert(event):
        if db.query(Event).filter_by(event_name = event.event_name).count() > 0:
            raise DuplicateEntryException('Event already in database %s' % event)

        db.add(event)
        db.commit()

    @staticmethod
    def get(name):
        if db.query(Event).filter_by(event_name = name).count() > 0:
            return db.query(Event).filter_by(event_name = name).one()

        raise LookupError("No event with name '%s'" % name)

    @staticmethod
    def delete(event):
        db.delete(event)
        db.commit()

################################################################################
class Author(Base):
    __tablename__ = 'authors'
    author_id = Column(Integer, primary_key=True)
    author_name = Column(String)

    def __repr__(self):
        data = {}
        data['author_id'] = self.author_id
        data['author_name'] = self.author_name
        return json.dumps(data)
    
    @staticmethod
    def select(**kwargs):
        return db.query(Author).filter_by(**kwargs).all()

    @staticmethod
    def get(name):
        if db.query(Author).filter_by(author_name = name).count() > 0:
            return db.query(Author).filter_by(author_name = name).one()

        raise LookupError("No author with name '%s'" % name)

    @staticmethod
    def insert(author):
        """inserts an author item into the database"""
        if db.query(Author).filter_by(author_name=author.author_name).count() > 0:
            raise DuplicateEntryException("Already inserted this author: %s" % author)

        db.add(author)
        db.commit()

    @staticmethod
    def delete(author):
        if db.query(Author).filter_by(author_name=author.author_name).count() == 0:
            return

        db.delete(author)
        db.commit()

################################################################################
class Poll(Base):
    __tablename__ = 'polls'
    poll_id = Column(Integer, primary_key=True)
    cset_id = Column(Integer, ForeignKey('csets.cset_id'))
    file_path = Column(String)

    def __repr__(self):
        ret = {}
        ret['poll_id'] = self.poll_id
        ret['cset_id'] = self.cset_id
        ret['file_path'] = self.file_path
        return json.dumps(ret)

    @staticmethod
    def insert(poll):
        db.add(poll)
        db.commit()

    @staticmethod
    def delete(poll):
        db.delete(poll)
        db.commit()

    @staticmethod
    def select(**kwargs):
        return db.query(Poll).filter_by(**kwargs).all()

################################################################################
class Pov(Base):
    __tablename__ = 'povs'
    pov_id = Column(Integer, primary_key=True)
    cset_id = Column(Integer, ForeignKey('csets.cset_id'))
    file_path = Column(String)

    def __repr__(self):
        ret = {}
        ret['pov_id'] = self.pov_id
        ret['cset_id'] = self.cset_id
        ret['file_path'] = self.file_path
        return json.dumps(ret)

    @staticmethod
    def insert(pov):
        db.add(pov)
        db.commit()

    @staticmethod
    def delete(pov):
        db.delete(pov)
        db.commit()

    @staticmethod
    def select(**kwargs):
        return db.query(Pov).filter_by(**kwargs).all()

################################################################################
class Cb(Base):
    __tablename__ = 'cbs'
    cb_id = Column(Integer, primary_key=True)
    cset_id = Column(Integer, ForeignKey('csets.cset_id'))
    cb_index = Column(Integer)
    file_path = Column(String)

    def __repr__(self):
        ret = {}
        ret['cb_id'] = self.cb_id
        ret['cset_id'] = self.cset_id
        ret['cb_index'] = self.cb_index
        ret['file_path'] = self.file_path
        return json.dumps(ret)

    @staticmethod
    def insert(cb):
        db.add(cb)
        db.commit()

    @staticmethod
    def delete(cb):
        db.delete(cb)
        db.commit()

    @staticmethod
    def select(**kwargs):
        return db.query(Cb).filter_by(**kwargs).all()

################################################################################
class PatchedSubPov(Base):
    __tablename__ = 'patchedsubpovs'
    patched_subpov_id = Column(Integer, primary_key=True)
    subpov_id = Column(Integer, ForeignKey('subpovs.subpov_id'))
    replay_return_codes = Column(postgresql.ARRAY(postgresql.INTEGER))

    def __repr__(self):
        ret = {}
        ret['patched_subpov_id'] = self.patched_subpov_id
        ret['subpov_id'] = self.subpov_id
        ret['replay_return_codes'] = self.replay_return_codes
        return json.dumps(ret)
    
    @staticmethod
    def insert(a):
        db.add(a)
        db.commit()

    @staticmethod
    def delete(a):
        db.delete(a)
        db.commit()

    @staticmethod
    def select(**kwargs):
        return db.query(PatchedSubPov).filter_by(**kwargs).all()

################################################################################
class PatchedCb(Base):
    __tablename__ = 'patchedcbs'
    patchedcb_id = Column(Integer, primary_key=True)
    cset_id = Column(Integer, ForeignKey('csets.cset_id'))
    cb_index = Column(Integer)
    file_path = Column(String)

    def __repr__(self):
        ret = {}
        ret['patchedcb_id'] = self.patchedcb_id
        ret['cset_id'] = self.cset_id
        ret['file_path'] = self.file_path
        return json.dumps(ret)

    @staticmethod
    def insert(cb):
        db.add(cb)
        db.commit()

    @staticmethod
    def delete(cb):
        db.delete(cb)
        db.commit()

    @staticmethod
    def select(**kwargs):
        return db.query(PatchedCb).filter_by(**kwargs).all()

################################################################################
class Pcap(Base):
    __tablename__ = 'pcaps'
    pcap_id = Column(Integer, primary_key=True)
    cset_id = Column(Integer, ForeignKey('csets.cset_id'))
    file_path = Column(String)

    def __repr__(self):
        ret = {}
        ret['pcap_id'] = self.pcap_id
        ret['cset_id'] = self.cset_id
        ret['file_path'] = self.file_path
        return json.dumps(ret)

    @staticmethod
    def insert(pcap):
        db.add(pcap)
        db.commit()

    @staticmethod
    def delete(pcap):
        db.delete(pcap)
        db.commit()

    @staticmethod
    def select(**kwargs):
        return db.query(Pcap).filter_by(**kwargs).all()

################################################################################
class Cset(Base):
    __tablename__ = 'csets'
    cset_id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    author_id = Column(Integer, ForeignKey('authors.author_id')) 
    commit_date = Column(DateTime, default=datetime.datetime.now())
    readme = Column(String)
    cwes = Column(String)
    image_version = Column(String)
    accepted = Column(Boolean, default=False)
    anon_id = Column(String, nullable=False)
    folder_path = Column(String)

    # relationships
    author = relationship(Author, uselist=False, backref='csets')
    cbs = relationship(Cb, uselist=True, backref='cbs')
    povs = relationship(Pov, uselist=True, backref='povs')
    polls = relationship(Poll, uselist=True, backref='polls')
    pcaps = relationship(Pcap, uselist=True, backref='pcaps')
    pcbs = relationship(PatchedCb, uselist=True, backref='patchedcbs')
    # cw, think I need this for consensus. If unnecessary, please remove and let me know how to get other submitted POVs--thanks
    #subpovs = relationship(SubPov, uselist=True, backref='subpovs')

    def __repr__(self):
        data = {}
        data['cset_id'] = self.cset_id
        data['name'] = self.name
        data['author_id'] = self.author_id
        data['commit_date'] = str(self.commit_date)
        data['readme'] = self.readme
        data['cwes'] = self.cwes
        data['image_version'] = self.image_version
        data['anon_id'] = self.anon_id
        return json.dumps(data)

    def update(self):
        db.commit()

    @staticmethod
    def insert(cset, cbs=[], povs=[], polls=[], pcaps=[], patched_cbs=[]):
        """ inserts a challenge set into the database """

        # check if already inserted
        if db.query(Cset).filter_by(name=cset.name,
                                    author_id=cset.author_id
                                   ).count() > 0:
            raise DuplicateEntryException("Already inserted this cset: %s" % cset)

        if len(cbs) == 0:
            raise ValueError("CBs required, non given")

        if len(povs) == 0:
            raise ValueError("POVs required, non given")

        if len(polls) == 0:
            raise ValueError("Polls required, non given")

        #if not pcaps:
        #    raise DatabaseException("Pcaps required, non given")

        if not patched_cbs:
            raise ValueError("Patched CB(s) required, non given")

        # insert into db
        db.add(cset)
        db.commit()

        new_cset = db.query(Cset).filter_by(name = cset.name,
                                            author_id = cset.author_id
                                           ).one()

        for p in povs:
            p.cset_id = new_cset.cset_id
            db.add(p) 

        for c in cbs:
            c.cset_id = new_cset.cset_id
            db.add(c)

        for p in polls:
            p.cset_id = new_cset.cset_id
            db.add(p)

        for p in pcaps:
            p.cset_id = new_cset.cset_id
            db.add(p)

        for p in patched_cbs:
            p.cset_id = new_cset.cset_id
            db.add(p)

        db.commit()

    @staticmethod
    def select(**kwargs):
        return db.query(Cset).filter_by(**kwargs).all()

    @staticmethod
    def delete(cset):
        if db.query(EventCset).filter_by(cset_id = cset.cset_id).count() > 0:
            e = db.query(EventCset).filter_by(cset_id = cset.cset_id).one()
            EventCset.delete(e)

        for sub in Submission.select(cset_id = cset.cset_id):
            Submission.delete(sub)

        for p in cset.povs:
            db.delete(p)
        for c in cset.cbs:
            db.delete(c)
        for p in cset.polls:
            db.delete(p)
        for p in cset.pcaps:
            db.delete(p)
        for p in cset.pcbs:
            db.delete(p)

        db.delete(cset)
        db.commit()

################################################################################
class CrsData(Base):
    __tablename__ = 'crsdata'
    crsdata_id = Column(Integer, primary_key=True)
    cset_id = Column(Integer, ForeignKey('csets.cset_id'))
    run_date = Column(DateTime, default=datetime.datetime.now())
    bucket = Column(Integer)
    notes = Column(String)
    core = Column(String)
    kernel = Column(String)
    run_duration = Column(Integer)
    host = Column(String)

    @staticmethod
    def insert(csdata):
        db.add(csdata)
        db.commit()

    @staticmethod
    def delete(csdata):
        db.delete(csdata)
        db.commit()

    def update(self):
        db.commit()

    @staticmethod
    def select(**kwargs):
        return db.query(CrsData).filter_by(**kwargs).all()

################################################################################
class SubPov(Base):
    __tablename__ = 'subpovs'
    subpov_id = Column(Integer, primary_key=True)
    submission_id = Column(Integer, ForeignKey('submissions.submission_id'))
    subpov_hash = Column(String, nullable=False)
    replay_return_codes = Column(postgresql.ARRAY(postgresql.INTEGER))
    # cw 12 May 2015 -- removing dead columns for Ticket #510
    file_path = Column(String, nullable=False)
    
    @staticmethod
    def insert(pov):
        # hash the pov then store it
        db.add(pov)
        db.commit()
    
    def __repr__(self):
        data = {}
        data['subpov_id'] = self.subpov_id
        data['submission_id'] = self.submission_id
        data['subpov_hash'] = self.subpov_hash
        # cw -- 26 March 2015
        #data['comp_pov_successful'] = self.comp_pov_successful
        #data['patched_eval'] = self.patched_eval
        data['file_path'] = self.file_path
        data['replay_return_codes'] = str(self.replay_return_codes)
        return json.dumps(data)

    @staticmethod
    def select(**kwargs):
        return db.query(SubPov).filter_by(**kwargs).all()

    def update(self):
        db.commit()

    @staticmethod
    def delete(pov):
        db.delete(pov)
        db.commit()

################################################################################
class SubRb(Base):
    __tablename__ = 'subrbs'
    subrb_id = Column(Integer, primary_key=True)
    submission_id = Column(Integer, ForeignKey('submissions.submission_id'))
    subrb_index = Column(Integer, nullable=False)
    subrb_hash = Column(String, nullable=False)
    cb_id = Column(Integer, ForeignKey('cbs.cb_id'))
    file_path = Column(String, nullable=False)
    file_size = Column(Integer)
    
    @staticmethod
    def insert(rb):
        # hash the rb then store it
        if rb.subrb_index < 1:
            raise DatabaseException("SubRb indexes must be greater than 0")

        db.add(rb)
        db.commit()

    def __repr__(self):
        data = {}
        data['subrb_id'] = self.subrb_id
        data['submission_id'] = self.submission_id
        data['subrb_index'] = self.subrb_index
        data['subrb_hash'] = self.subrb_hash
        data['cb_id'] = self.cb_id
        data['file_path'] = self.file_path
        return json.dumps(data)

    @staticmethod
    def select(**kwargs):
        return db.query(SubRb).filter_by(**kwargs).all()

    def update(self):
        db.commit()
    
    @staticmethod
    def delete(rb):
        db.delete(rb)
        db.commit()

################################################################################
class Competitor(Base):
    __tablename__ = 'competitors'
    competitor_id = Column(Integer, primary_key=True)
    competitor_name = Column(String)
    distribution_bucket = Column(String)
    submission_bucket = Column(String)
    access_key_id = Column(String)
    secret_access_key = Column(String)
    amazon_iam_account = Column(String)
    cqe_encryption_key = Column(String)

    def __repr__(self):
        data = {}
        data['competitor_id'] = self.competitor_id
        data['competitor_name'] = self.competitor_name
        data['distribution_bucket'] = self.distribution_bucket
        data['submission_bucket'] = self.submission_bucket
        data['access_key_id'] = self.access_key_id
        data['secret_access_key'] = self.secret_access_key
        data['amazon_iam_account'] = self.amazon_iam_account
        data['cqe_encryption_key'] = self.cqe_encryption_key
        return json.dumps(data)

    @staticmethod
    def insert(comp):
        if db.query(Competitor).filter_by(competitor_name = comp.competitor_name, 
                distribution_bucket = comp.distribution_bucket,
                submission_bucket = comp.submission_bucket).count() > 0:
            raise DuplicateEntryException('Already added this competitor: %s' % comp)
        
        db.add(comp)
        db.commit()

    @staticmethod
    def select(**kwargs):
        return db.query(Competitor).filter_by(**kwargs).all()

    @staticmethod
    def delete(comp):
        db.delete(comp)
        db.commit()

    @staticmethod
    def get(name):
        if db.query(Competitor).filter_by(competitor_name = name).count() > 0:
            return db.query(Competitor).filter_by(competitor_name = name).one()

        raise LookupError("No competitor with name '%s'" % name)

################################################################################
class Submission(Base):

    __tablename__ = 'submissions'
    submission_id = Column(Integer, primary_key=True)
    competitor_id = Column(Integer, ForeignKey('competitors.competitor_id'))
    cset_id = Column(Integer, ForeignKey('csets.cset_id'))
    event_id = Column(Integer, ForeignKey('events.event_id'))
    ar_hash = Column(String)
    enc_hash = Column(String)
    # cw 12 May 2015 -- timezone now defaults to False to fix DST inconsistencies seen in database for Ticket #510
    timestamp = Column(DateTime(timezone=False))
    verified = Column(Boolean, default=False)
    rbs_clear = Column(Boolean, default=False)
    pov_clear = Column(Boolean, default=False)
    ar_md5 = Column(String)
    enc_md5 = Column(String)
    
    rbs = relationship(SubRb, uselist=True, backref='submissions', lazy='joined')
    pov = relationship(SubPov, uselist=False, backref='submissions', lazy='joined')

    def __repr__(self):
        data = {}
        data['submission_id'] = self.submission_id
        data['competitor_id'] = self.competitor_id
        data['cset_id'] = self.cset_id
        data['event_id'] = self.event_id
        data['ar_hash'] = self.ar_hash
        data['enc_hash'] = self.enc_hash
        data['timestamp'] = str(self.timestamp)
        data['verified'] = str(self.verified)
        return json.dumps(data)

    @staticmethod
    def delete(sub):
        for r in sub.rbs:
            db.delete(r)

        db.delete(sub.pov)
        db.delete(sub)
        db.commit()

    def update(self):
        db.commit()

    @staticmethod
    def get(sub_id):
        if db.query(Submission).filter_by(submission_id = sub_id).count() == 1:
            return db.query(Submission).filter_by(submission_id = sub_id).one()

        raise LookupError("Cannot find submission with submission_id %s" % sub_id)

    @staticmethod
    def verify(sub):
        sub.verified = True
        db.commit()

    @staticmethod
    def clear_rbs(sub):
        sub.rbs_clear = True
        db.commit()

    @staticmethod
    def clear_pov(sub):
        sub.pov_clear = True
        db.commit()

    @staticmethod
    def select_with_hash(enc_hash):
        return db.query(Submission, Cset).join(Cset).filter(Submission.cset_id == Cset.cset_id, Submission.enc_hash == enc_hash).one()

    @staticmethod
    def select_povs(ah):
        cur = db.query(Submission).filter_by(ar_hash = ah).one()
        povs = db.query(Submission).filter(Submission.cset_id == cur.cset_id, Submission.ar_hash != ah).all()

        return (cur, povs)

    @staticmethod
    def select(**kwargs):
        return db.query(Submission).filter_by(**kwargs).all()

    @staticmethod
    def insert(submission, rbs, pov):

        # check if item is already in the database
        if db.query(Submission).filter_by(competitor_id = submission.competitor_id, 
                event_id = submission.event_id, 
                enc_hash = submission.enc_hash, 
                timestamp = submission.timestamp).count() > 0:

            raise DuplicateEntryException("Duplicate submission: %s" % submission)

        #TODO check there is the proper number of rbs
        if not pov:
            raise DatabaseException("Submission must include a PoV")

        # check that the indexes line up
        indexes = [n.subrb_index for n in rbs]
        indexes.sort()
        
        if len(set(indexes)) != len(rbs):
            raise DuplicateEntryException("Duplicate indexes in SubRb submissions. Got %d, expecting %d" % (len(set(indexes)), len(rbs)))
        
        #for i in range(1, len(rbs)):
        #    if i != rbs[i-1].subrb_index:
        #        raise DatabaseException("SubRb indexes are not not in order or missing an index. (around %d)" % i)

        # add the submission to the database
        db.add(submission)
        #submission.povs = pov
        #submission.rbs = rbs
        #db.add(submission)
        #db.add(submission.povs)
        #db.add(submission.rbs)
        #db.commit()
        db.flush()
        
        # grab the newly submitted item to get the submission_id
        #submission_obj = db.query(Submission).filter_by(competitor_id = submission.competitor_id,
        #        event_id = submission.event_id,
        #        ar_hash = submission.ar_hash,
        #        enc_hash = submission.enc_hash,
        #        timestamp = submission.timestamp).one()
        
        #submit the pov and rbs 
        pov.submission_id = submission.submission_id
        db.add(pov)
        #SubPov.insert(pov)
        for rb in rbs:
            rb.submission_id = submission.submission_id
            #SubRb.insert(rb)
            db.add(rb)
        
        db.commit()
        return submission
    
    @staticmethod
    def get_latest_verified(competitor_id, event_id, cset_id):
        if db.query(Event).filter_by(event_id = event_id).count() != 1:
            raise DatabaseException("Invalid event id: %d" % event_id)

        if db.query(Competitor).filter_by(competitor_id = competitor_id).count() != 1:
            raise DatabaseException("Invalid competitor id: %d" % competitor_id)

        if db.query(Cset).filter_by(cset_id = cset_id).count() != 1:
            raise DatabaseException("Invalid challenge set %d" % cset_id)

        subs = db.query(Submission).filter_by(competitor_id = competitor_id, cset_id = cset_id, event_id = event_id, verified = True, pov_clear = True, rbs_clear = True).order_by(Submission.timestamp.desc(), Submission.cset_id.desc()).all()
        
        if len(subs) == 0:
            return None

        return subs[0]

    @staticmethod
    def get_latest_verified_all(event_id, cset_id):
        competitors = [c.competitor_id for c in db.query(Competitor).all()]
        return filter(lambda x: x is not None, [Submission.get_latest_verified(comp, event_id, cset_id) for comp in competitors])

################################################################################
class ScoringSubRb(Base):
    __tablename__ = 'scoringsubrbs'
    score_sub_rb_id = Column(Integer, primary_key=True)
    submission_id = Column(Integer, ForeignKey('submissions.submission_id'))
    pov_id = Column(Integer, ForeignKey('povs.pov_id'))
    # cw -- 26 March 2015
    #ref_pov_mitigated = Column(Boolean, nullable=False)
    replay_return_codes = Column(postgresql.ARRAY(postgresql.INTEGER))

    def __repr__(self):
        ret = {}
        ret['score_sub_rb_id'] = str(self.score_sub_rb_id)
        ret['submission_id'] = str(self.submission_id)
        ret['pov_id'] = str(self.pov_id)
        #ret['ref_pov_mitigated'] = str(self.ref_pov_mitigated)
        ret['replay_return_codes'] = str(self.replay_return_codes)
        return json.dumps(ret)
    
    @staticmethod
    def insert(s):
        db.add(s)
        db.commit()

    def update(self):
        db.commit()

    @staticmethod
    def delete(s):
        db.delete(s)
        db.commit()

    @staticmethod
    def select(**kwargs):
        return db.query(ScoringSubRb).filter_by(**kwargs).all()

################################################################################
class ScoringPolls(Base):
    __tablename__ = 'scoringpolls'
    score_id = Column(Integer, primary_key=True)
    submission_id = Column(Integer, ForeignKey('submissions.submission_id'))
    poll_id = Column(Integer, ForeignKey('polls.poll_id'), index=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.datetime.now())
    ref_cycles = Column(Numeric, index=True)
    uops_retired = Column(Numeric)
    insn_retired = Column(Numeric)
    sw_cpu_clock = Column(Numeric)
    sw_task_clock = Column(Numeric)
    sw_minflt = Column(Numeric)
    sw_majflt = Column(Numeric)
    user_time = Column(Float)
    # cw -- 7 Apr. 2015 per request
    minor_faults = Column(Numeric)
    #max_rss = Column(Integer)
    max_resident_set_size = Column(Numeric)
    replay_return_code = Column(Integer, nullable=False)
    ref_cycles_index = Index('ref_cycles_index', poll_id, ref_cycles)

    def __repr__(self):
        data = {}
        data['score_id'] = str(self.score_id)
        data['submission_id'] = str(self.submission_id)
        data['poll_id'] = str(self.poll_id)
        data['timestamp'] = str(self.timestamp)
        data['ref_cycles'] = str(self.ref_cycles)
        data['uops_retired'] = str(self.uops_retired)
        data['insn_retired'] = str(self.insn_retired)
        data['sw_cpu_clock'] = str(self.sw_cpu_clock)
        data['sw_task_clock'] = str(self.sw_task_clock)
        data['sw_minflt'] = str(self.sw_minflt)
        data['sw_majflt'] = str(self.sw_majflt)
        data['minor_faults'] = str(self.minor_faults)
        return json.dumps(data)

    @staticmethod
    def insert(score):
        db.add(score)
        db.commit()

    @staticmethod
    def delete(score):
        db.delete(score)
        db.commit()

    @staticmethod
    def select(**kwargs):
        return db.query(ScoringPolls).filter_by(**kwargs).all()

    def update(self):
        db.commit()

################################################################################
class Consensus(Base):
    __tablename__ = 'consensus'
    consensus_id = Column(Integer, primary_key=True)
    submission_id = Column(Integer, ForeignKey('submissions.submission_id'))
    subpov_id = Column(Integer, ForeignKey('subpovs.subpov_id'))
    #score = Column(Integer, nullable=False)
    replay_return_codes = Column(postgresql.ARRAY(postgresql.INTEGER))

    def __repr__(self):
        data = {}
        data['consensus_id'] = str(self.consensus_id)
        data['submission_id'] = str(self.submission_id)
        data['subpov_id'] = str(self.subpov_id)
        # cw 26 March 2015
        #data['score'] = str(self.score)
        data['replay_return_codes'] = str(self.replay_return_codes)
        return json.dumps(data)

    @staticmethod
    def delete(con):
        db.delete(con)
        db.commit()

    @staticmethod
    def insert(con):
        db.add(con)
        db.commit()

    @staticmethod
    def select(**kwargs):
        return db.query(Consensus).filter_by(**kwargs).all()

