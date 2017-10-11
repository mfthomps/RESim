#!/usr/bin/env python
import MySQLdb as mdb
import sys
def usage():
    print('forensicsMap <csid> <pov_team> <defend_team> <round>')
    exit(0)
con = None
if len(sys.argv) < 3:
    usage()
csid = sys.argv[1]
pov_team = sys.argv[2]
if len(sys.argv) == 5:
    round_id = sys.argv[4]
else:
    round_id = None
if len(sys.argv) >= 4:
    defend_team = sys.argv[3]
else:
    defend_team = None

try:
    con = mdb.connect('localhost', 'cgc', 'password')
except mdb.Error, e:
    print "forensicsMap init, error %d: %s" % (e.args[0], e.args[1])

try:
    t_cur = con.cursor()
    if round_id is not None:
        cmd = "SELECT common, json FROM pov_scores_db.map_to_forensics WHERE common like '%%%s%%' and pov_team = %d and defend_team = %d and round = %d " % (csid, int(pov_team), int(defend_team), int(round_id))
        t_cur.execute(cmd)
        rows = t_cur.fetchall()
        for (common, json) in rows:
            print('%s  %s' % (common, json))
    elif defend_team is not None:
        cmd = "SELECT round, common, json FROM pov_scores_db.map_to_forensics WHERE common like '%%%s%%' and pov_team = %d and defend_team = %d ORDER BY round" % (csid, int(pov_team), int(defend_team))
        t_cur.execute(cmd)
        rows = t_cur.fetchall()
        for (round_id, common, json) in rows:
            print('%d  %s  %s' % (round_id, common, json))
    else:
        cmd = "SELECT round, defend_team, common, json FROM pov_scores_db.map_to_forensics WHERE common like '%%%s%%' and pov_team = %d ORDER BY round, defend_team" % (csid, int(pov_team))
        t_cur.execute(cmd)
        rows = t_cur.fetchall()
        for (round_id, defend_team, common, json) in rows:
            print('%d  %d  %s  %s' % (round_id, defend_team, common, json))

except mdb.Error, e:
    print "forensicsMap query, init, error %d: %s" % (e.args[0], e.args[1])
