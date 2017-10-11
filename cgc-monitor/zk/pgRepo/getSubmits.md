% getSubmits(1) Cyber Grand Challenge Modules
% Mike Thompson <mfthomps@nps.edu>
% March 18, 2015
# NAME

getSubmits -- get competitor submissions from CQE scoring database

# SYNOPSIS

getSubmits [all | just_one | no_replays]

# DESCRIPTION

Retrieve competitor submissions from the scoring database, put them into a 
file system local to the monitoring system and enqueue the replays using 
zookeeper.

# OPTIONS
all
:   Get all submissions, default is to only retrieve the latest submit from each competitor at this moment
If all is specified, the service will loop forever, polling the database.
just_one
:   for testing, retrieve the first submission.
no_replays
:   do not enqueue any replays, just copy the files from the scoring server

# COPYRIGHT
Created by employees of the US Government, cannot be copyrighted.
