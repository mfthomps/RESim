% reportSQL(1) Cyber Grand Challenge Monitoring Utilities
% Mike Thompson <mfthomps@nps.edu>
% April 1, 2015
# NAME

runEvent -- Run the CGC Monitoring system for a given event

# SYNOPSIS

runEvent event_db event_name

# DESCRIPTION

Run the monitor for the given *event_db* and *event_name* as defined in the scoring database.
The local data stores will be deleted, and the appropriate Csets and competitor
submissions will be retrieved from the scoring database.  This script will continue
to run, polling the scoring database, until it is killed.

# ALSO SEE
showEvents

# COPYRIGHT
Created by employees of the US Government, cannot be copyrighted.
