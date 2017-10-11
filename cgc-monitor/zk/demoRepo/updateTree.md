% updateTree (1) Cyber Grand Challenge Monitoring Test jigs
% Mike Thompson <mfthomps@nps.edu>
% April 18, 2015
# NAME

updateTree  -- Create Zookeeper nodes for CBs & replays found
in the file repository.

# SYNOPSIS

updateTree [no_replays]

# DESCRIPTION
Create CB nodes and replay nodes based on CBs, RCBs, Polls and PoVs found
in the file repo.  The *no_replay* option will just cause the CB
nodes to be created, and populated with program section data.

# COPYRIGHT
Created by employees of the US Government, cannot be copyrighted.

# SEE ALSO
clearZk
