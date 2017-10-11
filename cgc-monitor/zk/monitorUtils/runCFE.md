% runCFE(1) Cyber Grand Challenge Monitoring Utilities
% Mike Thompson <mfthomps@nps.edu>
% April 25, 2016
# NAME

runCFE -- Run the CGC Monitoring system for a given CFE game

# SYNOPSIS

runCFE games_dir [game_name]

# DESCRIPTION

Run the cgc-monitor for new games that appear in the given games_dir.
Optionally, start handling config files found in a given game.  
The local data stores will be deleted, and a game_notify service
will be started using nohup.

This command expects the monitor slaves to be down, and will fail if
they are not.  After clearing the zookeeper and RCB data stores, the
monitor slaves are started and followed by game_notify.

# ALSO SEE
game_notify

# COPYRIGHT
Created by employees of the US Government, cannot be copyrighted.
