% cgc-monitor-game-notify (1) Cyber Grand Challenge Monitoring
% Mike Thompson <mfthomps@nps.edu>
% March 30, 2015
# NAME

game_notify -- Listen for new CFE games and new CFE config files.


# DESCRIPTION

The game_notify service uses inotify to detect new game directories
and new CFE configuration files, and it uses the cfeFlow utility
to enqueue new config files into the cgc-monitor.  Alternately
the service acts as a proxy to forward CFE game directories and files
to the cgc-monitor.

    game_notify <path_to_games> [proxy monitor_system]



# COPYRIGHT
Created by employees of the US Government, cannot be copyrighted.

# SEE ALSO
cfeFlow

