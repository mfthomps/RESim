#!/bin/bash
#
# Create monitor debug sessions using specific workspaces.
# Intened to run on the blade allocated for debug sessions
# in the confgiMgr.py self.dbg_host.  Modified the workspaces
# to match the dbg_instance -- or fix script to read that config!
#
RESULT=$(tmux list-sessions | grep ida-server)
if [ -z "$RESULT" ]; then
   echo "No tmux ida-server session, create some"
   cd /mnt/simics/simicsWorkspace6
   tmux new-session -s ida-server -d
   tmux new-window -t ida-server -c /mnt/simics/simicsWorkspace7
   tmux new-window -t ida-server -c /mnt/simics/simicsWorkspace8
   tmux new-window -t ida-server -c /mnt/simics/simicsWorkspace9
   tmux new-window -t ida-server -c /mnt/simics/simicsWorkspace10
else
   echo "$RESULT"
   echo "Using existing tmux session"
fi
tmux send-keys -t ida-server:0 "monitorDebug.sh $1" C-m
tmux send-keys -t ida-server:1 "monitorDebug.sh $1" C-m
tmux send-keys -t ida-server:2 "monitorDebug.sh $1" C-m
tmux send-keys -t ida-server:3 "monitorDebug.sh $1" C-m
tmux send-keys -t ida-server:4 "monitorDebug.sh $1" C-m
echo "Debug sessions started, use: tmux attach-session -t ida-server"
echo "to access the tmux sessions."

