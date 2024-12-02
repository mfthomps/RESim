sleep 8
./findWindow.sh "cadet01-tst"
sleep 1
xdotool type "@cgc.setDebugCallback(cgc.trackKbuf)"
xdotool key Return
xdotool type "@cgc.setDebugCallbackParam(4)"
xdotool key Return
xdotool type "@cgc.debugSnap()"
xdotool key Return
xdotool type "run-command-file doprep.simics"
xdotool key Return
drive-driver z.directive -d
#
# Now run the simulation

