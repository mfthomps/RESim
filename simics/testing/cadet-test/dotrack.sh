sleep 3
./findWindow.sh "cadet01-tst"
sleep 1
xdotool type "run-command-file dotrack.simics"
xdotool key Return

