sleep 8
./findWindow.sh "cadet01-tst"
sleep 1
xdotool type "@cgc.debugSnap()"
xdotool key Return
xdotool type "run-command-file doprep.simics"
xdotool key Return
drive-driver.py z.directive -t -d
#
# Now run the simulation

