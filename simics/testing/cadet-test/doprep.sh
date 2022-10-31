sleep 8
./findWindow.sh "cadet01-tst"
sleep 2
xdotool type "@cgc.debugSnap()"
xdotool key Return
xdotool type "run-command-file doprep.simics"
xdotool key Return
SIM4=4.8
if [[ "$SIMDIR" != *"$SIM4"* ]]; then
    ./findWindow.sh "Simics Target Consoles"
    xdotool key Down
    xdotool key Return
fi
sleep 2
./findWindow.sh driver.mb.sb.com
xdotool type "perl -E 'say \"X\" x 1000' | nc 10.0.0.91 5001"
xdotool key Return
#
# Now run the simulation

