sleep 8
./findWindow.sh "cadet01-tst"
sleep 1
xdotool type "@cgc.debugSnap()"
xdotool key Return
xdotool type "run-command-file doprep.simics"
xdotool key Return
SIM4=4.8
if [[ "$SIMDIR" != *"$SIM4"* ]]; then
    ./findWindow.sh "Simics Target Consoles"
    sleep 1
    xdotool key Down
    xdotool key Return
fi
sleep 1
./findWindow.sh driver.mb.sb.com
sleep 1
xdotool type "perl -E 'say \"Z\" x 1000' | nc 10.0.0.91 5001"
xdotool key Return
#
# Now run the simulation

