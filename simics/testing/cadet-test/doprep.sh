sleep 8
./findWindow.sh "cadet01-tst"
xdotool type "@cgc.debugIfNot()"
xdotool key Return
xdotool type "@cgc.trackIO(4)"
xdotool key Return
xdotool type "@cgc.prepInjectWatch(0, 'cadetread')"
xdotool key Return
./findWindow.sh "Simics Target Consoles"
xdotool key Down
xdotool key Return
sleep 2
./findWindow.sh driver.mb.sb.com
xdotool type "perl -E 'say \"X\" x 1000' | nc 10.0.0.91 5001"
xdotool key Return
#
# Now run the simulation

