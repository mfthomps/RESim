kill -9 $(ps aux | grep '[p]layAllTarget.sh' | grep -v 'vi ' | awk '{print $2}')
kill-simics.sh
