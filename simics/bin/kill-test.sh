#!/bin/bash
#
#  kill the alltests.sh automated tests
#
kill -9 $(ps aux | grep '[a]lltests.sh' | grep -v 'vi ' | awk '{print $2}')
kill -9 $(ps aux | grep '[l]aunchRESim.py' | awk '{print $2}') >>/dev/null 2>&1
