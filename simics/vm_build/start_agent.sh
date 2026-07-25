#!/bin/bash
touch /tmp/driver-ready.flag
/usr/bin/simics-agent --overwrite --executable --download driver-script.sh --to /usr/bin
/usr/bin/driver-script.sh
/usr/bin/simics-agent &
/usr/bin/simics-agent --overwrite --upload /tmp/driver-ready.flag

