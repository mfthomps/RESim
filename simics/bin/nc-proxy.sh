#!/bin/sh -e
#
# Use 2 netcat instances to proxy a connection made to the driver,
# through the driver to a service, e.g., netcat, running on the simics host.
#
if [ $# != 3 ]
then
    echo "usage: $0 <src-port> <dst-host> <dst-port>"
    exit 0
fi

TMP=`mktemp -d`
PIPE=$TMP/pipe
trap 'rm -rf "$TMP"' EXIT
mkfifo -m 0600 "$PIPE"

#nc -k -l -p "$1" <"$PIPE" | nc "$2" "$3" > "$PIPE"
nc -lvp "$1" <"$PIPE" | nc "$2" "$3" > "$PIPE"
