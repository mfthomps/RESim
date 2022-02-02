#!/bin/bash
#
#  Use xdotool to find and get focus on a named window.
#  Used in automated tests
#
#
mywin=$(xdotool search --name "$1")
first=$( echo $mywin | head -n1  | awk '{print $1;}' )
echo "looking for $1  first is $first"
xdotool windowactivate $first
