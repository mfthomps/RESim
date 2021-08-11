#!/bin/bash
mywin=$(xdotool search --name "$1")
first=$( echo $mywin | head -n1  | awk '{print $1;}' )
echo "first is $first"
xdotool windowactivate $first
