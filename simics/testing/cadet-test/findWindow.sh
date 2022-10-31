#!/bin/bash
mywin=$(xdotool search --name "$1")
while [[ -z "$first" ]]; do
    first=$( echo $mywin | head -n1  | awk '{print $1;}' )
    #echo "first is $first  mywin $mywin param $1"
done
xdotool windowactivate $first
