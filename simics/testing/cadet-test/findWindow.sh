#!/bin/bash
mywin=$(xdotool search --name "$1")
xdotool windowactivate $mywin
