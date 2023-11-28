#!/bin/bash

# Run a command in the background.
_evalBg() {
    #eval "$@" &>/dev/null & disown;
    eval "$@" &>/tmp/bkground.log & disown;
}
if [ ! -z "$2" ];then
    sleep $2
fi
cmd=$1
_evalBg "$1";

