#!/bin/bash

# Run a command in the background.
_evalBg() {
    #eval "$@" &>/dev/null & disown;
    eval "$@" &>/tmp/bkground.log & disown;
}

cmd=$1
_evalBg "$1";

