#!/bin/bash
file=$1
ignore=$RESIM_DIR/simics/bin/no_execve.txt
grep execve $1 | grep -f $ignore -v | grep -v "return from"
