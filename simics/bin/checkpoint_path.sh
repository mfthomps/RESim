#!/bin/bash
#
# display the checkpoint providence of a given checkpoint.
#
ckpt=$1
gunzip -c $1/config.gz | grep checkpoint_path
