#!/bin/bash
#
# Print a list of CFE CSET IDs derived from svn/trunk/challenge-sets based on
# whether the CSET has pov_1 directories or *povxml files.
#
challenge_dir="/mnt/cgcsvn/cgc/trunk/challenge-sets/"
here=`pwd`
cd $challenge_dir
find . -name pov_1 -o -name pov_0 -o -name "*povxml" | grep -v /unreleasable | awk -F/ '{ print $3 }' | grep -v templates | sort | uniq
cd $here
#find . -name "*povxml" | awk -F/ '{ print $3 }' | grep -v templates | sort
