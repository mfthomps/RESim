#!/bin/bash
scp -P 2222 ../cgc-monitor-game-notify_0.1_amd64.deb bladessh:/tmp
ssh -p 2222 bladessh scp /tmp/cgc-monitor-game-notify_0.1_amd64.deb space:~/
