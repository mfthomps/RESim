#!/bin/bash
scp -P 2222 ../workspace/authorized_keys localhost:/tmp
ssh -p 2222 localhost "cat /tmp/authorized_keys >> ~/.ssh/authorized_keys"
