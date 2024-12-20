#!/usr/bin/bash
mkdir -p logs/driver
scp -P 4022 mike@localhost:/tmp/*.log logs/driver/
