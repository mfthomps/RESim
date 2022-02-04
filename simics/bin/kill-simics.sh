kill $(ps aux | grep '[l]aunchRESim.py' | awk '{print $2}')
kill $(ps aux | grep '[r]unAFL' | awk '{print $2}')
