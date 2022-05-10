kill $(ps aux | grep '[c]rashReport' | awk '{print $2}')
kill $(ps aux | grep '[l]aunchRESim.py' | awk '{print $2}')
kill $(ps aux | grep '[d]rive-driver.py' | awk '{print $2}')
