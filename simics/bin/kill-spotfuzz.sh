kill -9 $(ps aux | grep '[r]unSpotFuzz' | awk '{print $2}')
