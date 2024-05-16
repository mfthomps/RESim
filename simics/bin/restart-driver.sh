sudo kill $(ps aux | grep '[d]river-server.py' | awk '{print $2}')
echo "did kill" >/tmp/kill.log
sudo nohup /tmp/driver-server.py restart &
echo "did restart" >/tmp/kill.log
