scp -P 4022 $RESIM_DIR/simics/bin/driver-server.py mike@localhost:/tmp/new_driver-server.py
scp -P 4022 $RESIM_DIR/simics/bin/restart-driver-update.sh mike@localhost:/tmp/
cp $RESIM_DIR/simics/bin/driver_server_version .driver_server_version
ssh -f -n -p 4022 mike@localhost  "/tmp/restart-driver-update.sh"
