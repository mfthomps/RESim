make clean
cp monitorSlaveService debian/monitorSlaveService.init
make
dpkg-buildpackage -us -uc -d
sudo dpkg -i ../cgc-monitor-build-utils_0.1_amd64.deb
