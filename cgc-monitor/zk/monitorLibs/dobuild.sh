make clean
make
#debuild --no-tgz-check -us -uc -d
dpkg-buildpackage -us -uc -d
sudo dpkg -i ../cgc-monitor-libs_0.1_amd64.deb
