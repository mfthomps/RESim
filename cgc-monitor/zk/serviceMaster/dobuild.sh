make clean
make
#debuild --no-tgz-check -us -uc -d
dpkg-buildpackage -us -uc -d
