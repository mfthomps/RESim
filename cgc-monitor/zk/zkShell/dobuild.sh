make clean
make
cp zkShellService debian/zkShellService.init
debuild --no-tgz-check -us -uc -d
