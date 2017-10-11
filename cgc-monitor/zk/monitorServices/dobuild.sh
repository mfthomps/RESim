make clean
cp logUpdateService debian/logUpdateService.init
cp sqlUpdateService debian/sqlUpdateService.init
make
debuild --no-tgz-check -us -uc -d
