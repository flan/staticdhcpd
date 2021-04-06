#Runs both libpydhcpserver and staticDHCPd's Debian scripts
cd libpydhcpserver
/usr/bin/debuild -uc -us 
cd ..

cd staticDHCPd
/usr/bin/debuild -uc -us
cd ..

rm *.dsc
rm *.changes
rm *.build
rm *.buildinfo
rm *.tar.xz
