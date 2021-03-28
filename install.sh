#Runs both libpydhcpserver and staticDHCPd's installation scripts
cd libpydhcpserver
/usr/bin/env python3 setup.py install
cd ..

cd staticDHCPd
/usr/bin/env python3 setup.py install
cd ..
