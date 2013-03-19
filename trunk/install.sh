#Runs both libpydhcpserver and staticDHCPd's installation scripts
cd libpydhcpserver
/usr/bin/env python setup.py install
cd ..

cd staticDHCPd
/usr/bin/env python setup.py install
cd ..
