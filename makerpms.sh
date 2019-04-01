#Builds RPMs for both libpydhcpserver and staticDHCPd
cd libpydhcpserver
/usr/bin/env python setup.py bdist_rpm --release 1 --group "Development/Libraries"
cd ..

cd staticDHCPd
/usr/bin/env python setup.py bdist_rpm --release 1 --requires "libpydhcpserver >= 2.0.0" --group "System Environment/Daemons"
cd ..
