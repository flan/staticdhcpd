#Builds RPMs for both libpydhcpserver and staticDHCPd
cd libpydhcpserver
/usr/bin/env python3 setup.py bdist_rpm --release 1 --group "Development/Libraries"
cd ..

cd staticDHCPd
/usr/bin/env python3 setup.py bdist_rpm --release 1 --requires "libpydhcpserver >= 3.0.0" --group "System Environment/Daemons"
cd ..
