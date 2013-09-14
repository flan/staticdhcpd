Platform specification
======================

*libpydhcpserver* is fundamentally a framework on which a DHCP server may be
built. Its :doc:`types <../types>` may be of value to developers working with
DHCP in Python, but some will br crazy enough to need to build a server of
their own and this is a good place to start.

For reference, consider studying
`staticDHCPd <http://staticdhcpd.googlecode.com/>`_, a complete server built on
top of *libpydhcpserver*.


Public API
----------

This is really just DHCPServer. Everything else is well-encapsulated.
