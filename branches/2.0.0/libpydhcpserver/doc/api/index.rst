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
Building a DHCP server is relatively straightforward: a request packet is
received and analysed, then a response packet is emitted. Between the
:doc:`types <../types>` *libpydhcpserver* provides (which include an
object-oriented packet interface) and the `DHCPServer` class described below.

Constants
+++++++++
.. data:: IP_UNSPECIFIED_FILTER

    A tuple of IPv4 addresses (dotted quads) that reflect non-unicast addresses.

Classes
+++++++
.. autoclass:: dhcp.DHCPServer
    :members: __init__, _getNextDHCPPacket
    