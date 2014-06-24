Framework overview
==================
*libpydhcpserver* is fundamentally a framework on which a DHCP server may be
built. Its :doc:`types <../types/index>` may be of value to developers working
with DHCP in Python, but some will be crazy enough to need to build a server of
their own and this is a good place to start.

For reference, consider studying
`staticDHCPd <http://staticdhcpd.googlecode.com/>`_, a complete server built on
top of *libpydhcpserver*.


API: all you need to know
-------------------------
The core operation of a DHCP server is relatively straightforward: a request
packet is received and analysed, then a response packet is emitted. Between the
:doc:`types <../types/index>` *libpydhcpserver* provides (which include an
object-oriented packet interface) and the
:class:`DHCPServer <dhcp.DHCPServer>` class described below, all that's left
for you to do is customise the analysis part.

.. module:: dhcp

Constants
+++++++++
.. autodata:: IP_UNSPECIFIED_FILTER

Named Tuples
++++++++++++
.. autodata:: Address
    :annotation:

Classes
+++++++
.. autoclass:: DHCPServer
    :members:
    :private-members:
    