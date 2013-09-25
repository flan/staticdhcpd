Framework overview
==================
*libpydhcpserver* is fundamentally a framework on which a DHCP server may be
built. Its :doc:`types <../types>` may be of value to developers working with
DHCP in Python, but some will be crazy enough to need to build a server of
their own and this is a good place to start.

For reference, consider studying
`staticDHCPd <http://staticdhcpd.googlecode.com/>`_, a complete server built on
top of *libpydhcpserver*.


Public API
----------
Building a DHCP server is relatively straightforward: a request packet is
received and analysed, then a response packet is emitted. Between the
:doc:`types <../types>` *libpydhcpserver* provides (which include an
object-oriented packet interface) and the :class:`DHCPServer <dhcp.DHCPServer>` class described
below.

Constants
+++++++++
.. autodata:: dhcp.IP_UNSPECIFIED_FILTER

Classes
+++++++
.. autoclass:: dhcp.Address

.. autoclass:: dhcp.DHCPServer
    :members:
    :private-members:
    :special-members:
    :exclude-members: __weakref__
    
    .. autoattribute:: dhcp.DHCPServer._server_address
    .. autoattribute:: dhcp.DHCPServer._network_link
    
    
Private API
-----------
You'll pretty much never need to touch any of this, unless you're tracking down a bug or extending
*libpydhcpserver*.

Constants
+++++++++
.. autodata:: dhcp._IP_GLOB
.. autodata:: dhcp._IP_BROADCAST
.. autodata:: dhcp._ETH_P_SNAP

Classes
+++++++
.. autoclass:: dhcp._NetworkLink
    :members:
    :private-members:
    :special-members:
    :exclude-members: __weakref__
    
    .. autoattribute:: dhcp._NetworkLink._client_port
    .. autoattribute:: dhcp._NetworkLink._server_port
    .. autoattribute:: dhcp._NetworkLink._pxe_port
    .. autoattribute:: dhcp._NetworkLink._pxe_socket
    .. autoattribute:: dhcp._NetworkLink._responder_dhcp
    .. autoattribute:: dhcp._NetworkLink._responder_pxe
    .. autoattribute:: dhcp._NetworkLink._responder_broadcast
    .. autoattribute:: dhcp._NetworkLink._listening_sockets
    .. autoattribute:: dhcp._NetworkLink._unicast_discover_supported
    
.. autoclass:: dhcp._Responder
    :members:
    :private-members:
    :special-members:
    :exclude-members: __weakref__
    
.. autoclass:: dhcp._L3Responder
    :members:
    :private-members:
    :special-members:
    :exclude-members: __weakref__
    :show-inheritance:
    
    .. autoattribute:: dhcp._L3Responder._socket
    
.. autoclass:: dhcp._L2Responder
    :members:
    :private-members:
    :special-members:
    :exclude-members: __weakref__
    :show-inheritance:
    
    .. autoattribute:: dhcp._L2Responder._ethernet_id
    .. autoattribute:: dhcp._L2Responder._server_address
    .. autoattribute:: dhcp._L2Responder._pack_
    .. autoattribute:: dhcp._L2Responder._array_
    
.. autoclass:: dhcp._L2Responder_AF_PACKET
    :members:
    :private-members:
    :special-members:
    :exclude-members: __weakref__
    :show-inheritance:
    
    .. autoattribute:: dhcp._L2Responder_AF_PACKET._socket
    
.. autoclass:: dhcp._L2Responder_pcap
    :members:
    :private-members:
    :special-members:
    :exclude-members: __weakref__
    :show-inheritance:
    
    .. autoattribute:: dhcp._L2Responder_pcap._fd
    .. autoattribute:: dhcp._L2Responder_pcap._inject
    .. autoattribute:: dhcp._L2Responder_pcap._c_int_
    