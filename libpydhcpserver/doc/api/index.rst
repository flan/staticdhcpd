Framework overview
==================
*libpydhcpserver* is fundamentally a framework on which a DHCP server may be
built. Its :doc:`types <../types/index>` may be of value to developers working with
DHCP in Python, but some will be crazy enough to need to build a server of
their own and this is a good place to start.

For reference, consider studying
`staticDHCPd <http://staticdhcpd.googlecode.com/>`_, a complete server built on
top of *libpydhcpserver*.


Public API
----------
The core operation of a DHCP server is relatively straightforward: a request packet is
received and analysed, then a response packet is emitted. Between the
:doc:`types <../types/index>` *libpydhcpserver* provides (which include an
object-oriented packet interface) and the :class:`DHCPServer <dhcp.DHCPServer>` class described
below, all that's left for you to do is customising the analysis part.

.. module:: dhcp

Constants
+++++++++
.. autodata:: IP_UNSPECIFIED_FILTER

Classes
+++++++
To build a DHCP server, all you need to understand are the following class-interfaces.

Address
|||||||
.. autoclass:: Address

DHCPServer
||||||||||
.. autoclass:: DHCPServer
    :members:
    :private-members:
    :special-members:
    :exclude-members: __weakref__
    
    .. autoattribute:: DHCPServer._server_address
    .. autoattribute:: DHCPServer._network_link
    
    
Private API
-----------
You'll pretty much never need to touch any of this, unless you're tracking down a bug or modifying
*libpydhcpserver*.

Constants
+++++++++
.. autodata:: _IP_GLOB
.. autodata:: _IP_BROADCAST
.. autodata:: _ETH_P_SNAP

Classes
+++++++
Behind the scenes, a DHCP server does a lot of networking stuff; *libpydhcpserver* handles layer 2
and layer 3 traffic, making it more complex than just working at layer 4; if you want to preserve a
worldview that starts with writing application code and ends with writing data to a stream, read no
further.

_NetworkLink
||||||||||||
.. autoclass:: _NetworkLink
    :members:
    :private-members:
    :special-members:
    :exclude-members: __weakref__
    
    .. autoattribute:: _NetworkLink._client_port
    .. autoattribute:: _NetworkLink._server_port
    .. autoattribute:: _NetworkLink._pxe_port
    .. autoattribute:: _NetworkLink._pxe_socket
    .. autoattribute:: _NetworkLink._responder_dhcp
    .. autoattribute:: _NetworkLink._responder_pxe
    .. autoattribute:: _NetworkLink._responder_broadcast
    .. autoattribute:: _NetworkLink._listening_sockets
    .. autoattribute:: _NetworkLink._unicast_discover_supported
    
_Responder
||||||||||
.. autoclass:: _Responder
    :members:
    :private-members:
    :special-members:
    :exclude-members: __weakref__
    
_L3Responder
||||||||||||
.. autoclass:: _L3Responder
    :members:
    :private-members:
    :special-members:
    :exclude-members: __weakref__
    :show-inheritance:
    
    .. autoattribute:: _L3Responder._socket
    
_L2Responder
||||||||||||
.. autoclass:: _L2Responder
    :members:
    :private-members:
    :special-members:
    :exclude-members: __weakref__
    :show-inheritance:
    
    .. autoattribute:: _L2Responder._ethernet_id
    .. autoattribute:: _L2Responder._server_address
    .. autoattribute:: _L2Responder._pack_
    .. autoattribute:: _L2Responder._array_
    
_L2Responder_AF_PACKET
||||||||||||||||||||||
.. autoclass:: _L2Responder_AF_PACKET
    :members:
    :private-members:
    :special-members:
    :exclude-members: __weakref__
    :show-inheritance:
    
    .. autoattribute:: _L2Responder_AF_PACKET._socket
    
_L2Responder_pcap
|||||||||||||||||
.. autoclass:: _L2Responder_pcap
    :members:
    :private-members:
    :special-members:
    :exclude-members: __weakref__
    :show-inheritance:
    
    .. autoattribute:: _L2Responder_pcap._fd
    .. autoattribute:: _L2Responder_pcap._inject
    .. autoattribute:: _L2Responder_pcap._c_int_
    