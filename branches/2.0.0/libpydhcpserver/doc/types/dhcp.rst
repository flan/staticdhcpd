DHCP data-types
===============
Networking is a complex subject, with lots of different ways to communicate the
same information. To make this easier, abstract encapsulations are provided that
behave like all of the most common expressions simultaneously.

If you ever find yourself needing to pass or work with an
:class:`IPv4 <dhcp_types.ipv4.IPv4>` or :class:`MAC <dhcp_types.mac.MAC>`
address, wrap it with one of these. If it's coming out of the library, chances
are it's one already.

IPv4 addresses
--------------
A fairly straightforward representation of a conventional IP address. It can be
coerced into a familiar dotted-quad string, an efficient sequence of bytes, or
a somewhat intimidating unsigned, 32-bit integer. It can also be assembled from
any of these things, as well as other instances of this class.

.. module:: dhcp_types.ipv4

.. autoclass:: IPv4
    :members:

MAC addresses
-------------
A simple, friendly representation of a standard six-octet MAC address. It can be 
coerced into a string of colon-delimited hex-values, an efficient sequence of
bytes, or a scary unsigned integer. It can be built from any of these things,
too, other instances of the class, or hex-strings that may or may not contain
any delimiters you like.

.. module:: dhcp_types.mac

.. autoclass:: MAC
    :members:

DHCP packets
------------
The heart of the library, data-structure-wise, a DHCP packet to be examined,
modified, and serialised for transmission.

.. module:: dhcp_types.packet

Constants
+++++++++
.. autodata:: FLAGBIT_BROADCAST
    :annotation:

Classes
+++++++
.. autoclass:: DHCPPacket
    :members:
    