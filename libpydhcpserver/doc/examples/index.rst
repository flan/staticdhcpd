Example usage
=============
Basically, this is where rules will go, minus the staticDHCPd-specific stuff.

Remember to include the packet-response stuff and anything else that shows with a grep on 'docu' in the commit-log.


Primer on manipulating DHCP packets
===================================
If you want to do anything with *libpydhcpserver*, it will be necessary to
modify DHCP packets at some point. Fortunately, it's really not difficult.

Useful background knowledge
---------------------------
It will be necessary to think in terms of the types of data involved in the
operation you wish to perform. :ref:`constants-types` covers the various
primitive data-types used in the system.

:ref:`constants-fields` and :ref:`constants-options` describe how these types
fit into packets and demystify a great deal of what's presented in the remainder
of this page, but involve some research. It is recommended that you study these
examples first, then attempt to learn how they work.

Conventions
-----------
With a few exceptions for :ref:`special RFC requirements <conversion-rfc>`, all
DHCP options are set as follows, where ``x`` is the option's ID or name and
``packet`` is a :class:`DHCPPacket <dhcp_types.packet.DHCPPacket>`:

* **TYPE_IPV4**::
    
    packet.setOption(x, '127.0.0.1')
    packet.setOption(x, [127, 0, 0, 1])
    
* ipv4+: A series of one or more IPv4 addresses, assignable using packet.setOption(x, ipsToList('127.0.0.1,192.168.1.1'))

* ipv4*: A series of zero or more IPv4 addresses, assignable using packet.setOption(x, [])

*  A single bit, assignable using packet.setOption(x, [int(True)])
    byte: A single byte, assignable using packet.setOption(x, [127])
    byte+: A series of one or more bytes, assignable using packet.setOption(x, [127, 255, 100, 2])
    char: A single character, assignable using packet.setOption(x, [ord('c')])
    char+: A series of one or more characters, assignable using packet.setOption(x, strToList('hello'))
    
    16-bits: A single 16-bit value, assignable using packet.setOption(x, intToList(65535))
    16-bits+: A series of 16-bit values, assignable using packet.setOption(x, intsToList((65535, 2, 10)))
    32-bits: A single 32-bit value, assignable using packet.setOption(x, longToList(1000000))
    32-bits+: A series of 32-bit values, assignable using packet.setOption(x, longsToList((65535, 2, 1000000)))
    string: A series of zero or more characters, assignable using packet.setOption(x, strToList('hello')) 

**Note:** All integers may be specified in hex (``0xF0``), octal (``020``), and
binary (``0b10001000``).
