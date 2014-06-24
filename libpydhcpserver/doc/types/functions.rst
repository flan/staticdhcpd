Convenience functions
=====================
For efficiency purposes, packet-data is conceptualised as sequences of bytes,
since it has very limited interaction with human operators. This is great for
performance, but not so great when writing code.

To maintain efficiency and avoid errors, a number of optimised convenience
routines are provided and described below. However, they are all encapsulated
within the :meth:`getOption <dhcp_types.packet.DHCPPacket.getOption>` and
:meth:`setOption <dhcp_types.packet.DHCPPacket.setOption>` methods of
:class:`DHCPPacket <dhcp_types.packet.DHCPPacket>`, so it is rare that you will
need to invoke them directly.

Type-conversion
---------------
DHCP needs to encode a wide variety of data and it can be easy to confuse
byte-ordering. That's where the conversion-functions come into play.

.. module:: dhcp_types.conversion

Decoders 
||||||||
The following functions convert from byte-sequences into more familiar
data-types. They are additionally bound via autoconversion.

.. autofunction:: listToNumber
.. autofunction:: listToInt
.. autofunction:: listToInts
.. autofunction:: listToLong
.. autofunction:: listToLongs
.. autofunction:: listToStr
.. autofunction:: listToIP
.. autofunction:: listToIPs

Encoders
||||||||
When writing values to a packet, the following methods, additionally bound via
autoconversion, will handle the hard part.

.. autofunction:: intToList
.. autofunction:: intsToList
.. autofunction:: longToList
.. autofunction:: longsToList
.. autofunction:: strToList
.. autofunction:: strToPaddedList
.. autofunction:: ipToList
.. autofunction:: ipsToList

RFC conversions
---------------
DHCP has many extending RFCs, and many of those have their own data-formats.

Where possible, `libpydhcpserver` provides routines for processing their
content, letting you focus on logic, not bitwise shifts.

.. module:: dhcp_types.rfc

Decoders
||||||||
The following functions decode RFC options, providing easy-to-process data.
They are bound and invoked, where appriopriate, via autoconversion.

.. autofunction:: rfc3046_decode
.. autofunction:: rfc3925_decode
.. autofunction:: rfc3925_125_decode

Encoders
||||||||
For setting RFC options, the following classes can be passed in place of
byte-sequences, handling all logic internally.

.. autoclass:: RFC
    :members:
    
.. autoclass:: rfc1035_plus
    :show-inheritance:
    
.. autoclass:: rfc2610_78
    :show-inheritance:
    
.. autoclass:: rfc2610_79
    :show-inheritance:
    
.. autoclass:: rfc3361_120
    :show-inheritance:
    
.. autoclass:: rfc3397_119
    :show-inheritance:
    
.. autoclass:: rfc3925_124
    :show-inheritance:
    
.. autoclass:: rfc3925_125
    :show-inheritance:
    
.. autoclass:: rfc4174_83
    :show-inheritance:
    
.. autoclass:: rfc4280_88
    :show-inheritance:
    
.. autoclass:: rfc5223_137
    :show-inheritance:
    
.. autoclass:: rfc5678_139
    :show-inheritance:
    
.. autoclass:: rfc5678_140
    :show-inheritance:
    