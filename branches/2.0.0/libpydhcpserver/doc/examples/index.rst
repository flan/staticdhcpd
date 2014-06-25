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

Data-access Conventions
-----------------------
As much as possible, *libpydhcpserver* tries to keep things consistent and easy
to predict.

Setting values
++++++++++++++
With a few exceptions for :ref:`special RFC requirements <conversion-rfc>`, all
DHCP options are set as follows, where ``x`` is the option's ID or name and
``packet`` is a :class:`DHCPPacket <dhcp_types.packet.DHCPPacket>`:

* **TYPE_IPV4**::
    
    packet.setOption(x, IPv4('127.0.0.1')) #Using the libpydhcpserver IPv4 type
    packet.setOption(x, '127.0.0.1')
    packet.setOption(x, [127, 0, 0, 1])
    packet.setOption(x, 2130706433)
    
* **TYPE_IPV4_PLUS**::
    
    packet.setOption(x, '127.0.0.1,192.168.0.1')
    packet.setOption(x, [[127, 0, 0, 1], '192.168.0.1'])
    
* **TYPE_IPV4_MULT**::
    
    packet.setOption(x, []) #Having no IPs is permitted
    packet.setOption(x, '127.0.0.1,192.168.0.1')
    
* **TYPE_BOOL**::
    
    packet.setOption(x, True)
    packet.setOption(x, False)
    packet.setOption(x, 1)
    packet.setOption(x, 0)
    

* **TYPE_BYTE**::
    
    packet.setOption(x, 127) #Must be 0-255
    
* **TYPE_BYTE_PLUS**::
    
    packet.setOption(x, [0, 127, 255]) #Must be 0-255
    
* **TYPE_STRING**::
    
    packet.setOption(x, 'hello')
    
* **TYPE_INT**::
    
    packet.setOption(x, 32768) #Must be 0-65,535
    
* **TYPE_INT_PLUS**::
    
    packet.setOption(x, [0, 32768, 65535]) #Must be 0-65,535
    
* **TYPE_LONG**::
    
    packet.setOption(x, 2147483648) #Must be 0-4,294,967,295
    
* **TYPE_LONG_PLUS**::
    
    packet.setOption(x, [0, 2147483648, 4294967295]) #Must be 0-4,294,967,295
    
**Note:** All integers may be specified in hex (``0xF0``), octal (``020``), and
binary (``0b10001000``).

**Note:** Anything, including RFC values, may be passed as a list or tuple of
bytes, too, if you know what you want to set.

Getting values
++++++++++++++
Except for RFC values, which are returned bytes-only, everything attached to a
packet can be retreieved in a format that is either efficient (bytes) or
friendly (like the first form of everything that can be used in the setting
examples above).

::
    
    >>> packet.getOption(15) #The domain-name
    [117, 103, 117, 117, 46, 99, 97]
    
    >>> packet.getOption('domain_name', convert=True)
    'uguu.ca'

Examples
--------
The interesting part of this document: how to apply this stuff. Before that,
though, quickly familiarise yourself with
:class:`DHCPPacket <dhcp_types.packet.DHCPPacket>`.

Options
+++++++
DHCP options are accessed exactly as described above, so here are some practical
examples.

Set renewal T1 to 60 seconds::
    
    packet.setOption('renewal_time_value', 60)
    packet.setOption(58, 60) #The same thing, but using the numeric ID
    
See if the client requested a specific option::
    
    if packet.isRequestedOption('router'): #Option 3
        print("The client wants 'router'")
    
Using numeric IDs is *slightly* faster, but, really, unless you know what
you're doing, the gains aren't worth the headaches.

Fields
++++++
DHCP fields are accessed the same way as are options, through
:func:`setOption <dhcp_types.packet.DHCPPacket.setOption>`.

Unless you're working with PXE, which makes **FIELD_FILE** relevant, the only
things you are likely to want to manipulate are **FIELD_CIADDR**,
**FIELD_YIADDR**, **FIELD_SIADDR**, and **FIELD_GIADDR**.

All of them work with IPv4 data, so the example here will be modifying the
server's address::
    
    ip = packet.getOption(FIELD_SIADDR, convert=True) #IPv4('192.168.0.1')
    ip = list(ip) #[192, 168, 0, 1]
    ip[3] = 2 #[192, 168, 0, 2]
    packet.setOption(FIELD_SIADDR, ip)

RFC options
+++++++++++
RFC values can be pretty complex. *libpydhcpserver* implements convenient
handlers for a lot of them, though.

:rfc:`2610`
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
Set :class:`Option 78 <dhcp_types.rfc.rfc2610_78>` with the following pattern::
    
    packet.setOption('directory_agent', rfc2610_78('192.168.1.1,192.168.1.2'))
    
There are no limits on the number of comma-delimited values you may specify.

Set :class:`Option 79 <dhcp_types.rfc.rfc2610_79>` with the following pattern::

    packet.setOption('service_scope', rfc2610_79(u'slp-scope-string'))
    
Where ``slp-scope-string`` is the scope you want to set.

:rfc:`3361`
|||||||||||
Set :class:`Option 120 <dhcp_types.rfc.rfc3361_120>` with either of the
following patterns::

    packet.setOption('sip_servers', rfc3361_120('example.org,uguu.ca'))
    packet.setOption('sip_servers', rfc3361_120('192.168.1.1'))

There are no limits on the number of comma-delimited values you may specify.
The only restriction is that either names xor IPs may be used, never both.

:rfc:`3397`
||||||||||
Set :class:`Option 119 <dhcp_types.rfc.rfc3397_119>` with the following
pattern::

    packet.setOption('domain_search', rfc3397_119('example.org,uguu.ca'))

There are no limits on the number of comma-delimited values you may specify.

:rfc:`3925`
|||||||||||
Set :class:`Option 124 <dhcp_types.rfc.rfc3925_124>` with the following
pattern::
    
    packet.setOption('vendor_class', rfc3925_124([(0x00000001, strToList('hello'))]))

Set :class:`Option 125 <dhcp_types.rfc.rfc3925_125>` with the following
pattern::
    
    packet.setOption('vendor_specific', rfc3925_125([(0x00000001, [(45, strToList('hello'))])]))

:rfc:`4174`
|||||||||||
Set :class:`Option 83 <dhcp_types.rfc.rfc4174_83>` with the following
pattern::
    
    isns_functions = 0b0000000000000111
    dd_access = 0b0000000000111111
    admin_flags = 0b0000000000001111
    isns_security = 0b00000000000000000000000001111111
    
    packet.setOption('internet_storage_name_service', rfc4174_83(
        isns_functions, dd_access, admin_flags, isns_security,
        '192.168.1.1,192.168.1.2,192.168.1.3'
    ))

There are no limits on the number of comma-delimited values you may specify,
but you may require at least two, depending on the rest of your configuration.

:rfc:`4280`
|||||||||||
Set :class:`Option 88 <dhcp_types.rfc.rfc4280_88>` with the following
pattern::
    
    packet.setOption('bcmcs_domain_list', rfc4280_88('example.org,uguu.ca'))

There are no limits on the number of comma-delimited values you may specify.

Set :class:`Option 89` as you would any other **TYPE_IPV4_PLUS** value.

:rfc:`5223`
|||||||||||
Set :class:`Option 137 <dhcp_types.rfc.rfc5223_137>` with the following
pattern::
    
    packet.setOption('v4_lost', rfc5223_137('example.org,uguu.ca'))

There are no limits on the number of comma-delimited values you may specify.

:rfc:`5678`
|||||||||||
Set :class:`Option 139 <dhcp_types.rfc.rfc5678_139>` with the following
pattern::
    
    packet.setOption('ipv4_mos', rfc5678_139(
        (1, '127.0.0.1,192.168.1.1'),
        (2, '10.0.0.1'),
    ))

There are no limits on the number of comma-delimited values you may specify.

Set :class:`Option 140 <dhcp_types.rfc.rfc5678_140>` with the following
pattern::
    
    packet.setOption('fqdn_mos', rfc5678_140(
        (1, 'example.org,uguu.ca'),
        (2, 'example.ca,google.com'),
    ))
    
There are no limits on the number of comma-delimited values you may specify.
