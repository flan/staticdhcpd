Constants
=========
There's a lot of stuff going on behind the scenes in DHCP, and while this
library tries to make it accessible, it is impossible to hide. At least, not
without removing what makes the library worth using.

Keep this around as a reference when messing with internals, but most of this is
used internally to do the right thing with whatever you throw at a packet.
Check back when things don't go as expected, but go with your instinct first.

Also, it's ugly, but the data presented here is enough to avoid having to go
look at the source. The source is better-formatted, though.

.. module:: dhcp_types.constants

DHCP fields
-----------
.. autodata:: FIELD_OP

.. autodata:: FIELD_HTYPE

.. autodata:: FIELD_HLEN

.. autodata:: FIELD_HOPS

.. autodata:: FIELD_XID

.. autodata:: FIELD_SECS

.. autodata:: FIELD_FLAGS

.. autodata:: FIELD_CIADDR

.. autodata:: FIELD_YIADDR

.. autodata:: FIELD_SIADDR

.. autodata:: FIELD_GIADDR

.. autodata:: FIELD_CHADDR

.. autodata:: FIELD_SNAME

.. autodata:: FIELD_FILE

.. autodata:: DHCP_FIELDS
    :annotation:
        
.. autodata:: DHCP_FIELDS_SPECS
    :annotation:

.. autodata:: DHCP_FIELDS_TYPES

DHCP options
------------
.. autodata:: DHCP_OPTIONS_TYPES

.. autodata:: DHCP_OPTIONS

.. autodata:: DHCP_OPTIONS_REVERSE
    :annotation:

DHCP miscellany
---------------
.. autodata:: DHCP_OP_NAMES

.. autodata:: DHCP_TYPE_NAMES

.. autodata:: MAGIC_COOKIE
    :annotation:

.. autodata:: MAGIC_COOKIE_ARRAY
    :annotation:
    
Type-definitions
----------------
.. autodata:: TYPE_IPV4

.. autodata:: TYPE_IPV4_PLUS

.. autodata:: TYPE_IPV4_MULT

.. autodata:: TYPE_BYTE

.. autodata:: TYPE_BYTE_PLUS

.. autodata:: TYPE_STRING

.. autodata:: TYPE_BOOL

.. autodata:: TYPE_INT

.. autodata:: TYPE_INT_PLUS

.. autodata:: TYPE_LONG

.. autodata:: TYPE_LONG_PLUS

.. autodata:: TYPE_IDENTIFIER

.. autodata:: TYPE_NONE
