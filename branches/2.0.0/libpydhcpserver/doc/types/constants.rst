Constants
=========
There's a lot of stuff going on behind the scenes in DHCP, and while this
library tries to make it accessible, it is impossible to hide. At least, not
without removing what makes the library worth using.

Keep this around as a reference when messing with internals, but most of this is
used internally to do the right thing with whatever you throw at a packet.
Check back when things don't go as expected, but go with your instinct first.

.. module:: dhcp_types.constants

.. _constants-fields:

DHCP fields
-----------
.. autodata:: FIELD_OP
    :annotation:

.. autodata:: FIELD_HTYPE
    :annotation:

.. autodata:: FIELD_HLEN
    :annotation:

.. autodata:: FIELD_HOPS
    :annotation:

.. autodata:: FIELD_XID
    :annotation:

.. autodata:: FIELD_SECS
    :annotation:

.. autodata:: FIELD_FLAGS
    :annotation:

.. autodata:: FIELD_CIADDR
    :annotation:

.. autodata:: FIELD_YIADDR
    :annotation:

.. autodata:: FIELD_SIADDR
    :annotation:

.. autodata:: FIELD_GIADDR
    :annotation:

.. autodata:: FIELD_CHADDR
    :annotation:

.. autodata:: FIELD_SNAME
    :annotation:

.. autodata:: FIELD_FILE
    :annotation:

.. autodata:: DHCP_FIELDS
    :annotation:
        
.. autodata:: DHCP_FIELDS_SPECS
    :annotation:

.. autodata:: DHCP_FIELDS_TYPES
    :annotation:
    
    *Reading the source for this element is VERY strongly recommended.*

.. _constants-options:

DHCP options
------------
.. autodata:: DHCP_OPTIONS_TYPES
    :annotation:
    
    *Reading the source for this element is VERY strongly recommended.*
    
.. autodata:: DHCP_OPTIONS
    :annotation:
    
    *Reading the source for this element is VERY strongly recommended.*
    
.. autodata:: DHCP_OPTIONS_REVERSE
    :annotation:

DHCP miscellany
---------------
.. autodata:: DHCP_OP_NAMES
    :annotation:

.. autodata:: DHCP_TYPE_NAMES
    :annotation:

.. autodata:: MAGIC_COOKIE
    :annotation:

.. autodata:: MAGIC_COOKIE_ARRAY
    :annotation:
    
.. _constants-types:

Type-definitions
----------------
.. autodata:: TYPE_IPV4
    :annotation:

.. autodata:: TYPE_IPV4_PLUS
    :annotation:

.. autodata:: TYPE_IPV4_MULT
    :annotation:

.. autodata:: TYPE_BYTE
    :annotation:

.. autodata:: TYPE_BYTE_PLUS
    :annotation:

.. autodata:: TYPE_STRING
    :annotation:

.. autodata:: TYPE_BOOL
    :annotation:

.. autodata:: TYPE_INT
    :annotation:

.. autodata:: TYPE_INT_PLUS
    :annotation:

.. autodata:: TYPE_LONG
    :annotation:

.. autodata:: TYPE_LONG_PLUS
    :annotation:

.. autodata:: TYPE_IDENTIFIER
    :annotation:

.. autodata:: TYPE_NONE
    :annotation:
    