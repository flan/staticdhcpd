Database resources
==================
If you have a specialised site or want to integrate staticDHCPd into an
existing framework (please don't build your framework around it -- it's
designed to fit into your architecture, not to *be* your architecture), you
may find that you need to create a custom database handler.

It's really not that hard: subclass the type of database you want, override
``lookupMac()``, and you're done. Everything you need to know is described
below.

Classes
-------
.. autoclass:: databases.generic.Definition

    .. autoattribute:: databases.generic.Definition.ip
        :annotation:

    .. autoattribute:: databases.generic.Definition.hostname
        :annotation:

    .. autoattribute:: databases.generic.Definition.gateway
        :annotation:

    .. autoattribute:: databases.generic.Definition.subnet_mask
        :annotation:

    .. autoattribute:: databases.generic.Definition.broadcast_address
        :annotation:

    .. autoattribute:: databases.generic.Definition.domain_name
        :annotation:

    .. autoattribute:: databases.generic.Definition.domain_name_servers
        :annotation:

    .. autoattribute:: databases.generic.Definition.ntp_servers
        :annotation:

    .. autoattribute:: databases.generic.Definition.lease_time
        :annotation:

    .. autoattribute:: databases.generic.Definition.subnet
        :annotation:

    .. autoattribute:: databases.generic.Definition.serial
        :annotation:

    .. autoattribute:: databases.generic.Definition.extra
        :annotation:

.. autoclass:: databases.generic.Database
    :members:

.. autoclass:: databases.generic.CachingDatabase
    :show-inheritance:
    :members:
    