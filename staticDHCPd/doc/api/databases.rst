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
    :members:

.. autoclass:: databases.generic.Database
    :members:

.. autoclass:: databases.generic.CachingDatabase
    :show-inheritance:
    :members:
    