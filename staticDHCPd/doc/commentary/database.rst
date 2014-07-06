General database structure and concept
======================================
staticDHCPd's database structure is meant to be highly normalised, while
capturing all of the most important attributes of a DHCP lease.

However, its design, for legacy reasons, has some design features tied to its
origins as an ISP's server in 2009. This section will provide some insight into
why certain choices were made.

"tables"
--------
*staticDHCPd* was originally built against a MySQL database, since that's what
shipped with OS X 10.6, which was the core of the server infrastructure on which
it had to run. Its database access routines were built to be decoupled early in
its lifetime, but the concept of using REST APIs to serve leases wasn't on the
radar (SOAP was still fairly dominant at the time, which would have been
unacceptably slow, especially for thousands of clients), and No-SQL models were
still too new. The net effect of all of this is that the design was
conceptualised from an SQL viewpoint and there was no need to change.

By the time that the framework became mature enough to allow for non-SQL
database backends, the architecture was too well-established (and, to be fair,
well-vetted, without complications) to change.

Built-in versus extension interfaces
------------------------------------
SQL-type database modules are built-in only to maintain backwards-compatibility.
They will not be removed until a compelling reason is raised to force
``conf.py`` to be updated as part of an upgrade.

All future database development will occur using extension-modules, because
they're more flexible and can do whatever a site needs.

Integration
-----------
If you have an existing database that provides all or most of the information
below in an SQL setup, it might be worthwhile to create a view to transform it
into *staticDHCPd*'s format to reduce the amount of work you will need to do.

"subnets" table
---------------
A "subnet" is used to collect settings applicable to multiple clients. Its name
comes from the idea that members of a subnet will typically share the same
gateway, DNS servers, and other like details.

.. data:: subnet(text)
    
    While it's generally a good idea to use a value like ``192.168.0.0/24`` so
    you know, at a glance, what subnet its clients should be on, it is perfectly
    legal to set a value like ``my subnet``: this field is just free-form text.
    
    The origin of this field's name is directly related to the origin of the
    name of the table.
    
.. data:: serial(int)
    
    This field may be used to separate a subnet into partitions to do things
    like set different default gateways to reduce load on network hardware.
    
    Its name reflects the idea that, within a single subnet, there may be
    multiple configurations that are generated as environmental needs evolve.
    
.. data:: lease_time(int)
    
    The number of seconds for which clients will believe their "leases" to be
    valid; by default, T1 is half of this, so stable clients may update their
    information in as little as half this time.
    
.. data:: gateway(text)
    
    May be a list of comma-delimited IPv4 addresses or ``NULL`` to avoid
    setting the corresponding DHCP option. Normally, you will only specify one.
    
.. data:: subnet_mask(test)
    
    May be an IPv4 address or ``NULL`` to avoid setting the corresponding DHCP
    option. CIDR notation is not supported at this time.
    
.. data:: broadcast_address(text)
    
    May be an IPv4 address or ``NULL`` to avoid setting the corresponding DHCP
    option.
    
.. data:: ntp_servers(text)
    
    May be a list of comma-delimited IPv4 addresses or ``NULL`` to avoid
    setting the corresponding DHCP option. Up to three may be specified.
    
.. data:: domain_name_servers(text)
    
    May be a list of comma-delimited IPv4 addresses or ``NULL`` to avoid
    setting the corresponding DHCP option. Up to three may be specified.
    
.. data:: domain_name(text)
    
    May be any arbitrary, FQDN-valid string or ``NULL`` to avoid setting the
    corresponding DHCP option.
    
"maps" table
------------
Shortened from "mappings", this is where MACs are bound to specific leases.

.. data:: mac(string)
    
    A lower-case, colon-separated MAC address.
    
.. data:: ip(string)
    
    A dot-separated IPv4 address.
    
.. data:: hostname(string)
    
    May be a string or ``NULL`` to avoid setting the corresponding DHCP option.
    
.. data:: subnet(string)
    
    Must correspond to an entry in the `subnets` table.
    
.. data:: serial(int)
    
    Must correspond to an entry in the `subnets` table.
    