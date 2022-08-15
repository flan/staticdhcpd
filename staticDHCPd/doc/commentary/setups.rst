Specialised and non-static configurations
=========================================
*staticDHCPd* is meant to help administrators easily configure static
environments, with easy-to-integrate provisioning facilities. However, special
cases arise and that's what makes the software truly powerful. Some of the more
interesting setups in the wild will be documented here.

.. _setups-dynamic:

Dynamic hybrids
---------------
The motivating case for adding support for dynamic provisioning to *staticDHCPd*
was a LAN party context in which guests need to register their systems before
they can be given a static mapping by site administration. Using the `dynamism`
extension, unknown clients can be given configuration that puts them into an
isolated subnet on a short lease so they can access a registration system, and
the DHCP server itself can send notification of the new arrival to a webservice
to streamline the operators' work.

The rest of this article outlines how to use the sample extensions provided
with *staticDHCPd*. Any site seeking to use dynamic services will almost
certainly need to do some customisation, though, so consider at least basic
Python knowledge to be a pre-requisite.

Be aware also that, unlike dynamic-provisioning-focused servers, like the ISC's,
not all provisioning semantics are respected and that, unlike *staticDHCPd*'s
static behaviour, this facet of the system is not RFC-compliant. It probably
won't do anything environment-breaking, but be prepared for some weird things;
feedback, if you encounter anything curious, is very welcome.

Setup
+++++
For the common case, it is enough to
:doc:`install <../customisation/extensions>` ``dynamism.py`` normally.

If you want to do anything cooler, like send a JSON message to a webservice when
an unknown MAC appears or block clients after they renew five times, subclass
``DynamicPool`` or just hack it in-place. It's simple code and it's your
environment, so just apply what you find in tutorials on the Internet and have
fun!

How stable are dynamic leases?
++++++++++++++++++++++++++++++
They should be pretty consistent: when IPs are added to the pool, if
`scapy <http://www.secdev.org/projects/scapy/>`_ is available, and if the
scan option is enabled, the server will ARP for each address (in parallel, so
it's not slow), setting up leases as hits are found, making your network a
living database. Additionally, if a client requests a specific IP after the
server is already online (clients often do this when rebooting), that address
will be plucked if available.

If scapy is unavailable, you'll probably get a lot of DECLINEs, but your network
will stabilise before too long.

Is DST a factor with leases?
++++++++++++++++++++++++++++
No, DST shouldn't be relevant. Internally, leases are managed as offsets against
UTC, so timezones are only applied when formatting the timestamps for
presentation to operators.

.. _setups-pxe:

PXE support
-----------
In general, it should be sufficient to test for option 60
(`vendor_class_identifier`) in :ref:`scripting-loadDHCPPacket` to see if it
matches the device-type you want to net-boot and set options 60, 66
(`tftp_server_name`), and 67 (`bootfile_name`) accordingly, as demonstrated in
the following example::

    vendor_class_identifier = source_packet.getOption('vendor_class_identifier', convert=True)
    if vendor_class_identifier and vendor_class_identifier.startswith('PXEClient'):
        #The device may look for a specific value; check your manual
        packet.setOption('vendor_class_identifier', 'PXEServer:staticDHCPd')
        #Tell it where to get its bootfile; IPs are valid, too
        packet.setOption('tftp_server_name', 'bootserver.example.org')
        #Have the device ask for its own MAC, stripped of colons and uppercased
        packet.setOption('bootfile_name', str(mac).replace(':', '').upper() + '.cfg')
        
Those working with systems derived from BOOTP, rather than DHCP, like embedded
BIOS-level stacks, will probably want to do something more like this::
    
    vendor_class_identifier = source_packet.getOption('vendor_class_identifier', convert=True)
    if vendor_class_identifier and vendor_class_identifier.startswith('PXEClient'):
        #Tell it where to get its bootfile; your device probably isn't
        #DNS-aware if it's using BOOTP, but the field is free-form text
        packet.setOption('siaddr', DHCP_SERVER_IP) #The same address defined earlier in conf.py
        #Tell it which file to look for; pxelinux.0 is pretty common
        packet.setOption('file', 'pxelinux.0')

The two approaches are not mutually exclusive and well-behaved clients should
only look at the fields they understand. But it's probably safest to use ``if``
clauses to be sure that you're not at risk of confusing a partial
implementation.

Of course, you can use other criteria to evaluate whether an option should be
set and what its value should be.

In the event that the client tries to hit a ProxyDHCP port (4011, by
convention), you'll need to edit ``conf.py`` and assign the port number to
**PROXY_PORT**. This will cause *staticDHCPd* to bind another port on the same
interface(s) as the main DHCP port; full DHCP service will be provided on that
port, too, including IP assignment.

The ``port`` parameter in :ref:`scripting-loadDHCPPacket` and other functions
will allow site-specific code to respond differently depending on how the packet
was received; you can use simple tests like this to apply appropriate logic::
    
    if port == PROXY_PORT: #The address defined in conf.py
        #set special fields
        
Chances are, in most cases, the client will have been assigned an IP over the
standard DHCP port already, testable with ``packet.getOption('ciaddr')``, and
though it's highly unlikely, the device may complain if the response contains an
IP offer; ``packet.deleteOption('yiaddr')`` takes care of this.
