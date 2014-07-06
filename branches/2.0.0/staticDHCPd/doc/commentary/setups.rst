Specialised and non-static configurations
=========================================
*staticDHCPd* is meant to help administrators easily configure static
environments, with easy-to-integrate provisioning facilities. However, special
cases arise and that's what makes the software truly powerful. Some of the more
interesting setups in the wild will be documented here.

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
They're should be pretty consistent: when IPs are added to the pool, if
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
