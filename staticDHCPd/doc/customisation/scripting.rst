Scripting guide
===============
In addition to static parameters to configure *staticDHCPd* to work in your
environment, extensive scripting is possible, allowing it to perform dynamic
allocations, send events to other systems, and give you full control over every
last detail of how DHCP works in your domain.

As with the static parameters, scripting logic is intended to be as
forwards-compatible as possible, so newer versions of the server should work
with any extensions you've developed, with no issues.
(Check the changelog, though)

Organising your setup
---------------------
To avoid potential conflicts, any non-standard functions you may define should
be named with a leading underscore. Likewise, any modules you define should also
be named with a leading underscore.

If you wish to encapsulate code inside of a module, place it in the
``staticDHCPd_extensions/`` subdirectory next to ``conf.py`` or in a subpackage thereof. The
``staticDHCPd_extensions/`` subdirectory is added to ``sys.path``, so imports from a
relative root should work just like they usually do.

In particular, if you expect to have a lot of custom code, you should create a
file in the ``staticDHCPd_extensions/`` subdirectory named ``_handlers.py`` and import
the main callback functions from there to keep ``conf.py`` clean. At the same
level as the config directives, do something like the following::

    from _handlers import (handleUnknownMAC, loadDHCPPacket)
    #Where the things imported are the handlers you've defined

Note that, although ``_handlers`` is in ``staticDHCPd_extensions/``, it is imported as a
root-level module.

Note also that your handlers module will not have access to functions and
namespace elements defined within ``conf.py``. For this reason, it is a good
idea to define ``init()`` in ``conf.py()`` to do the run-once work (which is
what most of the built-ins are for), but export the runtime operations to the
new namespace. You can inject needed elements into it as part of ``init()``,
too::
    
    def init():
        import _handlers
        _handlers.rfc1035_plus = rfc1035_plus

Important data-types
--------------------
*staticDHCPd* has some local data-types that are used throughout the framework:

* :class:`databases.generic.Definition`

* :data:`statistics.Statistics`

Customising DHCP behaviour
--------------------------
Several functions are provisioned as hooks from *staticDHCPd*'s core. To
make use of one, just create a function in ``conf.py`` with the corresponding
signature.

All of these functions can share packet-specific data using *libpydhcpserver*'s
``meta`` attribute on the packet object. This is a dictionary that neither
*staticDHCPd* nor *libpydhcpserver* ever touch, letting you use it for
whatever you want.

.. _scripting-init:

init()
++++++
.. function:: init()

    Called immediately after all of staticDHCPd's other subsystems have been
    configured.

Example
|||||||
::
    
    def _tick_logger():
        #A trivial function that writes to the log whenever a tick occurs
        logger.debug("Ticked!")
        
    def init():
        callbacks.systemAddTickHandler(_tick_logger)

When init() is called, the `_tick_logger()` function, also defined in
``conf.py``, will be registered to be invoked every time the system generates
a "tick" event.

To do something before *staticDHCPd* has finished bringing up its own
subsystems, write your logic at the same level as the parameter definitions,
where `_tick_logger()` is defined.

.. _scripting-filterPacket:

filterPacket()
++++++++++++++
.. function:: filterPacket(packet, method, mac, client_ip, relay_ip, port)

    Provides a means of writing your own blocklist logic, excluding packets from
    sources you don't trust, that have done weird things, or under any other
    conceivable circumstance.
    
    It is called before the MAC is looked up in the database or by
    :func:`handleUnknownMAC`. Returning ``True`` will cause the MAC to proceed
    through the chain as normal, while returning ``False`` will cause it to be
    discarded. Returning ``None`` will put it into the temporary blocklist, like
    other MACs that trip *staticDHCPd*'s configurable thresholds.

    :param packet: The packet received from the client, an instance of
                   :class:`libpydhcpserver.dhcp_types.packet.DHCPPacket`.
                   
                   Any changes made to this packet will persist.
    :param method: The type of DHCP request the packet represents, one of
                       ``DECLINE``, ``DISCOVER``, ``INFORM``, ``RELEASE``,
                       ``REQUEST:INIT-REBOOT``, ``REQUEST:REBIND``,
                       ``REQUEST:RENEW``, ``REQUEST:SELECTING``.
    :type method: str
    :param mac: The MAC of the client, an instance of
                :class:`libpydhcpserver.dhcp_types.mac.MAC`.
    :param client_ip: The client's requested IP address (may be ``None``), an
                      instance of :class:`libpydhcpserver.dhcp_types.ipv4.IPv4`.
    :param relay_ip: The relay used by the client (may be ``None``), an
                     instance of :class:`libpydhcpserver.dhcp_types.ipv4.IPv4`.
    :param port: The port on which the packet was received.
    :type port: int
    :return: ``False`` if the packet should be rejected; ``True``
                  if it should be accepted; ``None`` if the source should be
                  ignored temporarily.

Example
|||||||
::

    import random
    def filterPacket(packet, method, mac, client_ip, relay_ip, port):
        return random.random() > 0.2
        
This will fake a lossy network, dropping 20% of all packets received.

.. _scripting-handleUnknownMAC:

handleUnknownMAC()
++++++++++++++++++
.. function:: handleUnknownMAC(packet, method, mac, client_ip, relay_ip, port)

    If staticDHCPd gets a request to serve a MAC that it does not recognise,
    this function will be invoked, allowing you to query databases of your own
    to fill in the blanks.
    
    :param packet: The packet received from the client, an instance of
                   :class:`libpydhcpserver.dhcp_types.packet.DHCPPacket`.
                   
                   Any changes made to this packet will persist.
    :param method: The type of DHCP request the packet represents, one of
                       ``DECLINE``, ``DISCOVER``, ``INFORM``, ``RELEASE``,
                       ``REQUEST:INIT-REBOOT``, ``REQUEST:REBIND``,
                       ``REQUEST:RENEW``, ``REQUEST:SELECTING``.
    :type method: str
    :param mac: The MAC of the client, an instance of
                :class:`libpydhcpserver.dhcp_types.mac.MAC`.
    :param client_ip: The client's requested IP address (may be ``None``), an
                      instance of :class:`libpydhcpserver.dhcp_types.ipv4.IPv4`.
    :param relay_ip: The relay used by the client (may be ``None``), an
                     instance of :class:`libpydhcpserver.dhcp_types.ipv4.IPv4`.
    :param port: The port on which the packet was received.
    :type port: int
    :return: An instance of :class:`databases.generic.Definition` or ``None``,
             if the MAC could not be handled.

Example
|||||||
::
    
    import databases.generic.Definition
    def handleUnknownMAC(packet, method, mac, client_ip, relay_ip, port):
        if mac == 'aa:bb:cc:dd:ee:ff':
            return databases.generic.Definition(
                ip='192.168.0.100', lease_time=600,
                subnet='192.168.0.0/24', serial=0,
                hostname='guestbox',
                #gateways=None, #The old format didn't support per-definition gateways
                subnet_mask='255.255.255.0',
                broadcast_address='192.168.0.255',
                domain_name='guestbox.example.org.',
                domain_name_servers=['192.168.0.5', '192.168.0.6', '192.168.0.7'],
                ntp_servers=['192.168.0.8', '192.168.0.9'],
            )
        return None

It is difficult to provide a general example of how to use this function, since
its role is basically that of a code-driven database. When you need to use it,
you will know.

filterRetrievedDefinitions()
++++++++++++++++++++++++++++
.. function:: filterRetrievedDefinitions(definitions, packet, method, mac, client_ip, relay_ip, port)

    Some databases produce collections of :class:`databases.generic.Definition`
    objects, rather than simply returning one or ``None``. This function allows
    you to use runtime information, not necessarily passed back to the database,
    to make a decision about which :class:`databases.generic.Definition` to use
    for processing the request.
    
    :param definitions: A collection of :class:`databases.generic.Definition`s.
    :param packet: The packet received from the client, an instance of
                   :class:`libpydhcpserver.dhcp_types.packet.DHCPPacket`.
                   
                   Any changes made to this packet will persist.
    :param method: The type of DHCP request the packet represents, one of
                       ``DECLINE``, ``DISCOVER``, ``INFORM``, ``RELEASE``,
                       ``REQUEST:INIT-REBOOT``, ``REQUEST:REBIND``,
                       ``REQUEST:RENEW``, ``REQUEST:SELECTING``.
    :type method: str
    :param mac: The MAC of the client, an instance of
                :class:`libpydhcpserver.dhcp_types.mac.MAC`.
    :param client_ip: The client's requested IP address (may be ``None``), an
                      instance of :class:`libpydhcpserver.dhcp_types.ipv4.IPv4`.
    :param relay_ip: The relay used by the client (may be ``None``), an
                     instance of :class:`libpydhcpserver.dhcp_types.ipv4.IPv4`.
    :param port: The port on which the packet was received.
    :type port: int
    :return: An instance of :class:`databases.generic.Definition` or ``None``,
             if the `definitons` could not be processed.

Example
|||||||
This is a very site-specific feature, since no built-in database modules
support cases with MAC-collisions.

Likely users of this feature will be heavy users of VM environments, where
images may be loaded on multiple systems in various subnets, without the MAC
being redefined.

Before resorting to this approach for resolving such conflicts, consider using
`handleUnknownMAC()`_ and passing the parameters it receives to your database
engine. `filterRetrievedDefinitions()`_ is appropriate only in the case where
the database layer cannot do additional processing on its own or runtime context
is only available on the DHCP server for technical reasons.

.. _scripting-loadDHCPPacket:

loadDHCPPacket()
++++++++++++++++
.. function:: loadDHCPPacket(packet, method, mac, definition, relay_ip, port, source_packet)

    Before any response is sent to a client, an opportunity is presented to
    allow you to modify the packet, adding or removing options and setting
    values as needed for your environment's specific requirements. Or even
    allowing you to define your own blocklist rules and behaviour.

    :param packet: The packet to be sent to the client, an instance of
                   :class:`libpydhcpserver.dhcp_types.packet.DHCPPacket`.
    :param method: The type of DHCP request the packet represents, one of
                       ``DECLINE``, ``DISCOVER``, ``INFORM``, ``RELEASE``,
                       ``REQUEST:INIT-REBOOT``, ``REQUEST:REBIND``,
                       ``REQUEST:RENEW``, ``REQUEST:SELECTING``.
    :type method: str
    :param mac: The MAC of the client, an instance of
                :class:`libpydhcpserver.dhcp_types.mac.MAC`.
    :param definition: The lease-definition provided via MAC-lookup, an instance
                       of :class:`databases.generic.Definition`.
    :param relay_ip: The relay used by the client (may be ``None``), an
                     instance of :class:`libpydhcpserver.dhcp_types.ipv4.IPv4`.
    :param port: The port on which the packet was received.
    :type port: int
    :param source_packet: The packet received from the client, an instance of
                          :class:`libpydhcpserver.dhcp_types.packet.DHCPPacket`.
                          
                          This is a pristine copy of the original packet,
                          unaffected by any previous modifications.
    :return: ``True`` if processing can proceed; ``False`` if the packet
             should be rejected.

Example
|||||||
::
    
    import random
    def loadDHCPPacket(packet, method, mac, definition, relay_ip, port, source_packet):
        if not definition.ip[3] % 3: #The client's IP's fourth octet is a multiple of 3
            packet.setOption('renewal_time_value', 60)
        elif method.startswith('REQUEST:') and random.random() < 0.5:
            packet.transformToDHCPNakPacket()
        elif random.random() < 0.1:
            return False
        return True
        
This will set the renewal-time (T1) for clients to one minute if they have an IP
that ends in a multiple of 3.

If the first qualifier isn't satisfied and it's a REQUEST-type packet, there's
a 50% chance that it will be changed into a NAK response.

Lastly, if neither of the previous conditions were met, there's a 10% chance the
packet will simply be dropped.

.. _scripting-callbacks:

Using system callbacks
----------------------
A number of callbacks exist that let you hook your code into *staticDHCPd*'s
core functions and modules. All of these are accessible from anywhere within
`conf.py`.

.. function:: callbacks.systemAddReinitHandler(callback)
    
    Registers a reinitialisation callback.
    
    :param callable callback: A callable that takes no arguments; if already
                              present, it will not be registered a second time.
    
.. function:: callbacks.systemRemoveReinitHandler(callback)
    
    Unregisters a reinitialisation callback.
    
    :param callable callback: The callback to remove.
    :return: True if a callback was removed.

.. function:: callbacks.systemAddTickHandler(callback)
    
    Registers a tick callback. Tick callbacks are invoked approximately once per
    second, but should treat this as a wake-up, not a metronome, and query the
    system-clock if performing any time-sensitive operations.
    
    :param callable callback: A callable that takes no arguments; if already
                              present, it will not be registered a second time.
                              The given callable must not block for any
                              significant amount of time.
    
.. function:: callbacks.systemRemoveTickHandler(callback)

    Unregisters a tick callback.
    
    :param callable callback: The callback to remove.
    :return bool: True if a callback was removed.
    
.. function:: callbacks.statsAddHandler(callback)
    
    Registers a statistics callback.
    
    :param callable callback: A callable that takes
                              :data:`statistics.Statistics` as its argument; if
                              already present, it will not be registered a
                              second time. This function must never block for
                              any significant amount of time.

.. function:: callbacks.statsRemoveHandler(callback)

    Unregisters a statistics callback.
    
    :param callable callback: The callable to be removed.
    :return bool: True if a callback was removed.
    
.. data:: callbacks.WEB_METHOD_DASHBOARD

    The content is rendered before the dashboard.
    
.. data:: callbacks.WEB_METHOD_TEMPLATE

    The content is rendered in the same container that would normally show the
    dashboard, but no dashboard elements are present.
    
.. data:: callbacks.WEB_METHOD_RAW
    
    The content is presented exactly as returned, identified by the given
    MIME-type.
    
.. function:: callbacks.webAddHeader(callback)
    
    Installs an element in the headers; at most one instance of any given
    ``callback`` will be accepted.
    
    :param callable callback: Must accept the parameters `path`, `queryargs`,
                              `mimetype`, `data`, and `headers`, with the
                              possibility that `mimetype` and `data` may be
                              None; `queryargs` is a dictionary of parsed
                              query-string items, with values expressed as lists
                              of strings; `headers` is a dictionary-like object.
                              
                              It must return data as a string, formatted as
                              XHTML, to be embedded inside of <head/>, or None
                              to suppress inclusion.
                              
.. function:: callbacks.webRemoveHeader(callback)
    
    Removes a header element.
    
    :param callable callback: The element to be removed.
    :return bool: True if an element was removed.

.. function:: callbacks.webAddDashboard(module, name, callback, ordering=None)
    
    Installs an element in the dashboard; at most one instance of any given
    ``callback`` will be accepted.
    
    :param basestring module: The name of the module to which this element
                              belongs.
    :param basestring name: The name under which to display the element.
    :param callable callback: Must accept the parameters `path`, `queryargs`,
                              `mimetype`, `data`, and `headers`, with the
                              possibility that `mimetype` and `data` may be
                              None; `queryargs` is a dictionary of parsed
                              query-string items, with values expressed as lists
                              of strings; `headers` is a dictionary-like object.
                              
                              It must return data as a string, formatted as
                              XHTML, to be embedded inside of a <div/>, or None
                              to suppress inclusion.
    :param int ordering: A number that controls where this element will appear
                         in relation to others. If not specified, the value will
                         be that of the highest number plus one, placing it at
                         the end; negatives are valid.
                         
.. function:: callbacks.webRemoveDashboard(callback)
    
    Removes a dashboard element.
    
    :param callable callback: The element to be removed.
    :return bool: True if an element was removed.

.. function:: callbacks.webAddMethod(path, callback, cacheable=False, hidden=True, secure=False, module=None, name=None, confirm=False, display_mode=WEB_METHOD_RAW)
    
    Installs a webservice method; at most one instance of ``path`` will be
    accepted.
    
    :param basestring path: The location at which the service may be called,
        like "/ca/uguu/puukusoft/staticDHCPd/extension/stats/histograph.csv".
    :param callable callback: Must accept the parameters `path`, `queryargs`,
                              `mimetype`, `data`, and `headers`, with the
                              possibility that `mimetype` and `data` may be
                              None; `queryargs` is a dictionary of parsed
                              query-string items, with values expressed as lists
                              of strings; `headers` is a dictionary-like object.
                              
                              It must return a tuple of (mimetype, data,
                              headers), with data being a string or bytes-like
                              object.
    :param bool cacheable: Whether the client is allowed to cache the method's
                           content.
    :param bool hidden: Whether to render a link in the side-bar.
    :param bool secure: Whether authentication will be required before this
                        method can be called.
    :param basestring module: The name of the module to which this element
                              belongs.
    :param basestring name: The name under which to display the element.
    :param bool confirm: Adds JavaScript validation to ask the user if they're
                         sure they know what they're doing before the method
                         will be invoked, if not `hidden`.
    :param display_mode: One of the WEB_METHOD_* constants.
    
.. function:: callbacks.webRemoveMethod(path)
    
    Removes a method element.
    
    :param basestring path: The element to be removed.
    :return bool: True if an element was removed.

.. _scripting-logging:

Logging facilities
------------------
*staticDHCPd* uses Python's native logging framework::
    
    logger.debug("The value of some parameter is %(param)r" % {
        'param': my_variable,
    })
    logger.info("Some step finished")
    logger.warn("The client is supposed to have been decommissioned")
    logger.error("The client provided invalid data")
    logger.critical("The database is offline")
    
In any modules you create, do the following at the start to hook into it::
    
    import logging
    logger = logging.getLogger('your-extension')
    
For backwards-compatibility reasons, an alias for the `warning` level is
provided; please do not use this and be sure to change any existing code::
    
    writeLog("Something happened")

``conf.py`` Environment
-----------------------
A number of convenience resources are present in ``conf.py``'s namespace by
default; these are enumerated here so you know what's provided out-of-the-box.

.. _scripting-conversion:

Conversion functions
++++++++++++++++++++
Various functions from *libpydhcpserver*. It is very rare that you will need to
make use of these directly from `2.0.0` onwards, but they exist for
backwards-compatibility and special cases.

* listToIP(``[127, 0, 0, 1]``) -> ``IPv4``
* listToIPs(``[127, 0, 0, 1, 127, 0, 0, 2]``) -> ``[IPv4, IPv4]``
* ipToList(``IPv4``) -> ``[127, 0, 0, 1]``
* ipsToList(``[IPv4, IPv4]``) -> ``[127, 0, 0, 1, 127, 0, 0, 2]``
* listToInt(``[127, 10]``) -> ``32522``
* listToInts(``[127, 10, 127, 9]``) -> ``[32522, 32521]``
* listToLong(``[16, 23, 127, 10]``) -> ``269975306``
* listToLongs(``[16, 23, 127, 10, 16, 23, 127, 9]``) -> ``[269975306, 269975305]``
* intToList(``32522``) -> ``[127, 10]``
* intsToList(``[32522, 32521]``) -> ``[127, 10, 127, 9]``
* longToList(``269975306``) -> ``[16, 23, 127, 10]``
* longsToList(``[269975306, 269975305]``) -> ``[16, 23, 127, 10, 16, 23, 127, 9]``
* strToList(``'hello'``) -> ``[104, 101, 108, 108, 111]``
* strToPaddedList(``'hello', 7``) -> ``[104, 101, 108, 108, 111, 0, 0]``
* listToStr(``[104, 101, 108, 108, 111]``) -> ``'hello'``

.. _scripting-rfc:

RFC interfaces
++++++++++++++
Also from *libpydhcpserver* is the RFC utility-set. You may need to use these at
some point, so it is worth reading *libpydhcpserver*'s documentation for more
information.

* rfc3046_decode
* rfc3925_decode
* rfc3925_125_decode
* rfc1035_plus
* rfc2610_78
* rfc2610_79
* rfc3361_120
* rfc3397_119
* rfc3442_121
* rfc3925_124
* rfc3925_125
* rfc4174_83
* rfc4280_88
* rfc5223_137
* rfc5678_139
* rfc5678_140
