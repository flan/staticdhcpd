"""
Additional tools for processing DHCP requests

Copyright 2016 NaviSite Inc. - A Time Warner Cable Company
"""
import logging

_logger = logging.getLogger('tools')

def filterRetrievedDefinitions(definitions, packet, packet_type, mac,
                               ip, giaddr, pxe_options):
    """
    Filter the possible definitions by using the extra information

    :param list: A list of definitions types to filter
    :param basestring packet_type: The type of packet being processed.
    :param str mac: The MAC of the responding interface, in network-byte
        order.
    :param :class:`libpydhcpserver.dhcp_types.ipv4.IPv4` ip: Value of
        DHCP packet's `requested_ip_address` field.
    :param :class:`libpydhcpserver.dhcp_types.ipv4.IPv4` giaddr: Value of
        the packet's relay IP address
    :param namedtuple pxe_options: PXE options
    :return :class:`databases.generic.Definition` definition: The associated
        definition; None if no "lease" is available.
    """
    if not definitions:
        return None
    elif len(definitions) == 1:
        #replicates current functionality, may want to change
        return definitions[0]

    for definition in definitions:
        #TODO: Handle RENEW/REBIND where we know the IP address
        if giaddr and definition.subnet_mask:
            #We can determine the correct definition since the
            # giaddr should exist in the same network as
            # the response IP address
            #TODO: What happens under multiple relays in the chain?
            if giaddr.isSubnetMember(definition.ip, definition.subnet_mask):
               return definition
    _logger.debug("No match found in filtering.")
    return None
