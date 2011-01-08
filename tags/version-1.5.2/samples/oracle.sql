CREATE DATABASE dhcp;
ALTER SESSION SET CURRENT_SCHEMA = dhcp;

CREATE TABLE subnets (
    subnet VARCHAR2(18) NOT NULL, -- A human-readable subnet-identifier, large enough to hold a CIDR mask.
    serial PLS_INTEGER NOT NULL DEFAULT 0, -- A means of allowing a subnet to be reused, just in case you have two 192.168.1.0/24s.
    lease_time PLS_INTEGER NOT NULL, -- The number of seconds a "lease" is good for. This can be massive unless properties change often.
    gateway VARCHAR2(15), -- The IPv4 gateway to supply to clients; may be null.
    subnet_mask VARCHAR2(15), -- The IPv4 subnet mask to supply to clients; may be null.
    broadcast_address VARCHAR2(15), -- The IPv4 broadcast address to supply to clients; may be null.
    ntp_servers VARCHAR2(50), -- A comma-separated list of IPv4 addresses pointing to NTP servers; limit 3; may be null.
    domain_name_servers VARCHAR2(50), -- A comma-separated list of IPv4 addresses pointing to DNS servers; limit 3; may be null.
    domain_name VARCHAR2(128), -- The name of the search domain to be provided to clients.
    PRIMARY KEY(subnet, serial)
);

CREATE TABLE maps (
    mac CHAR(17) PRIMARY KEY, -- The MAC address of the client to whom the IP and associated options will be passed.
    ip VARCHAR2(15) NOT NULL, -- The IPv4 address to provide to the client identified by the associated MAC.
    hostname VARCHAR2(32), -- The hostname to assign to the client; may be null.
    subnet VARCHAR2(18) NOT NULL, -- A human-readable subnet-identifier, used in conjunction with the serial.
    serial PLS_INTEGER NOT NULL DEFAULT 0, -- Together with the serial, this identifies the options to pass to the client.
    UNIQUE (ip, subnet, serial),
    FOREIGN KEY (subnet, serial) REFERENCES subnets (subnet, serial)
);

/* staticDHCPd requires an account with SELECT access; if anyone can provide a sane description of
   how to set this up under Oracle, it would be very much appreciated.
*/
