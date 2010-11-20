CREATE DATABASE dhcp;
USE dhcp;

CREATE TABLE subnets (
    subnet CHAR(18) NOT NULL, -- A human-readable subnet-identifier, large enough to hold a CIDR mask.
    serial SMALLINT UNSIGNED NOT NULL DEFAULT 0, -- A means of allowing a subnet to be reused, just in case you have two 192.168.1.0/24s.
    lease_time MEDIUMINT UNSIGNED NOT NULL, -- The number of seconds a "lease" is good for. This can be massive unless properties change often.
    gateway CHAR(15), -- The IPv4 gateway to supply to clients; may be null.
    subnet_mask CHAR(15), -- The IPv4 subnet mask to supply to clients; may be null.
    broadcast_address CHAR(15), -- The IPv4 broadcast address to supply to clients; may be null.
    ntp_servers CHAR(50), -- A comma-separated list of IPv4 addresses pointing to NTP servers; limit 3; may be null.
    domain_name_servers CHAR(50), -- A comma-separated list of IPv4 addresses pointing to DNS servers; limit 3; may be null.
    domain_name CHAR(128), -- The name of the search domain to be provided to clients.
    PRIMARY KEY(subnet, serial)
);

CREATE TABLE maps (
    mac CHAR(17) PRIMARY KEY, -- The MAC address of the client to whom the IP and associated options will be passed.
    ip CHAR(15) NOT NULL, -- The IPv4 address to provide to the client identified by the associated MAC.
    hostname CHAR(32), -- The hostname to assign to the client; may be null.
    subnet CHAR(18) NOT NULL, -- A human-readable subnet-identifier, used in conjunction with the serial.
    serial SMALLINT UNSIGNED NOT NULL DEFAULT 0, -- Together with the serial, this identifies the options to pass to the client.
    UNIQUE (ip, subnet, serial),
    FOREIGN KEY (subnet, serial) REFERENCES subnets (subnet, serial)
);

delimiter |
CREATE PROCEDURE cleanup()
    BEGIN
        OPTIMIZE LOCAL TABLE subnets, maps;
    END;
|
delimiter ;

/* staticDHCPd requires an account with SELECT access; the first of these lines grants that against its
   default config settings; the second provides a management account so you don't have to use root.
   How you get entries into the database is up to you, however.
GRANT SELECT ON dhcp.* TO 'dhcp_user'@'localhost' IDENTIFIED BY 'dhcp_pass';
GRANT SELECT, INSERT, DELETE, UPDATE, EXECUTE ON dhcp.* TO 'dhcp_maintainer'@'localhost' IDENTIFIED by 'dhcp_pass';
*/
