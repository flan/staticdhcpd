CREATE TABLE subnets (
    subnet TEXT NOT NULL, -- A human-readable subnet-identifier, typically a CIDR mask.
    serial INTEGER NOT NULL DEFAULT 0, -- A means of allowing a subnet to be reused, just in case you have two 192.168.1.0/24s.
    lease_time INTEGER NOT NULL, -- The number of seconds a "lease" is good for. This can be massive unless properties change often.
    gateway TEXT, -- The IPv4 gateway to supply to clients; may be null.
    subnet_mask TEXT, -- The IPv4 subnet mask to supply to clients; may be null.
    broadcast_address TEXT, -- The IPv4 broadcast address to supply to clients; may be null.
    ntp_servers TEXT, -- A comma-separated list of IPv4 addresses pointing to NTP servers; limit 3; may be null.
    domain_name_servers TEXT, -- A comma-separated list of IPv4 addresses pointing to DNS servers; limit 3; may be null.
    domain_name TEXT, -- The name of the search domain to be provided to clients.
    PRIMARY KEY(subnet, serial)
);

CREATE TABLE maps (
    mac TEXT PRIMARY KEY NOT NULL, -- The MAC address of the client to whom the IP and associated options will be passed.
    ip TEXT NOT NULL, -- The IPv4 address to provide to the client identified by the associated MAC.
    hostname TEXT, -- The hostname to assign to the client; may be null.
    subnet TEXT NOT NULL, -- A human-readable subnet-identifier, used in conjunction with the serial.
    serial INTEGER NOT NULL DEFAULT 0, -- Together with the serial, this identifies the options to pass to the client.
    UNIQUE (ip, subnet, serial),
    FOREIGN KEY (subnet, serial) REFERENCES subnets (subnet, serial)
);
