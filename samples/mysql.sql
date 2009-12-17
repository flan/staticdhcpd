CREATE DATABASE dhcp;
USE dhcp;

CREATE TABLE subnets (
	subnet CHAR(18),
	serial SMALLINT UNSIGNED,
	lease_time MEDIUMINT UNSIGNED NOT NULL,
	gateway CHAR(15),
	subnet_mask CHAR(15),
	broadcast_address CHAR(15),
	domain_name_servers CHAR(50),
	domain_name VARCHAR(255),
	PRIMARY KEY(subnet, serial)
);

CREATE TABLE maps (
	mac CHAR(17) PRIMARY KEY,
	ip CHAR(15) NOT NULL,
	subnet CHAR(18) NOT NULL,
	serial SMALLINT UNSIGNED,
	FOREIGN KEY (subnet, serial) REFERENCES subnets (subnet, serial)
);

GRANT SELECT ON dhcp.* TO 'dhcp_user'@'localhost' IDENTIFIED BY 'dhcp_pass';
/*GRANT INSERT, DELETE, UPDATE ON dhcp.* TO 'dhcp_user'@'%' IDENTIFIED by 'dhcp_pass';*/
