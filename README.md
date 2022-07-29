<a href='http://uguu.ca/wp-content/uploads/2013/03/staticDHCPd-2.0.0-beta-1.png'><img src='http://uguu.ca/wp-content/uploads/2013/03/staticDHCPd-2.0.0-beta-1-300x168.png' align='right' /></a>

staticDHCPd is an all-Python, [RFC 2131](http://www.ietf.org/rfc/rfc2131.txt)-compliant DHCP server, with support for most common DHCP extensions and extensive site-specific customisation.

**Work has begun on porting staticDHCPd to Python 3, as 3.0.0**

The 3.0.0 branch will need to be tested; the remaining checklist follows (if you test a thing, respond to issue #89):
  * staticDHCPd
    * Long-term soak-test
      * Stable memory usage
        * _memory may fluctuate a bit during operation, but it cannot grow indefinitely, regardless of network size_
        * _if possible, give it a week in a moderately busy network and check in a couple of times each day, sharing your numbers_
      * No processing errors
        * _no unusual or inexplicable behaviour_
        * _all errors must be handled sensibly_
    * E-mail logging facility
      * _it needs to work_
    * Databases
      * custom
        * _it needs to work_
      * PostgreSQL
        * _it needs to work_
      * MySQL
        * _it needs to work_
      * Oracle
        * _it needs to work_
      * connection-pooling
        * _should work with at least Postgres and MySQL; ideally also Oracle_
  * Extensions
    * httpdb
      * _it needs to work_
    * statistics graph
      * _reimplemented browser-side using Chart.js_
        * _needs to be tested in a non-lab context_
    * dynamism
      * _must handle dynamic allocation_
      * _must honour renewals and rebinds with the same address_
      * _must support releases_
    * feedservice
      * _it needs to work (or be removed)_
  * Documentation
    * libpydhcpserver
      * _correctness check_
      * _proofreading_
    * staticDHCPd
      * _correctness check_
      * _proofreading_
  * Build-processes
    * RPMs
      * _the script either needs to produce usable artifacts or be removed_

At this point, no new features will be added until the system is stable (but please submit ideas to the issue-tracker anyway). Any non-bugfix commits will be things to prepare for the Debian/RPM packages or minor formatting tweaks.

---

# Target audience #
staticDHCPd is appropriate for a very wide range of applications. In particular, it's an excellent choice for the following:
  * Sites with a need to centrally manage a potentially vast number of clients, all of which are known
    * staticDHCPd was originally developed to meet the needs of a growing ISP, with relays and multiple subnets
  * LAN parties
    * You can use the dynamic module to assign guest leases, have people connect log in to a registration page, which provisions a static assignment, and then let them plug into the real network; you can have staticDHCPd do the layer-2-to-layer-3 bridging for the website with just a few lines of code, so your users don't need to check any addresses on their own
  * Research and testing labs
    * Simple setup and configuration, even for network-based booting (PXE, TFTP), so you can focus on what matters, not esoteric syntax and troubleshooting
  * Home or small office environments where you'll have an always-on server
    * All of the important stuff can be static, so you can quickly spot irregularities with device auto-configuration, while still offering a dynamic network for guests
    * This is especially helpful for laptops that provide services, where you need to be able to auto-configure when you're out somewhere, but want everything to "just work" when you get home, without needing to change from DHCP to static addressing
  * Any situation in which you've ever thought "this would be so much easier if only I could control this one thing"
    * staticDHCPd has [extensive scripting support](http://static.uguu.ca/projects/staticDHCPd/doc/customisation/scripting.html)
    * It also lets you [customise pretty much everything](http://static.uguu.ca/projects/staticDHCPd/doc/customisation/configuration.html) that a client sees
    * And you can [tie it into any database imaginable](http://static.uguu.ca/projects/staticDHCPd/doc/customisation/configuration.html#database-engine-text-none-must-be-specified)

On the other hand, it's the wrong choice in the following cases:
  * Your environment is entirely dynamic
    * Consider the [ISC's server](http://www.isc.org/software/dhcp) for this
  * Your environment is large and mostly dynamic, with need for only a few static assignments
    * Again, the ISC's server is a good choice
  * You already have a solution that works well for your needs
    * Why are you considering alternatives?
  * Your employer won't let you run anything without an SLA
    * You're probably looking for solutions in the wrong place
  * You actually **want** to have a hard time upgrading from one version to the next
    * staticDHCPd will let you take your config file and custom code from version 1.0 and drop it into 2.0 or 3.0 with no changes required, even though the codebase running it is entirely different
  * The concept of a feature-rich server running with a 4MB footprint scares you

If you think it might be a good match for your needs, take a look at its [five-minute quick-start guide](https://github.com/flan/staticdhcpd/blob/3.0.x/staticDHCPd/README).


---

# Origins #
staticDHCPd was originally created for an ISP, which, as you can imagine, requires that its provisioning tools offer full control over which MACs are allowed to learn about and gain access to its network. It was also necessary that the database of authorised clients be updatable with no delay and that it could be easily linked to other systems to streamline the provisioning process, both of which were factors in excluding the ISC's server as a candidate.

Its name comes from these circumstances, in which the only thing required of the system was that it could serve static "leases" and do it well. That's no longer the case, though, since it's matured quite a bit and picked up enough scriptable flexibility that dropping in a module to handle dynamic allocation can be done with five lines of customisation code (which is given its own, out-of-the-core-codebase home), only one of which is truly site-dependent.


---

# Overview #
Internally, staticDHCPd makes use of a forked version of Mathieu Ignacio's [pydhcplib](http://pydhcplib.tuxfamily.org/pmwiki/) (though few traces of its ancestry remain) and is developed against [Debian](http://www.debian.org/)-[based](http://www.ubuntu.com/) [GNU](http://www.gnu.org/)/[Linux](http://www.kernel.org/) distributions and has been shown to operate on [FreeBSD](http://www.freebsd.org/) and [Apple Mac OS X](http://www.apple.com/), for which it was originally created. It should run on any Unix variant without issue, but is not supported on [Microsoft Windows](http://www.microsoft.com/), due to a lack of familiarity with permissions, sockets, and signals on that platform (a patch would be welcome, but must be accompanied by a commitment of maintenance).

A rich, fully customisable and extensible web-management console is included (and reasonably secure, through optional use of DIGEST authentication), intended to make life easy for NOC staff or curious administrators. It, a statistics engine, and a host of other features are all optional and lazily loaded, so your server will never be unnecessarily bloated.

Comprehensive logging and reporting systems are built-in, from standard things like self-rotating files to in-memory web-dashboard reporting to Atom feeds for keeping an eye on the server while you stay up to date with the news to e-mail notification for emergencies.

All features tested against the ISC's <tt>dhclient</tt> and <tt>dhcrelay</tt> to ensure compatibility with the DHCP protocol in realistic contexts. Furthermore, its developer uses it for practical purposes: a single home server manages multiple networks, containing various consumer electronics (phones, tablets, game consoles, printers), dedicated servers, laptops, desktops, and guest devices.


---

# Documentation #
All documentation found outside of the following resources is pre-2.0.0 and should be considered deprecated.

3.0.x is largely identical to 2.0.x, with the exception of any errata noted below.

libpydhcpserver: http://static.uguu.ca/projects/libpydhcpserver/doc/

staticDHCPd: http://static.uguu.ca/projects/staticDHCPd/doc/

## 3.0.x errata ##

### Extensions ###
* Owing to conflicts with Python's standard library and changes to how import-semantics work, extensions now live in `/etc/staticDHCPd/staticDHCPd_extensions`
  * To migrate, move any existing extensions from `/etc/staticDHCPd/extensions/` and change the corresponding `import` lines in `conf.py` to be `import staticDHCPd_extensions.<extension>`
  * No other changes should be needed in the common case


---

# Making it go #
## Downloading ##
Stable releases of staticDHCPd are available from the [releases page](https://github.com/flan/staticdhcpd/releases).

Debian packages for 3.0.x will be published as it approaches release.

## Testing ##
The [README](https://github.com/flan/staticdhcpd/blob/3.0.x/staticDHCPd/README) contains a quick-start guide. It will walk you through creating a simple configuration database and running staticDHCPd without making any changes to your server.

## Installing ##
Just run `sudo sh install.sh`, or whatever equivalent is appropriate for your platform, and everything will be where it needs to go. You'll also receive some helpful (disclaimer: only as helpful as its users) text that will explain how to make the server run automatically on boot, specific to your platform.

You'll find a sample configuration file in `/etc/staticDHCPd/`; copy it to the same directory, without the `.sample` suffix, and you're ready for the next step. (If you're upgrading, just leave your old file alone; it'll work just fine)

## Configuring ##
While SQLite or INI-files are fine for home users and small labs, most environments will want to use a multi-client database service, to allow for runtime updates. Full details on how to configure staticDHCPd to speak with a server, and many more options, are described in the configuration guide in the `doc` directory.

For the server itself, [specific schema-structuring](database.md) is required, for which scripts and examples can be found in the `samples` directory.

Additionally, some database engines require additional packages:
  * **Postgres** support requires installation of the [psycopg](http://initd.org/psycopg/) library (<tt>python3-psycopg2</tt>)
  * **Oracle** support requires installation (and likely compilation) of the [cx-oracle](http://cx-oracle.sourceforge.net/) library
  * **MySQL** support requires installation of the [MySQLdb](http://mysql-python.sourceforge.net/) library (<tt>python3-mysqldb</tt>)
  * Connection-pooling requires [eventlet](http://eventlet.net/) (<tt>python3-eventlet</tt>)

While you're at it, you should also install <tt>python3-scapy</tt> if you intend to use dynamic provisioning. It'll allow your network to serve as a living database for reconstructing leases after a server restart. [scapy](http://www.secdev.org/projects/scapy/) is also a pretty great library in general. And, if you want the snazzy load-graph in the web interface, also install <tt>python3-pycha</tt>. These libraries aren't necessary, though: the associated components will function in a limited capacity if they're absent.

## Running ##
Once everything's configured, you can launch the daemon with `sudo staticDHCPd`. You'll need to start it with superuser permissions because it needs to bind to restricted ports, but it'll switch to whatever permissions you specified in the config file once setup is complete.

If you're using caching (or INI) with your database, you can send <tt>SIGHUP</tt> to the process to cause it to reinitialise, clearing the cache (or re-reading the file), and invoking the reinitialisation behaviour of any custom modules that subscribe to the event. You can also, if enabled, access this functionality from the web interface.

To kill the server, you can <tt>^C</tt> it in non-daemon mode, or send <tt>SIGTERM</tt> otherwise. It'll go down gracefully.


---

# Getting involved with development #
staticDHCPd is available under the [GPLv3](http://www.gnu.org/licenses/gpl-3.0.html). Accordingly, its full source code and all assets are available for use by anyone who wants to learn how something was done or to create a derivative work, as long as the terms of this license are upheld, which basically just amounts to not telling others they can't do the same with anything you publish. (Giving credit in anything you produce, while not strictly necessary, would be nice)

Lending a hand is easy: just send a pull-request with explanations of what it addresses; if coding's not your thing, tell us what's not working the way it should and provide clear steps that describe how to reproduce the problem. As soon as we've had an opportunity to review your submission and make sure that it doesn't break anything, the code will be updated and you'll be credited.

All code is meticulously commented. If you find an under-documented section of code, please let us know.


---

# Project information #
## Development plans ##
For details on where the project is headed, check out the development feed at http://uguu.ca/tag/staticdhcpd/


---

# Feedback #
If staticDHCPd has helped you, please let us know. Conversely, if it exploded in your face and, after consulting the [FAQ](FAQ.md), you need help to get things working, also let us know.

Just don't contact Mathieu Ignacio with any complaints; he may have provided a crucial piece of this system, but he is not responsible for any mistakes we may have made.


---

# Credits #
[Neil Tallim](http://uguu.ca/)
  * Architecture and implementation
  
Mathieu Ignacio
  * [pydhcplib](http://pydhcplib.tuxfamily.org/pmwiki/)
  
Matthew Boedicker
  * Oracle support; sanity checking
  
Andrew Xuan
  * Lots of constructive feedback
  
John Stowers
  * Inspiration for making the database engine more flexible
  * Ideas for several features that helped to define what 2.0 should be
  
Aleksandr Chusov
  * Lots of 2.0.0 dev-branch testing: stepping on glass so nobody else had to
  
Ken Mitchell
  * Identification and testing of the broadcast bit, meaning that every client should now be supported
  
Anthony Woods
  * Suggestions that led to enabling site-specific metadata to be stored and easily accessed in databases ("definition.extra") and unifying Definition across the codebase


---

# Contacts #
neil {dot} tallim {at} linux {dot} com
