:tocdepth: 3

Configuration guide
===================
A single config file is the only thing you need to modify in order to have
almost full control over your DHCP server's behaviour.

The file is intended to be largely forwards-compatible, meaning that, when a new
version of *staticDHCPd* is released, you shouldn't have to change anything: the
new engine will massage and inject data as needed to make sure that gaps in your
configuration will be filled with sane defaults, and that old scripting logic
will still work. (Within reason, of course; always check the changelog)

The default file is very minimal in nature. To extend it, simply place the
parameters, described below, that you want to modify into that file and restart
your server.

``conf.py``
-----------
conf.py is, as you may have surmised, a real Python file. It is executed by the
interpreter before *staticDHCPd* is fully online and you can do, with it,
everything that you'd normally expect a Python script to do, including importing
other modules. More information on that is provided in the
:doc:`scripting guide <./scripting>` -- the important thing to note for basic
configurations is that you need to conform to Python syntax when specifying
values:

* ``None``, written capitalised and without quotation, indicates that a value is
  explicitly null.
* Text values must be strings, "like this" or 'like this', with quotation marks.
* Numbers are written naturally, like 6 or 7.32.
* Boolean values are written as ``True`` or ``False``, capitalised, without
  quotation. ``1`` and ``0`` are NOT suitable substitutes.
* Lists are written like ``[1, 2, 'hello']``, and may contain mixed data-types.
* Concatenations of strings may be done using the + operator::
    
    'hello' + 'goodbye' # = 'hellogoodbye'
    #Non-string data, like numbers, must be converted
    'hello' + str(5) # = 'hello5'
    
* Any value defined in the file may be referenced on any later line, like this::
    
    _HELLO = 'hello'
    GREETING = _HELLO + 'goodbye'
    
* Everything is case-sensitive.
 
You may define non-config-parameter values in this file, but it would be a good
idea to prefix their names with an underscore, to avoid potential conflicts with
future upstream changes.

Parameters
----------
The various settings that may be defined within ``conf.py``. These should always
be specified before any custom code you might add, like functions.

General
+++++++
**DEBUG** : boolean : default=False
|||||||||||||||||||||||||||||||||||
* Adds additional information to everything that gets logged
* Does not modify the logging severity levels of individual loggers

**SYSTEM_NAME** : text : default='staticDHCPd'
||||||||||||||||||||||||||||||||||||||||||||||
* The name the system will use to self-identify

**DAEMON** : boolean : default=True
|||||||||||||||||||||||||||||||||||
* Causes the server to daemonise during startup
* Not a good thing to have enabled when doing initial setup because you lose ^C
  and console logs

**PID_FILE** : text, None : default=None
||||||||||||||||||||||||||||||||||||||||
* The path to which a pidfile should be written
* ``'/var/run/staticDHCPd.pid'`` is a good choice

Server
++++++
**UID** : integer : **MUST BE SPECIFIED**
|||||||||||||||||||||||||||||||||||||||||
* The UID under which the server will run, after everything is bound
* This should normally be your system's "nobody"

**GID** : integer : **MUST BE SPECIFIED**
|||||||||||||||||||||||||||||||||||||||||
* The GID under which the server will run, after everything is bound
* This should normally be your system's "nobody"

**DHCP_SERVER_IP** : text : **MUST BE SPECIFIED**
|||||||||||||||||||||||||||||||||||||||||||||||||
* The IP of the interface to use for DHCP traffic
* This value must be a specific IP address: ``'0.0.0.0'`` is invalid

**DHCP_RESPONSE_INTERFACE** : text : default=None
|||||||||||||||||||||||||||||||||||||||||||||||||
* The value is the lexical name of the interface from which responses
  should be sent, like ``'eth0'``
* If set, response-packets will be crafted from layer 2, allowing for unicast
  OFFERs in response to DISCOVERs, if the client set the broadcast bit
* For most environments, this will not be required, but if other DHCP servers,
  like the *ISC*'s, work and *staticDHCPd* does not, this is probably why

**DHCP_RESPONSE_INTERFACE_QTAGS** : list : default=None
|||||||||||||||||||||||||||||||||||||||||||||||||||||||
* If **DHCP_RESPONSE_INTERFACE** is set and qtags are required on that
  interface, they may be supplied in order of appearance (head to tail) as TCI
  blocks
* Format::

    (Priority Control Point (0-7),
     Drop Eligible Indicator (True/False),
     VLAN Identifier (1-4094),)

* Example: ``[(3, True, 42), (1, False, 77)]`` -> VLAN 42 with nested VLAN 77

**DHCP_SERVER_PORT** : integer : default=67
|||||||||||||||||||||||||||||||||||||||||||
* The port on which to listen for DHCP queries

**DHCP_CLIENT_PORT** : integer : default=68
|||||||||||||||||||||||||||||||||||||||||||
* The port on which to respond to DHCP clients

**PXE_PORT** : integer, None : default=None
|||||||||||||||||||||||||||||||||||||||||||
* The port to use for PXE-processing, if required; PXE is disabled if not set
* PXE normally runs on ``4011``

Database
++++++++
**DATABASE_ENGINE** : text, None : **MUST BE SPECIFIED**
||||||||||||||||||||||||||||||||||||||||||||||||||||||||
* The database-engine to use for handling static lease data

  * One of ``None``, ``'SQLite'``, ``'PostgreSQL'``, ``'Oracle'``, ``'MySQL'``,
    ``'INI'``
  
* Only parameters related to the chosen database engine need to be supplied
* You may alternatively supply a callable that provides an instance of
  :class:`databases.generic.Database`, if you want to implement your own engine
  without messing with core code
  
  * The callable must require no arguments
  * To keep ``conf.py`` clean, define your engine in a separate module, like
    ``extensions/_mydb.py`` and import it just before **DATABASE_ENGINE** is
    set, referencing a callable declared therein
  * If you need to configure it differently for each server, declare a lambda
    or short function in ``conf.py`` and make changes to that as needed
  * It is sane to inherit from subclasses like
    :class:`databases.generic.CachingDatabase`; it is probably safe to inherit
    from the :class:`databases._sql._SQLDatabase` family, too, but its internal
    implementation is technically private
  * If you need to tie into :ref:`callbacks <scripting-callbacks>`, like
    reinitialisation, you should do this as part of the callable's logic; the
    ``callbacks`` object is not available at the time that ``conf.py`` is first
    processed, but it is available while the callable is executed
    
    * Alternatively, you can create the object at the ``conf.py`` level, write a
      simple ``lambda : _MY_INSTANTIATED_DATABASE_OBJECT`` as the callable, and
      operate on ``_MY_INSTANTIATED_DATABASE_OBJECT`` in ``init()``, for
      consistency
    * Note: the database object's ``reinitialise()`` method is automatically
      registered, so you only need to tie into callbacks if you need behaviour
      that cannot be captured there
      
Database:None
|||||||||||||
No parameters to set. This database is only useful if you are exclusively using
``handleUnknownMAC()``, described in the :doc:`scripting guide <./scripting>`,
to provision addresses.

Database:SQLite
|||||||||||||||
**CASE_INSENSITIVE_MACS** : boolean : default=False
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Forces case-insensitive comparisons for MACs
* If this matters to you, you should create a NOCASE index over `maps:mac`
  instead, for greater efficiency

**USE_CACHE** : boolean : default=False
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Causes data retrieved from the database to be stored in memory until the
  cache is flushed via reinitialisation
* For SQLite, this should normally be ``False``

**CACHE_ON_DISK** : boolean : default=False
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Causes the local cache to be managed as a local file, rather than a purely
  in-memory construct
  
  * Most kernels will keep the file in memory if accessed frequently, but
    its data-compaction is a little bit tighter, and the cache should reach
    its final state quickly, so reclaiming memory is swap-free
  * This file will be temporary, unless **PERSISTENT_CACHE** is set; in that case,
    the file will be the same
    
* For SQLite, this should normally be ``False``

**PERSISTENT_CACHE** : text : default=None
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Causes the cache to be written to a local database file, which will be used
  when *staticDHCPd* is restarted, to provide durability against unstable
  databases
* The value of this option is the path to the file;
  ``'/var/tmp/staticDHCPd.db'`` is usually a good choice
* If **CACHE_ON_DISK** is set, this file will be used; if not, the contents of
  this file will be read into memory
* For SQLite, this should normally be ``False``

**EXTRA_MAPS** : list : default=None
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Any non-standard fields to read from the `maps` table, which will be
  provided in ``definition.extra``, keyed as `maps.$COLUMN`

**EXTRA_SUBNETS** : list : default=None
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Any non-standard fields to read from the `subnets` table, which will be
  provided in ``definition.extra``, keyed as `subnets.$COLUMN`

**SQLITE_FILE** : text : *MUST BE SPECIFIED if using SQLite*
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* The path to the file that contains your SQLite database

Database:PostgreSQL
|||||||||||||||||||
**CASE_INSENSITIVE_MACS** : boolean : default=False
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Forces case-insensitive comparisons for MACs
* If this matters to you, you should create a lower() index over `maps:mac`
  instead, for greater efficiency

**USE_CACHE** : boolean : default=False
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Causes data retrieved from the database to be stored in memory until the
  cache is flushed via reinitialisation
* Can greatly improve performance in stable, high-load environments

**CACHE_ON_DISK** : boolean : default=False
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Causes the local cache to be managed as a local file, rather than a purely
  in-memory construct
  
  * Most kernels will keep the file in memory if accessed frequently, but
    its data-compaction is a little bit tighter, and the cache should reach
    its final state quickly, so reclaiming memory is swap-free
  * This file will be temporary, unless **PERSISTENT_CACHE** is set; in that
    case, the file will be the same

**PERSISTENT_CACHE** : text : default=None
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Causes the cache to be written to a local database file, which will be used
  when *staticDHCPd* is restarted, to provide durability against unstable
  databases
* The value of this option is the path to the file;
  ``'/var/tmp/staticDHCPd.db'`` is usually a good choice
* If **CACHE_ON_DISK** is set, this file will be used; if not, the contents of
  this file will be read into memory

**EXTRA_MAPS** : list : default=None
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Any non-standard fields to read from the `maps` table, which will be
  provided in ``definition.extra``, keyed as `maps.$COLUMN`

**EXTRA_SUBNETS** : list : default=None
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Any non-standard fields to read from the `subnets` table, which will be
  provided in ``definition.extra``, keyed as `subnets.$COLUMN`

**USE_POOL** : boolean : default=True
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Causes database connections to pull from a pool by default, reducing
  connection overhead considerably
* Requires that the *eventlet* library is installed; will fall back to direct
  connections if it's not available

**POSTGRESQL_DATABASE** : text : *MUST BE SPECIFIED if using PostgreSQL*
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* The name of your database

**POSTGRESQL_USERNAME** : text : *MUST BE SPECIFIED if using PostgreSQL*
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* The name of a user with SELECT permissions

**POSTGRESQL_PASSWORD** : text : *MUST BE SPECIFIED if using PostgreSQL*
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* The user's password

**POSTGRESQL_HOST** : text, None : default=None
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* The host on which PostgreSQL is running
* If ``None``, a local socket will be used

**POSTGRESQL_PORT** : integer : default=5432
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* The port on which PostgreSQL is running
* If **POSTGRESQL_HOST** is ``None``, a local socket will be used and this value
  will be ignored

**POSTGRESQL_SSLMODE** : text : default='disable'
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* The `SSL mode <http://www.postgresql.org/docs/9.0/static/libpq-ssl.html#LIBPQ-SSL-SSLMODE-STATEMENTS>`_
  to use
* Ignored in local socket situations
 
**POSTGRESQL_MAXIMUM_CONNECTIONS** : integer : default=4
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* The maximum number of threads that may connect to the database at once

Database:Oracle
|||||||||||||||
**CASE_INSENSITIVE_MACS** : boolean : default=False
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Forces case-insensitive comparisons for MACs
* If this matters to you, you should create a lower() index over `maps:mac`
  instead, for greater efficiency

**USE_CACHE** : boolean : default=False
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Causes data retrieved from the database to be stored in memory until the
  cache is flushed via reinitialisation
* Can greatly improve performance in stable, high-load environments

**CACHE_ON_DISK** : boolean : default=False
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Causes the local cache to be managed as a local file, rather than a purely
  in-memory construct
  
  * Most kernels will keep the file in memory if accessed frequently, but
    its data-compaction is a little bit tighter, and the cache should reach
    its final state quickly, so reclaiming memory is swap-free
  * This file will be temporary, unless **PERSISTENT_CACHE** is set; in that
    case, the file will be the same

**PERSISTENT_CACHE** : text : default=None
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Causes the cache to be written to a local database file, which will be used
  when *staticDHCPd* is restarted, to provide durability against unstable
  databases
* The value of this option is the path to the file;
  ``'/var/tmp/staticDHCPd.db'`` is usually a good choice
* If **CACHE_ON_DISK** is set, this file will be used; if not, the contents of
  this file will be read into memory

**EXTRA_MAPS** : list : default=None
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Any non-standard fields to read from the `maps` table, which will be
  provided in ``definition.extra``, keyed as `maps.$COLUMN`

**EXTRA_SUBNETS** : list : default=None
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Any non-standard fields to read from the `subnets` table, which will be
  provided in ``definition.extra``, keyed as `subnets.$COLUMN`

**USE_POOL** : boolean : default=True
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Causes database connections to pull from a pool by default, reducing
  connection overhead considerably
* Requires that the *eventlet* library is installed; will fall back to direct
  connections if it's not available

**ORACLE_DATABASE** : text : *MUST BE SUPPLIED if using Oracle*
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* The name of your database (from `tnsnames.ora`)

**ORACLE_USERNAME** : text : *MUST BE SUPPLIED if using Oracle*
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* The name of a user with SELECT permissions

**ORACLE_PASSWORD** : text : *MUST BE SUPPLIED if using Oracle*
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* The user's password

**ORACLE_MAXIMUM_CONNECTIONS** : integer : default=4
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* The maximum number of threads that may connect to the database at once

Database:MySQL
||||||||||||||
**CASE_INSENSITIVE_MACS** : boolean : default=False
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Forces case-insensitive comparisons for MACs
* MySQL is normally case-insensitive, so this isn't likely to be helpful

**USE_CACHE** : boolean : default=False
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Causes data retrieved from the database to be stored in memory until the
  cache is flushed via reinitialisation
* Can greatly improve performance in stable, high-load environments

**CACHE_ON_DISK** : boolean : default=False
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Causes the local cache to be managed as a local file, rather than a purely
  in-memory construct
  
  * Most kernels will keep the file in memory if accessed frequently, but
    its data-compaction is a little bit tighter, and the cache should reach
    its final state quickly, so reclaiming memory is swap-free
  * This file will be temporary, unless **PERSISTENT_CACHE** is set; in that
    case, the file will be the same

**PERSISTENT_CACHE** : text : default=None
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Causes the cache to be written to a local database file, which will be used
  when *staticDHCPd* is restarted, to provide durability against unstable
  databases
* The value of this option is the path to the file;
  ``'/var/tmp/staticDHCPd.db'`` is usually a good idea
* If **CACHE_ON_DISK** is set, this file will be used; if not, the contents of
  this file will be read into memory

**EXTRA_MAPS** : list : default=None
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Any non-standard fields to read from the `maps` table, which will be
  provided in ``definition.extra``, keyed as `maps.$COLUMN`

**EXTRA_SUBNETS** : list : default=None
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Any non-standard fields to read from the `subnets` table, which will be
  provided in ``definition.extra``, keyed as `subnets.$COLUMN`

**USE_POOL** : boolean : default=True
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* Causes database connections to pull from a pool by default, reducing
  connection overhead considerably
* Requires that the *eventlet* library is installed; will fall back to direct
  connections if it's not available

**MYSQL_DATABASE** : text : *MUST BE SPECIFIED if using MySQL*
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* The name of your database

**MYSQL_USERNAME** : text : *MUST BE SPECIFIED if using MySQL*
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* The name of a user with SELECT permissions

**MYSQL_PASSWORD** : text : *MUST BE SPECIFIED if using MySQL*
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* The user's password

**MYSQL_HOST** : text, None : default=None
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* The host on which MySQL is running
* If ``None``, a local socket will be used

**MYSQL_PORT** : integer : default=3306
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* The port on which MySQL is running
* If **MYSQL_HOST** is ``None``, a local socket will be used and this value will
  be ignored

**MYSQL_MAXIMUM_CONNECTIONS** : integer : default=4
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* The maximum number of threads that may connect to the database at once

Database:INI
||||||||||||
Any additional options in subnets or maps will be exposed through
``definition.extra``.

**INI_FILE** : text : *MUST BE SPECIFIED if using INI*
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
* The path to the file that contains your INI database

Server behaviour
++++++++++++++++
**ALLOW_LOCAL_DHCP** : boolean : default=True
|||||||||||||||||||||||||||||||||||||||||||||
* Whether link-local DHCP requests will be handled

**ALLOW_DHCP_RELAYS** : boolean : default=False
|||||||||||||||||||||||||||||||||||||||||||||||
* Whether relayed DHCP requests will be handled

**ALLOWED_DHCP_RELAYS** : list : default=[]
|||||||||||||||||||||||||||||||||||||||||||
* If relayed requests are allowed, providing a list of IPs, like
  ``['192.168.1.1', '192.168.2.1']``, will limit which ones will be accepted
* If empty, all relays are considered acceptable

**AUTHORITATIVE** : boolean : default=False
|||||||||||||||||||||||||||||||||||||||||||
* Controls whether unknown MACs should be NAKed instead of ignored
* If you are likely to run multiple DHCP servers that do not share the same
  lease-status information, this should be False, or else clients will
  experience intermittent stability issues, as one server contradicts the other
  instead of staying silent

**NAK_RENEWALS** : boolean : default=False
||||||||||||||||||||||||||||||||||||||||||
* Whether `REBIND` and `RENEW` requests should be NAKed when received, forcing
  clients to either wait out their lease or return to the `DISCOVER` phase
* This is good if you expect that you will be changing your configuration
  in the near future

**UNAUTHORIZED_CLIENT_TIMEOUT** : integer : default=60
||||||||||||||||||||||||||||||||||||||||||||||||||||||
* The number of seconds for which unknown MACs should be ignored, to avoid
  wasting processing resources unnecessarily

**MISBEHAVING_CLIENT_TIMEOUT** : integer : default=150
||||||||||||||||||||||||||||||||||||||||||||||||||||||
* The number of seconds for which MACs that are sending invalid requests should
  be ignored; with dynamic servers, these could be trying to trigger a DoS
  scenario, so there's no point in wasting resources on them

**ENABLE_SUSPEND** : boolean : default=True
|||||||||||||||||||||||||||||||||||||||||||
* Whether MACs that are flooding the server will be considered as misbehaving

**SUSPEND_THRESHOLD** : integer : default=10
||||||||||||||||||||||||||||||||||||||||||||
* The number of times a well-behaved MAC can interact with the server before
  being being considered as misbehaving
* The number of interactions in memory is reduced by one per second

Logging
+++++++
**LOG_FILE** : text, None : default=None
||||||||||||||||||||||||||||||||||||||||
* The path to which logs should be written
* The specified file must be writeable if it already exists, or containing
  directory must allow file-creation
* ``'/var/log/staticDHCPd/staticDHCPd.log'`` is a good choice, but you must
  create the directory and set appropriate permissions first

**LOG_FILE_HISTORY** : integer, None : default=7
||||||||||||||||||||||||||||||||||||||||||||||||
* If logging to a file, this will cause logs to rotate once per day, with
  retention up to the specified number of days
* If `None`, which is not recommended, the specified file will grow indefinitely

**LOG_FILE_SEVERITY** : text : default='WARN'
|||||||||||||||||||||||||||||||||||||||||||||
* Controls how much information appears in the log-file: only events at least
  this important
* One of ``'DEBUG'``, ``'INFO'``, ``'WARN'``, ``'ERROR'``, ``'CRITICAL'``

**LOG_CONSOLE_SEVERITY** : text : default='INFO'
||||||||||||||||||||||||||||||||||||||||||||||||
* Controls how much information appears in the console: only events at least
  this important
* Console-based logging is disabled when running as a daemon
* One of ``'DEBUG'``, ``'INFO'``, ``'WARN'``, ``'ERROR'``, ``'CRITICAL'``

Webservice
++++++++++
**WEB_ENABLED** : boolean : default=True
||||||||||||||||||||||||||||||||||||||||
* Whether the webservice engine should be enabled

**WEB_IP** : text : default='0.0.0.0'
|||||||||||||||||||||||||||||||||||||
* The IP on which HTTP traffic should be served
* By default, this will listen on all interfaces; to restrict it, provide a
  specific IP

**WEB_PORT** : integer : default=30880
||||||||||||||||||||||||||||||||||||||
* The port on which HTTP traffic should be served

**WEB_LOG_HISTORY** : integer : default=200
|||||||||||||||||||||||||||||||||||||||||||
* The number of events to present in the dashboard's log
* If ``0``, no log will be present in the dashboard

**WEB_LOG_SEVERITY** : text : default='INFO'
||||||||||||||||||||||||||||||||||||||||||||
* Controls how much information appears in the dashboard: only events at least
  this important
* One of ``'DEBUG'``, ``'INFO'``, ``'WARN'``, ``'ERROR'``, ``'CRITICAL'``

**WEB_LOG_MAX_HEIGHT** : integer, None : default=400
||||||||||||||||||||||||||||||||||||||||||||||||||||
* The maximum height, in pixels, of the web-log, before it scrolls
* A value of ``None`` disables this restriction

**WEB_DIGEST_USERNAME** : text, None : default=None
|||||||||||||||||||||||||||||||||||||||||||||||||||
* The username to use for DIGEST-based authentication
* If ``None``, authentication is disabled

**WEB_DIGEST_PASSWORD** : text, None : default=None
|||||||||||||||||||||||||||||||||||||||||||||||||||
* The password to use for DIGEST-based authentication
* If ``None``, authentication is disabled

**WEB_DASHBOARD_SECURE** : boolean : default=False
||||||||||||||||||||||||||||||||||||||||||||||||||
* Whether authentication is needed to access the dashboard

**WEB_REINITIALISE_CONFIRM** : boolean : default=True
|||||||||||||||||||||||||||||||||||||||||||||||||||||
* Whether confirmation is required to reinitialise the server

**WEB_REINITIALISE_SECURE** : boolean : default=False
|||||||||||||||||||||||||||||||||||||||||||||||||||||
* Whether authentication is requires to reinitialise the server

**WEB_REINITIALISE_HIDDEN** : boolean : default=False
|||||||||||||||||||||||||||||||||||||||||||||||||||||
* Whether the reinitilise element should be hidden

**WEB_REINITIALISE_ENABLED** : boolean : default=True
|||||||||||||||||||||||||||||||||||||||||||||||||||||
* Whether the reinitilise option should be available at all

**WEB_DASHBOARD_ORDER_LOG** : integer : default=1000
||||||||||||||||||||||||||||||||||||||||||||||||||||
* Sets the ordering bias of the log in the web-dashboard

**WEB_HEADER_TITLE** : boolean : default=True
|||||||||||||||||||||||||||||||||||||||||||||
* Whether the default title should be included in the web interface
* This is the same as the value you supplied for **SYSTEM_NAME**

**WEB_HEADER_CSS** : boolean : default=True
|||||||||||||||||||||||||||||||||||||||||||
* Whether the defualt CSS should be included in the web interface

**WEB_HEADER_FAVICON** : boolean : default=True
|||||||||||||||||||||||||||||||||||||||||||||||
* Whether the defualt favicon should be included in the web interface

E-mail
++++++
**EMAIL_ENABLED** : boolean : False
|||||||||||||||||||||||||||||||||||
* Whether e-mail notification of `CRITICAL`-severity events should occur
* These issues usually reflect very unusual conditions in your network, and
  are therefore generally very helpful

**EMAIL_SERVER** : text : *MUST BE SPECIFIED if using e-mail*
|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
* Your SMTP server's address

**EMAIL_PORT** : integer : default=25
|||||||||||||||||||||||||||||||||||||
* The SMTP port your server uses

**EMAIL_SOURCE** : text : *MUST BE SPECIFIED if using e-mail*
|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
* The address to put in the `FROM` field

**EMAIL_DESTINATION** : text : *MUST BE SPECIFIED if using e-mail*
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
* The address to put in the `TO` field

**EMAIL_SUBJECT** : text : default='staticDHCPd encountered a problem'
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
* The subject-line to use for e-mail issues
* ``"staticDHCPd running on " + DHCP_SERVER_IP + " encountered a problem"``
  might be a better choice for a larger environment

**EMAIL_USER** : text, None : default=None
||||||||||||||||||||||||||||||||||||||||||
* The username to use in authentication to the server
* If ``None``, authentication is not performed

**EMAIL_PASSWORD** : text : *MUST BE SPECIFIED if using e-mail and EMAIL_USER is set*
|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
* The password to use in authentication to the server
