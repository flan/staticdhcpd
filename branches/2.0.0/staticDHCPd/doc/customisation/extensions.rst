Working with extension modules
==============================
All included extension modules provide specific usage instructions in their
header sections.

However, because including common information in each one would be redundant,
the general flow of installing one is the following:

# Ensure that there exists an ``extensions/`` subdirectory in the same
  directory as ``conf.py``
# Copy the extension-file into ``extensions/``
# Follow its instructions to install hooks in ``conf.py``
# (re)Start *staticDHCPd*

Configuring modules
-------------------
*A univsersal means of centralising extension-module configuration is being
considered for inclusion in RC1; for now, all modules are self-contained*

*What will probably be implemented will be a namespace within ``conf.py``, not
unlike ``callbacks``, called ``extensions``, from which modules will pull
settings-updates on-load*

Developing your own module
--------------------------
The best way to start is by studying the provided modules. They range from
simple to fairly complex, but all of them are practical.

Simple -> Complex:

* `recent_activity`

  * Simple, self-installing web-interface dashboard element that shows
    the last several DHCP events.
    
* `httpdb`

  * Basic REST/JSON-based database interface.
  
* `feedservice`

  * Self-installing ATOM-feed interface to the logging system, using
    web-methods to extend the webserver.

* `statistics`

  * Self-installing web-interface dashboard elements that display DHCP activity
    and, if necessary packages are available, an activity graph.
    
* `dynamism`

  * Robust dynamic DHCP facilities that can enhance or completely supplant
    static behaviour.

No matter what you want to build, though, understanding how it will interact
with *staticDHCPd* is crucial. You will almost certainly be making use of
:ref:`callbacks <scripting-callbacks>`, and some combination of the
:ref:`scripting-init`, :ref:`scripting-filterPacket`,
:ref:`scripting-handleUnknownMAC`, and :ref:`scripting-loadDHCPPacket`
functions.
