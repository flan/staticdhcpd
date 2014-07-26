Working with extension modules
==============================
All included extension modules provide specific usage instructions in their
header sections.

However, because including common information in each one would be redundant,
the general flow of installing one is the following:

#. Ensure that there exists an ``extensions/`` subdirectory in the same
   directory as ``conf.py``
#. Copy or link the extension-file into ``extensions/``
#. Follow its instructions to install hooks in ``conf.py``
#. (re)Start *staticDHCPd*

Configuring modules
-------------------
Since your module is independent code that you explicitly hook into
*staticDHCPd*, and can therefore run independently, you are free to configure
it any way you would like; if you are its sole consumer, constants defined
in-file are likely the simplest method and more than good enough.

Supplying configuration through `conf.py`
+++++++++++++++++++++++++++++++++++++++++
While it is entirely possible to contain all extension configuration within the
module itself, if you plan to share, it is convenient for users to define
values in ``conf.py``.

To make use of this facility, all you need to do is instruct your users to add
lines like the following in :ref:`scripting-init`::

    extensions.your_module.REFRESH_INTERVAL = 5
    extensions.your_module.SOME_DICT = {
        1: 2,
        'a': 'c',
    }

Or like this, so that it's clear, at a glance, where your module's parameters
are set, by encouraging uniform indentation::

    with extensions.your_module as x:
        x.TIMEOUT = 0.25

If, however, you are working with a module for which loading in
:ref:`scripting-init` is too late, the convention to avoid conflicting with
future *staticDHCPd* built-in variables is to use ``X_YOURMODULE_VARIABLE``::
    
    X_HTTPDB_URI = 'http://example.org/dhcp'

Accessing configuration data
++++++++++++++++++++++++++++
Within your module, you then have a few ways of accessing this data. They'll
basically all start with importing the ``extensions`` namespace::

    import staticdhcpdlib.config
    _config = staticdhcpdlib.config.conf.extensions.your_module

You can then extract data from ``_config`` as needed; you'll probably want to
use one of the parsing methods it exposes to create a dictionary to avoid
testing to see if every value is set or not, but how to use it is entirely up
to you.

.. automethod:: config._Namespace.extension_config_merge

.. automethod:: config._Namespace.extension_config_dict

.. automethod:: config._Namespace.extension_config_iter

For performance reasons, it may be a good idea to assign the namespace's
data during module setup, then discard it and any intermediate structures,
like dictionaries compiled using these methods::

    del _config #Removes the reference and lets staticDHCPd reclaim resources
    del YOUR_CONFIG_DICTIONARY #Allows for normal Python garbage-collection

Of course, if keeping a dictionary or the namespace around is how you want to
access information, that's perfectly valid and the structures are pretty
efficient by themselves.

In the early-bind case, the following will work, and you may streamline the code
as you see fit::
    
    import staticdhcpdlib.config
    if hasattr(staticdhcpdlib.config, 'X_HTTPDB_URI'):
        URI = staticdhcpdlib.config.X_HTTPDB_URI
    else:
        URI = 'http://default/value'
        

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
