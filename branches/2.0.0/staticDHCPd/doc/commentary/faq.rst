Frequesntly asked questions and feature notes
=============================================
What platforms are supported?
-----------------------------
Almost anything POSIX-compliant should work as a server, which includes Linux,
the BSD family, and OS X. DHCP is a protocol, so it will serve Windows, your
smartphone, and your Vita just fine.

All core development is done in `Debian <http://debian.org/>`_ and
`Ubuntu <http://ubuntu.com/>`_ environments.

It *should* be possible to run *staticDHCPd* on Windows, but it will require
some significant rework of the sockets layer, particularly with raw L2 access,
and nobody central to the project has the skills, time, or resources for it. If
you make it work, please do not submit a patch unless you are also willing to
maintain Windows support indefinitely.

Can I do dynamic provisioning?
------------------------------
Support for limited, non-spec-compliant dynamic provisioning is provided through
the :ref:`dynamism extension module <setups-dynamic>`. It works pretty well for
most cases.

Can I connect to a non-standard database, like a webservice?
------------------------------------------------------------
Absolutely.

You can define your own database engine, as long as it implements
*staticDHCPd*'s database interface, then reference it in ``conf.py``, with no
need to carry patches against the core codebase.

An example is provided as the `httpdb`
:doc:`extension module <../customisation/extensions>`.

I want to change the order of elements in the dashboard
-------------------------------------------------------
And you should want to do this. Customisation is good.

Every dashboard element has an ordering-bias value; those with smaller values
appear first. If you have logging at a debug level, you'll see this information
printed when each one gets registered; every built-in element is
:doc:`configurable <../customisation/configuration>` via ``conf.py``, and you
can set your own bias values in any modules you write.

I want to use my own CSS/JS/favicon for the web interface
---------------------------------------------------------
Sure, that's not a problem at all.

You can inject your own lines into ``<head/>`` by using a tiny bit of code in
:ref:`scripting-init`::

    def init():
        #...
        def myHeaders(path, queryargs, mimetype, data, headers):
            return "<!-- anything you want to see appear in the <head/> section, as a valid XHTML fragment -->"
            
        callbacks.webAddHeader(myHeaders)
        #...
        
You can use lambdas, too, if that's your thing. However you do it, this will add
another block to the ``<head/>`` section, so you can add a link to your own
stylesheet or just embed code directly. As with the other
:ref:`web-callbacks <scripting-callbacks>`, the standard set of parameters are
passed to your function, so you can do different things depending on what was
requested or what was received via `POST`; you just have to return a string or
``None``, which suppresses output.

Anything you add, like a CSS class or JavaScript function, should be prefixed
with a leading underscore, where possible, to avoid potential future conflicts
with *staticDHCPd*'s core code.

If you want to replace the CSS or favicon completely, you'll find their
definitions in :mod:`web.resources` and handlers in :mod:`web.methods`.
Just implement your own equivalent method, then, in :ref:`scripting-init`, do
something similar to the following::

    callbacks.webRemoveMethod('/css') #Get rid of the old one
    callbacks.webAddMethod('/css', _YOUR_METHOD_HERE_, cacheable=True)

Replacing the favicon is pretty much identical. Replacing the JavaScript is
discouraged, but also roughly the same; extend that, rather than replace it.

Platform-specific questions
---------------------------
On Ubuntu, I get these ``non-fatal select() error`` messages in my logs at
startup. Why?

Actually, we're not quite sure why, either. It seems as though Ubuntu's default
configuration hits the process, when it starts, with a signal that generates an
interrupt, which wakes the ``select()`` operations prematurely and causes them
to throw an error because no handlers were invoked. No handlers were invoked
because the nature of the interrupt is unknown, so to ensure normal operation,
the error is semi-silently discarded and ``select()`` is invoked again, which is
what would normally happen after each wakeup event. No requests can possibly be
lost as a result of this error, so it's completely benign.

That said, if you see this message appear after the initial startup, then you
should start investigating the cause.

Further information:

    This is actually more of a Python issue than an Ubuntu issue (it would have
    been fixed if it were reasonably easy): Python's ``select()`` receives
    ``SIGINT``, as it should, but there's no clear way to actually handle the
    signal gracefully -- although handling it properly would require knowledge
    of why it's actually being sent.

Release errata
--------------
:rfc:`4388`: "LEASEQUERY"
+++++++++++++++++++++++++
The featureset described by this RFC is untested, yet was included in versions
1.4.0+, before removal in 1.6.3, because its implementation was wrong. It will
return if there is demand, but better to leave out bad code than try to hack it
into a semi-working state.

Unsupported features
--------------------
:rfc:`3011`: Subnet selection
+++++++++++++++++++++++++++++
This feature is not required in a purely static environment.

:rfc:`3004`: User class
+++++++++++++++++++++++
*staticDHCPd* requires that each client be known ahead of time, precluding any
need for the notion of dynamic assignment from pools based on clases.

:rfc:`3118`: DHCP Authentication
++++++++++++++++++++++++++++++++
This feature is not supported because of the large number of clients that ignore
the option.

It is also unnecessary in any environment in which *staticDHCPd* should be used:
if administrators do not have absolute control of their network, *staticDHCPd*
is not the right choice.

:rfc:`3203`: "FORCERENEW"
+++++++++++++++++++++++++
This feature explicitly depends on :rfc:`3118`.

It also poses problems related to authority and shouldn't be necessary in an
all-static environment. It will be implemented if anyone makes a solid case for
its inclusion, though.
