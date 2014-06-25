Practical recipies that everyone can use!
=========================================
While there's a lot of stuff that you can do with the
:doc:`../customisation/scripting` toolset, figuring out how to get started,
especially if you're not already familiar with Python, can be a bit
overwhelming. That's what this document is for: loaded with examples, it
serves as a crash-course for tweaking your environment to do special things
that will really help to make your life easier.

Pre-requisites
--------------
There are a few things that you will need to understand before diving into
these examples. Nothing difficult or long, but things that are essential
nonetheless.

*libpydhcpserver*
+++++++++++++++++
*staticDHCPd* unapologetically uses resources from *libpydhcpserver*. Reading
the examples section of its documentation, which is always distributed alongside
this one, should be considered necessary.

Python
++++++
staticDHCPd's configuration, ``conf.py``, is a living, breathing chunk of
`Python <http://python.org/>`_ source code. As such, when working with it,
Python coding conventions must be followed.

If anything mentioned here doesn't make sense, search the Internet for a
"hello, world!" Python script and do a bit of exploratory hacking.

Whitespace
||||||||||
Python is whitespace-sensitive. All this means, really, is that putting spaces
before every line you write is important and that the number of spaces must be
consistent. (And it's something you should do anyway, since indented code is
much easier to read)

When adding code to a scripting method, the standard convention is to indent it
with four spaces, like this::
    
    def loadDHCPPacket(...):
        packet.setOption('renewal_time_value', 60)
        if packet.isOption('router'):
            packet.setOption('domain_name', 'uguu.ca')
            logger.info("domain name set to 'uguu.ca'")
            
        #blank lines, like the one above, are optional; your code should be readable
        logger.info("processing done")
        return True

Strings
|||||||
A string is a sequence of bytes, usually text, like ``'hello'``. It may be
single- or double-quoted, and, if you need to put the same type of quotation
you used to start the string somewhere in the middle, it can be "escaped" by
prefixing it with a backslash:
``"Static assignments aren't really \"leases\"."``.

Numbers
|||||||
Integers, referred to as "ints", should be familiar, and "floating-point"
values, also known as "floats", are just numbers with a decimal component, like
``64.53``.

Conditionals
||||||||||||
You probably won't want logic to execute in all cases and that's what the ``if``
statement is for. Rather than trying to learn from an explanation, just read the
examples below and its use will become apparent quickly.

Comparators like ``>``, ``<=``, and ``!=`` should be pretty obvious, but you
will need to use ``==`` to test equality, since a single ``=`` is used for
assignment.

Comments
||||||||
Anything prefixed with a hash-mark (``#``) is a comment and will not be
processed.

Returns
|||||||
A ``return`` statement may be placed anywhere inside of a function. Its purpose
is to end execution and report a result.

The convention within *staticDHCPd* is to have ``return True`` indicate that
everything is good and processing should continue, while ``return False`` means
that the packet should be rejected. For your own sanity, when rejecting a
packet, you should log the reason why; this is covered in the examples below.

Environment
-----------
A number of convenience resources are present in the ``conf.py`` namespace by
default; these are enumerated here so you know what's provided out-of-the-box.

...

