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

Sequences
|||||||||
Lists, tuples, arrays, strings... Whatever they are, they are indexible, meaning
that you can access any individual element if you know its position. The only
real catch here is that everything starts at ``0``, not ``1``::
    
    x = [1, 2, 8, 'hello']
    x[0] #This is the value 1
    x[2] #This is the value 8

Evaluation
||||||||||
In Python, it is common to see things like the following::
    
    clients = some_function_that_returns_a_number_or_a_sequence()
    if not clients:
        #do something
        
When ``x`` is evaluated, it is asked if it holds a meaningful value and this
is used to determine whether it is equivalent to ``True`` or ``False`` for the
comparison. Numbers are ``False`` if equal to 0, sequences are ``False`` when
empty, and ``None`` is always ``False``. The ``not`` keyword is a more readable
variant of ``!``, meaning that ``True``/``False`` should be flipped.

Returns
|||||||
A ``return`` statement may be placed anywhere inside of a function. Its purpose
is to end execution and report a result.

The convention within *staticDHCPd* is to have ``return True`` indicate that
everything is good and processing should continue, while ``return False`` means
that the packet should be rejected. For your own sanity, when rejecting a
packet, you should log the reason why; this is covered in the examples below.

Examples
++++++++
This section will grow as new examples are created; if you let us know how to do
something cool or you ask a question and the result seems like a handy snippet,
it will probably show up here.

Gateway configuration
|||||||||||||||||||||
Tell all clients with an IP address ending in a multiple of 3 to use
192.168.1.254 as their default gateway::

    def loadDHCPPacket(...):
        #...
        if definition.ip[3] % 3 == 0:
            packet.setOption('router', '192.168.1.254')
        #...
        return True
        
Here, the modulus-by-3 of the last octet (zero-based array) of the IP address to
associate with the client is checked to see if it is zero. If so, the "router"
option (DHCP option 3) is set to 192.168.1.254

Prevent clients in all "192.168.0.0/24" subnets from having a default gateway::
    
    def loadDHCPPacket(...):
        #...
        if definition.subnet == '192.168.0.0/24':
            packet.deleteOption('router')
        #...
        return True

"subnet", which is the database's "subnet" field, not that of the client's
IP/netmask, is checked to see if it matches. If so, then the "router" option is
discarded.

Override renewal times
||||||||||||||||||||||
Set T1 to 60 seconds::
    
    def loadDHCPPacket(...):
        #...
        packet.setOption('renewal_time_value', 60)
        #...
        return True
        
Adjust domain names
|||||||||||||||||||
Set the client's domain name to "example.com" if the request was relayed, but
refuse to respond if it was relayed from 10.0.0.1::
    
    def loadDHCPPacket(...):
        #...
        if relay_ip: #The request was relayed
            if relay_ip == "10.0.0.1":
                return False #Abort processing
            packet.setOption('domain_name', 'example.com')
        #...
        return True

Here, ``relay_ip`` (DHCP field "giaddr"), is checked to see if it was set,
indicating that this request was relayed. The IP of the relay server is then
compared and, if it matches, "domain_name" is set to "example.com".

Working with option 82
||||||||||||||||||||||
Refuse relays without "relay_agent" (DHCP option 82)'s agent-ID set to
[1, 2, 3]::
    
    def loadDHCPPacket(...):
        #...
        if relay_ip: #The request was relayed
            relay_agent = packet.getOption('relay_agent')
            if relay_agent and not rfc3046_decode(relay_agent)[1] == [1, 2, 3]:
                return False
        #...
        return True

This allows any non-relayed requests to pass through. Any relayed requests
missing option 82 will be allowed (more on this below); any instances of option
82 with an invalid agent-ID (sub-option 1) will be ignored. Any instances of
option 82 missing sub-option 1 will generate an error (described in the next
example).

Even relay agents configured to set option 82 will omit it if the resulting DHCP
packet would be too large. For this reason, it's important to limit the relay
IPs allowed in the config settings.

Managing errors
|||||||||||||||
Do something to generate an error for testing purposes::
    
    def loadDHCPPacket(...):
        #...
        if not packet.setOption('router', [192])):
            raise Exception("192 is not a valid IP")
        #...
        return True
        
The reason why this fails should be obvious, though it is worth noting that
``setOption()`` returns ``False`` on failure, rather than raising an exception
of its own. This was done because it seemed easier for scripting novices to
work with while *staticDHCPd* was still in its infancy.

What's important here is that raising any sort of exception in
``loadDHCPPacket()`` prevents the DHCP response from being sent, but it will
help to debug problems by printing or e-mailing a thorough description of the
exception that occurred.
