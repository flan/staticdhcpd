

Working with extension modules
------------------------------
The examples below will show you how to enable dynamic provisioning using the
included `dynamism` module. To make these examples work, copy
``extensions/official/dynamism.py`` to the ``extensions/`` subdirectory.

Using `dynamism` as an example, you should be able to write extension modules of
your own.




Example
------------------------------
def init():
    import dynamism
    global _dynamic_pool
    _dynamic_pool = dynamism.DynamicPool('guest', 0, 300, 'guest-0')
    _dynamic_pool.add_ips(['192.168.250.' + str(i) for i in range(100, 201)])
    
Explanation
--------------------
When init() is called by staticDHCPd, this will import the 'dynamism' module
and create a dynamic allocation pool with 192.168.250.100-200 (range doesn't
include the upper-most element), making it available for use in other parts of
conf.py.

You'll probably want to pass in different parameters, though; see dynamism.py
for details.

The 'global' line is necessary because, when init() finishes, all variables it
declared would normally be discarded, so this says "I want to modify the variable
'_dynamic_pool' at the conf-module level".





::
    def handleUnknownMAC(packet, method, mac, client_ip, relay_ip, pxe, vendor):
        return _dynamic_pool.handle(method, packet, mac, client_ip)
        
Explanation
--------------------
Since '_dynamic_pool' was created in init() and made globally accessible, all
this function has to do is pass a few parameters to dynamism.handle() and it
will return either None or a Definition object, which is all you need.
