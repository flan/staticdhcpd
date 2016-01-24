"""
ipv4_to_iface
=============
Support for resolving an IPv4 address to a network interface in pure, stdlib
CPython.

Suitable for use with Linux, FreeBSD, OpenBSD, NetBSD, DragonflyBSD, and
Mac OS X.

Legal
=====
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and via any
medium.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

Authors
=======
Neil Tallim <flan@uguu.ca>
"""
import ctypes
import ctypes.util
import socket

_LIBC = ctypes.CDLL(ctypes.util.find_library('c'))

class struct_sockaddr(ctypes.Structure):
    _fields_ = (
        ('sa_family', ctypes.c_ushort),
    )

class struct_sockaddr_in(ctypes.Structure):
    _fields_ = (
        ('sin_family', ctypes.c_ushort),
        ('sin_port', ctypes.c_uint16),
        ('sin_addr', ctypes.c_byte * 4),
    )

class struct_ifaddrs(ctypes.Structure): pass
struct_ifaddrs._fields_ = (
        ('ifa_next', ctypes.POINTER(struct_ifaddrs)),
        ('ifa_name', ctypes.c_char_p),
        ('ifa_flags', ctypes.c_uint),
        ('ifa_addr', ctypes.POINTER(struct_sockaddr)),
    ) #Linux diverges from BSD for the rest, but it's safe to omit the tail

def _is_match(sockaddr, ipv4):
    if sockaddr.sa_family == socket.AF_INET: #IPv4 address
        sockaddr_in = ctypes.cast(ctypes.pointer(sockaddr), ctypes.POINTER(struct_sockaddr_in)).contents
        return socket.inet_ntop(socket.AF_INET, sockaddr_in.sin_addr) == ipv4
    return False

def get_network_interface(ipv4):
    """
    Returns the name of the interface to which the given address is bound, or
    None if nothing matches.
    """
    ifap = ctypes.POINTER(struct_ifaddrs)()
    if _LIBC.getifaddrs(ctypes.pointer(ifap)): #Non-zero response
        raise OSError(ctypes.get_errno())
        
    try:
        ifaddr = ifap.contents
        while True:
            if _is_match(ifaddr.ifa_addr.contents, ipv4):
                return ifaddr.ifa_name.decode("utf-8")
            if not ifaddr.ifa_next:
                break
            ifaddr = ifaddr.ifa_next.contents
    finally:
        _LIBC.freeifaddrs(ifap)
    return None

if __name__ == '__main__':
    import sys
    print(get_network_interface(sys.argv[1]))
