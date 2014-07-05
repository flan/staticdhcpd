Customisation guidance
======================
While quite usable out-of-the-box, especially for its intended purpose, which
is serving static DHCP "leases", different sites have different needs, and some
sites want as few frills as possible.

This section exists to cover the various bells and whistles available.

.. toctree::
    :maxdepth: 2

    configuration.rst
    scripting.rst
    extensions.rst

For the sysadmins out there working in acutely memory-constrained environments
(that still have enough space to support a Python interpreter), as a general
design guideline, *staticDHCPd* avoids loading anything it doesn't absolutely
need: if you choose not to enable the `web` subsystem, for example, it won't
ever be read from disk.

Additionally, staticDHCPd is pretty open to tuning, so if you know a lot about
the sort of load your environment will handle, you can change properties like
``checkinterval`` to adjust threading and resource priotisation and
responsiveness.
