Logging facilities
==================
*staticDHCPd* uses the native Python `logging` subsystem, so if you want to
work with it, just tap into that.

It does, however, define custom logging handlers.

Classes
-------
.. autoclass:: logging_handlers.FIFOHandler
    :show-inheritance:
    
    .. automethod:: logging_handlers.FIFOHandler.flush
    
    .. automethod:: logging_handlers.FIFOHandler.readContents
