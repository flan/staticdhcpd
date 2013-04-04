# -*- encoding: utf-8 -*-
"""
Provides a means of easily tracking recent DHCP activity, so you can see if a
device is self-configuring properly without needing to read through the logs.

To use this module, customise the constants below, then add the following to
conf.py's init() function:
    import recent_activity
    
Like staticDHCPd, this module under the GNU General Public License v3
(C) Neil Tallim, 2013 <flan@uguu.ca>
Inspiration derived from a discussion with John Stowers
"""
#The number of events to track; if None, no limit will be applied
MAX_EVENTS = 10
#The maximum age of an event to track; if None, no limit will be applied
MAX_AGE = 60 * 5

#Whether feed items should be removed when the system is reinitialised
CLEAR_ON_REINIT = True

#Whether the list should be part of the dashboard; if False, it will appear
#in the methods list
DISPLAY_IN_DASHBOARD = True
#The positioning bias of this element in the dashboard, as an integer
#If None, it will appear at the end
DASHBOARD_ORDERING = None
#If registering as a method, this is where its callback will be registered
METHOD_PATH = '/ca/uguu/puukusoft/staticDHCPd/contrib/recent-activity/render'

#The name of the module to which this element belongs
MODULE = 'recent activity'
#The name of this component
NAME = 'dhcp'
#If either of these are None and the module is not to be rendered in the
#dashboard, the method-link will be hidden

#Do not touch anything below this line
################################################################################
import collections
import logging
import threading
import time

from staticdhcpdlib import config

_logger = logging.getLogger('contrib.recent_activity')

_events = collections.deque(maxlen=MAX_EVENTS)
_lock = threading.Lock()

_Event = collections.namedtuple('Event', ('time', 'mac', 'ip', 'subnet', 'serial', 'method', 'pxe'))

def _drop_old_events():
    """
    Clears out any events older than `MAX_AGE`.
    """
    max_age = time.time() - MAX_AGE
    dropped = 0
    with _lock:
        while _events:
            if _events[-1].time < max_age:
                _events.pop()
                dropped += 1
            else:
                break
    if dropped:
        _logger.debug("Dropped %(count)i events from recent activity due to age" % {
         'count': dropped,
        })
        
def _flush():
    with _lock:
        _events.clear()
        
def _render(*args, **kwargs):
    """
    Provides a dashboard-embeddable rendering of all recent activity.
    """
    _drop_old_events()
    with _lock:
        if not _events:
            return "No activity in the last %(max-age)i seconds" % {
             'max-age': MAX_AGE,
            }
            
        elements = []
        for event in _events:
            elements.append("""
            <tr>
                <td>%(event)s</td>
                <td>%(pxe)s</td>
                <td>%(mac)s</td>
                <td>%(ip)s</td>
                <td>%(subnet)s</td>
                <td>%(serial)i</td>
                <td>%(time)s</td>
            </tr>""" % {
             'event': event.method,
             'pxe': event.pxe and 'Yes' or 'No',
             'mac': event.mac,
             'ip': event.ip or '-',
             'subnet': event.subnet,
             'serial': event.serial,
             'time': time.ctime(event.time),
            })
        return """
        <table class="element">
            <thead>
                <tr>
                    <th>Event</th>
                    <th>PXE</th>
                    <th>MAC</th>
                    <th>IP</th>
                    <th>Subnet</th>
                    <th>Serial</th>
                    <th>Time</th>
                </tr>
            </thead>
            <tbody>
                %(content)s
            </tbody>
        </table>""" % {
         'content': '\n'.join(elements),
        }
        
def _update(statistics):
    """
    Removes any previous event from `mac`, then adds the event to the
    collection.
    """
    mac = str(statistics.mac)
    with _lock:
        for (i, event) in enumerate(_events):
            if event.mac == mac:
                del _events[i]
                break
                
        _events.appendleft(_Event(time.time(), mac, statistics.client_ip, statistics.subnet, statistics.serial, statistics.method, statistics.pxe))
        
#Setup happens here
################################################################################
config.callbacks.statsAddHandler(_update)
_logger.info("Prepared recent-activity-tracker for up to %(count)i events, %(max-age)i seconds old" % {
 'count': MAX_EVENTS,
 'max-age': MAX_AGE,
})

if CLEAR_ON_REINIT:
    _logger.info("Registering callback handler to clear activity on reinitialisation...")
    config.callbacks.systemAddReinitHandler(_flush)
    
if DISPLAY_IN_DASHBOARD:
    _logger.info("Registering activity-tracker as a dashboard element, with ordering=%(ordering)s" % {
     'ordering': DASHBOARD_ORDERING,
    })
    config.callbacks.webAddDashboard(MODULE, NAME, _render, ordering=DASHBOARD_ORDERING)
else:
    _logger.info("Registering activity-tracker at '%(path)s'" % {
     'path': METHOD_PATH,
    })
    config.callbacks.webAddMethod(
     METHOD_PATH, _render,
     hidden=(MODULE is None or NAME is None), module=MODULE, name=NAME,
     display_mode=config.callbacks.WEB_METHOD_TEMPLATE
    )
    
