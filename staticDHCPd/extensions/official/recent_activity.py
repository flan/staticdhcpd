# -*- encoding: utf-8 -*-
"""
Provides a means of easily tracking recent DHCP activity, so you can see if a
device is self-configuring properly without needing to read through the logs.

To use this module, configure whatever is required in conf.py, inside of init(),
like this:
    with extensions.recent_activity as x:
        x.LIFETIME_STATS_ENABLED = True

For a list of all parameters you may define, see below.

Then add the following to conf.py's init() function:
    import staticDHCPd_extensions.recent_activity

Like staticDHCPd, this module under the GNU General Public License v3
(C) Neil Tallim, 2021 <neil.tallim@linux.com>

Inspiration derived from a discussion with John Stowers
"""
from staticdhcpdlib import config
_config = config.conf.extensions.recent_activity
_CONFIG = _config.extension_config_merge(defaults={
    #The number of events to track; if None, no limit will be applied
    'MAX_EVENTS': 10,
    #The maximum age of an event to track; if None, no limit will be applied
    'MAX_AGE': 60 * 5,

    #Whether feed items should be removed when the system is reinitialised
    'CLEAR_ON_REINIT': True,

    #Whether the list should be part of the dashboard; if False, it will appear
    #in the methods list
    'DISPLAY_IN_DASHBOARD': True,
    #The positioning bias of this element in the dashboard, as an integer; if
    #None, it will appear at the end
    'DASHBOARD_ORDERING': None,
    #If registering as a method, this is where its callback will be registered
    'METHOD_PATH': '/ca/uguu/puukusoft/staticDHCPd/extension/recent-activity/render',

    #If either MODULE or NAME are None and the module is not to be rendered in
    #the dashboard, the method-link will be hidden

    #The name of the module to which this element belongs
    'MODULE': 'recent activity',
    #The name of this component
    'NAME': 'dhcp',
}, required=[
])
del _config

#Do not touch anything below this line
################################################################################
import collections
import logging
import threading
import time

_logger = logging.getLogger('extension.recent_activity')

_events = collections.deque(maxlen=_CONFIG['MAX_EVENTS'])
_lock = threading.Lock()

_Event = collections.namedtuple('Event', ('time', 'mac', 'ip', 'subnet', 'serial', 'method', 'port'))

def _drop_old_events():
    """
    Clears out any events older than `MAX_AGE`.
    """
    max_age = time.time() - _CONFIG['MAX_AGE']
    dropped = 0
    with _lock:
        while _events:
            if _events[-1].time < max_age:
                _events.pop()
                dropped += 1
            else:
                break
    if dropped:
        _logger.debug("Dropped {} events from recent activity due to age".format(dropped))

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
            return "No activity in the last {} seconds".format(_CONFIG['MAX_AGE'])

        elements = []
        for event in _events:
            elements.append("""
            <tr>
                <td>{event}</td>
                <td>{port}</td>
                <td>{mac}</td>
                <td>{ip}</td>
                <td>{subnet}</td>
                <td>{serial}</td>
                <td>{time}</td>
            </tr>""".format(
                event=event.method,
                port=event.port,
                mac=event.mac,
                ip=event.ip or '-',
                subnet=event.subnet,
                serial=event.serial,
                time=time.ctime(event.time),
            ))
        return """
        <table class="element">
            <thead>
                <tr>
                    <th>Event</th>
                    <th>Port</th>
                    <th>MAC</th>
                    <th>IP</th>
                    <th>Subnet</th>
                    <th>Serial</th>
                    <th>Time</th>
                </tr>
            </thead>
            <tbody>
                {content}
            </tbody>
        </table>""".format(
            content='\n'.join(elements),
        )

def _update(statistics):
    """
    Removes any prior event from `mac`, then adds the event to the collection.
    """
    mac = str(statistics.mac)
    with _lock:
        for (i, event) in enumerate(_events):
            if event.mac == mac:
                del _events[i]
                break

        _events.appendleft(_Event(time.time(), mac, statistics.ip, statistics.subnet, statistics.serial, statistics.method, statistics.port))

#Setup happens here
################################################################################
config.callbacks.statsAddHandler(_update)
_logger.info("Prepared recent-activity-tracker for up to {} events, {} seconds old".format(_CONFIG['MAX_EVENTS'], _CONFIG['MAX_AGE']))

if _CONFIG['CLEAR_ON_REINIT']:
    _logger.info("Registering callback handler to clear activity on reinitialisation...")
    config.callbacks.systemAddReinitHandler(_flush)

if _CONFIG['DISPLAY_IN_DASHBOARD']:
    _logger.info("Registering activity-tracker as a dashboard element, with ordering={}".format(_CONFIG['DASHBOARD_ORDERING']))
    config.callbacks.webAddDashboard(
        _CONFIG['MODULE'], _CONFIG['NAME'], _render,
        ordering=_CONFIG['DASHBOARD_ORDERING'],
    )
else:
    _logger.info("Registering activity-tracker at '{}'".format(_CONFIG['METHOD_PATH']))
    config.callbacks.webAddMethod(
     _CONFIG['METHOD_PATH'], _render,
        hidden=(_CONFIG['MODULE'] is None or _CONFIG['NAME'] is None),
        module=_CONFIG['MODULE'],
        name=_CONFIG['NAME'],
        display_mode=config.callbacks.WEB_METHOD_TEMPLATE,
    )
