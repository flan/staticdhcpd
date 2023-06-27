# -*- encoding: utf-8 -*-
"""
Processes and exposes runtime statistics information about the DHCP server.

To use this module, configure whatever is required in conf.py, inside of init(),
like this:
    with extensions.statistics as x:
        x.LIFETIME_STATS_ENABLED = True

For a list of all parameters you may define, see below.

Then add the following to conf.py's init() function:
    import staticDHCPd_extensions.statistics

Like staticDHCPd, this module under the GNU General Public License v3
(C) Neil Tallim, 2021 <neil.tallim@linux.com>
"""
from staticdhcpdlib import config
_config = config.conf.extensions.statistics
_CONFIG = _config.extension_config_merge(defaults={
    #The name of the module to which dashboard elements belong
    'MODULE': 'statistics',

    #Whether lifetime stats should be made available
    'LIFETIME_STATS_ENABLED': True,
    #Whether lifetime stats should be included in the web dashboard
    'LIFETIME_STATS_DISPLAY': True,
    #The ordering-bias value to apply, as an integer; if None, appended to the
    #end
    'LIFETIME_STATS_ORDERING': None,
    #If not available via the dashboard, stats can be accessed at this path
    'LIFETIME_STATS_PATH': '/ca/uguu/puukusoft/staticDHCPd/extension/stats/lifetime',
    #The name of the component; if None and not displayed in the dashboard, the
    #method link will be hidden
    'LIFETIME_STATS_NAME': 'lifetime',

    #Whether averaging values should be made available
    'AVERAGES_ENABLED': True,
    #The periods, as quantised windows, over which statistics should be
    #averaged; 0 represents the current frame
    'AVERAGES_WINDOWS': [0, 1, 2, 3, 12, 72, 288],
    #Whether averages should be included in the web dashboard
    'AVERAGES_DISPLAY': True,
    #The ordering-bias value to apply, as an integer; if None, appended to the
    #end
    'AVERAGES_ORDERING': None,
    #If not available via the dashboard, stats can be accessed at this path
    'AVERAGES_PATH': '/ca/uguu/puukusoft/staticDHCPd/extension/stats/averages',
    #The name of the component; if None and not displayed in the dashboard, the
    #method link will be hidden
    'AVERAGES_NAME': 'averages',

    #Whether graph generation should be made available; this component depends
    #on the browser having Internet access to retrieve Chart.js (though this
    #module may be modified to use an offline copy)
    'GRAPH_ENABLED': True,
    #The ordering-bias value to apply, as an integer; if None, appended to the
    #end
    'GRAPH_ORDERING': None,
    #The dimensions of the canvas upon which to render the graph
    'GRAPH_RENDER_DIMENSIONS': (1536, 320),
    #The name of the component; if None and not displayed in the dashboard, the
    #method link will be hidden
    'GRAPH_NAME': 'packets per second',
    #Whether additional lines should be plotted for per-method data
    'GRAPH_INCLUDE_METHOD_LINES': True,
    'GRAPH_INCLUDE_METHOD_DISCARDED_LINES': True,
    #The path at which a CSV version of the graph may be obtained; None to
    #disable (this is independent of GRAPH_ENABLED)
    'GRAPH_CSV_PATH': '/ca/uguu/puukusoft/staticDHCPd/extension/stats/graph.csv',
    #The name of the component; if None, the method link will be hidden
    'GRAPH_CSV_NAME': 'graph (csv)',
    #The path at which a JSON version of the graph may be obtained; None to
    #disable (this is independent of GRAPH_ENABLED)
    'GRAPH_JSON_PATH': '/ca/uguu/puukusoft/staticDHCPd/extension/stats/graph.json',
    #The name of the component; if None, the method link will be hidden
    'GRAPH_JSON_NAME': 'graph (json)',

    #The number of seconds over which to quantise data; lower values will
    #increase resolution, but consume more memory
    'QUANTISATION_INTERVAL': 60 * 5,

    #The number of quantised elements to retain for statistical evaluation
    #Higher values will increase the amount of data that can be interpreted,
    #at the cost of more memory and processing time
    'RETENTION_COUNT': 288 * 2, #At five minutes, 288 is a day
}, required=[
])
del _config

#Do not touch anything below this line
################################################################################
import collections
import datetime
import logging
import threading
import time

from staticdhcpdlib import dhcp
_METHODS = tuple(sorted(getattr(dhcp, key) for key in dir(dhcp) if key.startswith('_PACKET_TYPE_')))

_logger = logging.getLogger('extension.statistics')

_Gram = collections.namedtuple('Gram', (
    'dhcp_packets',
    'dhcp_packets_discarded',
    'other_packets',
    'processing_time',
))

def _generate_dhcp_packets_dict():
    return dict((method, 0) for method in _METHODS)

class Statistics(object):
    """
    Tracks statistics and provides methods for visualising data.
    """
    def __init__(self, graph_size, gram_size):
        self._activity = False

        self._dhcp_packets = _generate_dhcp_packets_dict()
        self._dhcp_packets_discarded = _generate_dhcp_packets_dict()
        self._other_packets = 0

        self._processing_time = 0.0

        self._graph = collections.deque((None for i in range(graph_size)), maxlen=graph_size)
        self._gram_size = gram_size

        self._lock = threading.Lock()

        self._initialise_gram()

    def _initialise_gram(self):
        """
        Must be called from a context in which the lock is held.
        """
        self._gram_start_time = time.time()
        self._gram_start_time -= self._gram_start_time % self._gram_size #Round down
        self._current_gram = {
             'other-packets': 0,
             'dhcp-packets': _generate_dhcp_packets_dict(),
             'dhcp-packets-discarded': _generate_dhcp_packets_dict(),
             'processing-time': 0.0,
        }

    def _update_graph(self):
        """
        Call this every time data is collected or requested.
        """
        with self._lock:
            current_time = time.time()
            if self._gram_start_time <= current_time - self._gram_size:
                #Insert null grams as needed
                steps = int((current_time - self._gram_start_time) / max(1, self._gram_size))
                for i in range(1, steps):
                    self._graph.append(None)

                if self._activity:
                    self._graph.append(_Gram(
                        self._current_gram['dhcp-packets'],
                        self._current_gram['dhcp-packets-discarded'],
                        self._current_gram['other-packets'],
                        self._current_gram['processing-time'],
                    ))
                    self._initialise_gram()
                    self._activity = False
                else:
                    self._graph.append(None)

    def process(self, statistics):
        """
        Updates the statstics engine's data.
        """
        self._update_graph()
        with self._lock:
            self._activity = True

            if statistics.method:
                self._dhcp_packets[statistics.method] += 1
                self._current_gram['dhcp-packets'][statistics.method] += 1
                if not statistics.processed:
                    self._dhcp_packets_discarded[statistics.method] += 1
                    self._current_gram['dhcp-packets-discarded'][statistics.method] += 1
            else:
                self._other_packets += 1
                self._current_gram['other-packets'] += 1
            self._processing_time += statistics.processing_time
            self._current_gram['processing-time'] += statistics.processing_time

    def graph_csv(self):
        """
        Returns a CSV file containing the time at which the stats were recorded
        and the events that occurred during the corresponding period.
        """
        self._update_graph()

        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)
        header = ['time']
        header.extend(_METHODS)
        header.extend('{} discarded'.format(method) for method in _METHODS)
        header.extend(('other packets', 'processing time'))
        writer.writerow(header)
        del header

        null_record = ['0' for i in range(len(_METHODS) * 2)] + ['0', '0']

        render_format = '%Y-%m-%d %H:%M:%S'
        with self._lock:
            base_time = self._gram_start_time
            for (i, gram) in enumerate(reversed(self._graph)):
                record = [time.strftime(render_format, time.localtime(base_time - (i * self._gram_size)))]
                if gram:
                    record.extend(gram.dhcp_packets[i] for i in _METHODS)
                    record.extend(gram.dhcp_packets_discarded[i] for i in _METHODS)
                    record.extend((gram.other_packets, gram.processing_time))
                    writer.writerow(record)
                else:
                    writer.writerow(record + null_record)
        output.seek(0)
        return ('text/csv', output.read())
    
    def graph_json(self):
        """
        Returns a JSON file containing the time at which the stats were recorded
        and the events that occurred during the corresponding period.
        """
        self._update_graph()

        import json
        
        output = []
        
        null_record = {
            "methods": _generate_dhcp_packets_dict(),
            "methods_discarded": _generate_dhcp_packets_dict(),
            "other_packets": 0,
            "processing_time": 0.0,
        }
        
        with self._lock:
            base_time = self._gram_start_time
            for (i, gram) in enumerate(reversed(self._graph)):
                gram_time = base_time - (i * self._gram_size)
                if gram:
                    record = {
                        'time': gram_time,
                        'other_packets': gram.other_packets,
                        'processing_time': gram.processing_time,
                        'methods': gram.dhcp_packets,
                        'methods_discarded': gram.dhcp_packets_discarded,
                    }
                else:
                    record = null_record.copy()
                    record["time"] = gram_time
                output.append(record)
        output.reverse()
        return ('application/json', json.dumps(output))

    def graph(self, dimensions):
        """
        Uses Chart.js to render a client-side graph of average DHCP activity.
        """
        self._update_graph()
        
        import json

        datasets = []
        
        packets_per_second = []
        datasets.append({
            "label": 'Packets per second',
            "data": packets_per_second,
            "fill": False,
        })
        
        method_values = {}
        method_discarded_values = {}
        for method in _METHODS:
            if _CONFIG['GRAPH_INCLUDE_METHOD_LINES']:
                method_values[method] = []
                datasets.append({
                    "label": method,
                    "data": method_values[method],
                    "fill": False,
                    "hidden": True,
                })
            if _CONFIG['GRAPH_INCLUDE_METHOD_DISCARDED_LINES']:
                method_discarded_values[method] = []
                datasets.append({
                    "label": method + ' discarded',
                    "data": method_discarded_values[method],
                    "fill": False,
                    "hidden": True,
                })
                
        with self._lock:
            base_time = self._gram_start_time
            
            #This would add the current frame, but it doesn't average well and would skew Y
            #data = [sum(self._current_gram['dhcp-packets'].values()) / (time.time() - self._gram_start_time)]
            for (i, gram) in enumerate(self._graph):
                gram_time = int((base_time - ((len(self._graph) - i - 1) * self._gram_size)) * 1000)
                
                if gram:
                    packets_per_second.append({'x': gram_time, 'y': sum(gram.dhcp_packets.values()) / self._gram_size})
                    for method in _METHODS:
                        if method_values:
                            method_values[method].append({'x': gram_time, 'y': gram.dhcp_packets[method]})
                        if method_discarded_values:
                            method_discarded_values[method].append({'x': gram_time, 'y': gram.dhcp_packets_discarded[method]})
                else:
                    packets_per_second.append({'x': gram_time, 'y': 0})
                    for method in _METHODS:
                        if method_values:
                            method_values[method].append({'x': gram_time, 'y': 0})
                        if method_discarded_values:
                            method_discarded_values[method].append({'x': gram_time, 'y': 0})

        return """
        <canvas id="%(chart_id)s" width="%(width)i" height="%(height)i"></canvas>
        <script>
            const ctx = document.getElementById('%(chart_id)s').getContext('2d');
            if (typeof Chart !== 'undefined') {
                const __statistics_chart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        xValueType: "dateTime",
                        datasets: %(datasets)s,
                    },
                    options: {
                        scales: {
                            x: {
                                type: 'time',
                                time: {
                                    displayFormats: {
                                        hour: 'HH:mm',
                                        minute: 'HH:mm',
                                    },
                                    tooltipFormat: 'MMM D HH:mm',
                                },
                            },
                            y: {
                                type: 'linear',
                                display: true,
                                ticks: {
                                    beginAtZero: true,
                                    min: 0
                                },
                                scaleLabel: {
                                    display: true,
                                },
                            },
                        },
                        title: {
                            display: false,
                        },
                        legend: {
                            display: %(show_legend)s,
                        },
                        responsive: false,
                    }
                });
            } else {
                ctx.font = "20px Sans";
                ctx.fillText("Chart.js is unavailable", 5, 25);
            }
        </script>
        """ % {
            "chart_id": '__statistics_chart',
            "width": dimensions[0],
            "height": dimensions[1],
            "datasets": json.dumps(datasets),
            "show_legend": (method_values or method_discarded_values) and 'true' or 'false',
        }
        
    def lifetime_stats(self):
        """
        Provides launch-to-now statistics for what the server has handled,
        rendered as an XHTML fragment.
        """
        self._update_graph()

        received_total = 0
        received = ['<tr><td style="text-align: right; font-weight: bold;">Received</td>']
        processed = ['<tr><td style="text-align: right; font-weight: bold;">Processed</td>']
        discarded = ['<tr><td style="text-align: right; font-weight: bold;">Discarded</td>']
        with self._lock:
            for packet_type in _METHODS:
                _received = self._dhcp_packets[packet_type]
                _discarded = self._dhcp_packets_discarded[packet_type]
                _processed = _received - _discarded
                received_total += _received
                for (l, v) in ((received, _received), (processed, _processed), (discarded, _discarded)):
                    l.append('<td>{}</td>'.format(v))

            return """
            <table class="element">
                <thead>
                    <tr>
                        <th/>
                        {methods}
                    </tr>
                </thead>
                <tfoot>
                    <tr>
                        <td colspan="{span}">{dhcp} DHCP; {non_dhcp} non-DHCP; average turnaround: {average:.4f}s</td>
                    </tr>
                </tfoot>
                <tbody>
                    {received}</tr>
                    {processed}</tr>
                    {discarded}</tr>
                </tbody>
            </table>""".format(
                methods='\n'.join('<th>{}</th>'.format(method.replace('REQUEST:', 'R:')) for method in _METHODS),
                received=''.join(received),
                processed=''.join(processed),
                discarded=''.join(discarded),
                span=len(_METHODS) + 1,
                average=received_total and (self._processing_time / received_total) or 0.0,
                dhcp=received_total,
                non_dhcp=self._other_packets,
            )

    def averages(self, windows):
        """
        Provides the average load that the server has handled in every averaging
        period specified in `windows`, rendered as an XHTML fragment.
        """
        self._update_graph()

        current_time = time.time()
        elements = []
        with self._lock:
            for window in windows:
                packets = self._current_gram['dhcp-packets'].copy()
                packets_discarded = sum(self._current_gram['dhcp-packets-discarded'].values())
                other = self._current_gram['other-packets']
                processing_time = self._current_gram['processing-time']
                timestamp = self._gram_start_time

                for i in range(1, min(window, len(self._graph)) + 1):
                    timestamp -= self._gram_size
                    gram = self._graph[-1 * i]
                    if not gram:
                        continue

                    for (k, v) in gram.dhcp_packets.items():
                        packets[k] += v
                    packets_discarded += sum(gram.dhcp_packets_discarded.values())
                    other += gram.other_packets
                    processing_time += gram.processing_time

                total_time = float(max(int(current_time - timestamp), 1))
                total_packets = sum(packets.values())
                elements.append("""
                <tr>
                    <td>{time}</td>
                    {methods}
                    <td>{discarded:.4f}/s</td>
                    <td>{other:.4f}/s</td>
                    <td>{average:.4f}s</td>
                </tr>""".format(
                    time=datetime.timedelta(seconds=total_time),
                    methods='\n'.join('<td>{:.4f}/s</td>'.format(packets[method] / total_time) for method in _METHODS),
                    discarded=(packets_discarded / total_time),
                    other=(other / total_time),
                    average=(total_packets and (processing_time / total_packets) or 0.0),
                ))
            return """
            <table class="element">
                <thead>
                    <tr>
                        <th>Time period</th>
                        {methods}
                        <th>Discarded</th>
                        <th>Other</th>
                        <th>Turnaround</th>
                    </tr>
                </thead>
                <tbody>
                    {content}
                </tbody>
            </table>""".format(
                content='\n'.join(elements),
                methods='\n'.join('<th>{}</th>'.format(method.replace('REQUEST:', 'R:')) for method in _METHODS),
            )

#Setup happens here
################################################################################
_stats = Statistics(_CONFIG['RETENTION_COUNT'], _CONFIG['QUANTISATION_INTERVAL'])
config.callbacks.statsAddHandler(_stats.process)
_logger.info("Statistics engine online")

if _CONFIG['GRAPH_ENABLED']:
    _logger.debug("Registering Chart.js import")
    def _chartjs_header(path, queryargs, mimetype, data, headers):
        if path == '/':
            return """
            <script src="https://cdn.jsdelivr.net/npm/chart.js@^3"></script>
            <script src="https://cdn.jsdelivr.net/npm/moment@^2"></script>
            <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-moment@^1"></script>
            """
        return None
    config.callbacks.webAddHeader(_chartjs_header)
    del _chartjs_header
    
    _logger.info("Registering graph as a dashboard element, with ordering={}".format(_CONFIG['GRAPH_ORDERING']))
    config.callbacks.webAddDashboard(
        _CONFIG['MODULE'], _CONFIG['GRAPH_NAME'], lambda path, queryargs, mimetype, data, headers: _stats.graph(_CONFIG['GRAPH_RENDER_DIMENSIONS']),
        ordering=_CONFIG['GRAPH_ORDERING'],
    )
    
if _CONFIG['GRAPH_CSV_PATH']:
    _logger.info("Registering graph CSV-provider at '{}'".format(_CONFIG['GRAPH_CSV_PATH']))
    config.callbacks.webAddMethod(
        _CONFIG['GRAPH_CSV_PATH'], lambda *args, **kwargs: _stats.graph_csv(),
        hidden=(_CONFIG['GRAPH_CSV_NAME'] is None),
        module=_CONFIG['MODULE'],
        name=_CONFIG['GRAPH_CSV_NAME'],
        display_mode=config.callbacks.WEB_METHOD_RAW,
    )
    
if _CONFIG['GRAPH_JSON_PATH']:
    _logger.info("Registering graph JSON-provider at '{}'".format(_CONFIG['GRAPH_JSON_PATH']))
    config.callbacks.webAddMethod(
        _CONFIG['GRAPH_JSON_PATH'], lambda *args, **kwargs: _stats.graph_json(),
        hidden=(_CONFIG['GRAPH_JSON_NAME'] is None),
        module=_CONFIG['MODULE'],
        name=_CONFIG['GRAPH_JSON_NAME'],
        display_mode=config.callbacks.WEB_METHOD_RAW,
    )

if _CONFIG['AVERAGES_ENABLED']:
    renderer = lambda *args, **kwargs: _stats.averages(_CONFIG['AVERAGES_WINDOWS'])
    if _CONFIG['AVERAGES_DISPLAY']:
        _logger.info("Registering averages as a dashboard element, with ordering={}".format(_CONFIG['AVERAGES_ORDERING']))
        config.callbacks.webAddDashboard(
            _CONFIG['MODULE'], _CONFIG['AVERAGES_NAME'], renderer,
            ordering=_CONFIG['AVERAGES_ORDERING'],
        )
    else:
        _logger.info("Registering averages at '{}'".format(_CONFIG['AVERAGES_PATH']))
        config.callbacks.webAddMethod(
            _CONFIG['AVERAGES_PATH'], renderer,
            hidden=(_CONFIG['AVERAGES_NAME'] is None),
            module=_CONFIG['MODULE'],
            name=_CONFIG['AVERAGES_NAME'],
            display_mode=config.callbacks.WEB_METHOD_TEMPLATE,
        )

if _CONFIG['LIFETIME_STATS_ENABLED']:
    renderer = lambda *args, **kwargs: _stats.lifetime_stats()
    if _CONFIG['LIFETIME_STATS_DISPLAY']:
        _logger.info("Registering lifetime stats as a dashboard element, with ordering={}".format(_CONFIG['LIFETIME_STATS_ORDERING']))
        config.callbacks.webAddDashboard(
            _CONFIG['MODULE'], _CONFIG['LIFETIME_STATS_NAME'], renderer,
            ordering=_CONFIG['LIFETIME_STATS_ORDERING'],
        )
    else:
        _logger.info("Registering lifetime stats at '{}'".format(_CONFIG['LIFETIME_STATS_PATH']))
        config.callbacks.webAddMethod(
            _CONFIG['LIFETIME_STATS_PATH'], renderer,
            hidden=(_CONFIG['LIFETIME_STATS_NAME'] is None),
            module=_CONFIG['MODULE'],
            name=_CONFIG['LIFETIME_STATS_NAME'],
            display_mode=config.callbacks.WEB_METHOD_TEMPLATE,
        )
