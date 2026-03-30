"""
stats aggregation for the dashboard
takes parsed events and spits out numbers for chart.js
"""

from collections import defaultdict, Counter


def get_top_ips(events, n=10):
    """top N source IPs by event count — the usual suspects"""
    ip_counts = Counter()
    for evt in events:
        ip = evt.get('source_ip')
        if ip:
            ip_counts[ip] += 1

    return dict(ip_counts.most_common(n))


def get_events_by_hour(events):
    """
    group events by hour for the timeline chart
    uses the raw timestamp string — not perfect but close enough
    parses common formats: syslog (Jan  5 14:00:00) and access log (10/Oct/2000:13:55:36)
    """
    hour_counts = defaultdict(int)

    for evt in events:
        ts = evt.get('timestamp', '')
        hour = None

        # try syslog format first: "Jan  5 14:23:01"
        if len(ts) == 15 or len(ts) == 14:
            parts = ts.split(':')
            if len(parts) >= 1:
                hour = parts[0].split()[-1] + ':00'

        # try access log format: "10/Oct/2000:13:55:36 -0700"
        elif ':' in ts and '/' in ts:
            try:
                time_part = ts.split(':')[1]
                hour = time_part + ':00'
            except (IndexError, ValueError):
                pass

        if hour:
            hour_counts[hour] += 1

    # sort by hour
    return dict(sorted(hour_counts.items()))


def get_severity_breakdown(events):
    """count events by severity level — feeds the pie chart"""
    counts = Counter()
    for evt in events:
        sev = evt.get('severity', 'info')
        counts[sev] += 1

    return dict(counts)


def get_event_type_breakdown(events):
    """what kinds of events are we seeing"""
    counts = Counter()
    for evt in events:
        etype = evt.get('event_type', 'unknown')
        counts[etype] += 1

    return dict(counts)


def get_alert_type_breakdown(alerts):
    """group alerts by detection rule type"""
    counts = Counter()
    for alert in alerts:
        atype = alert.get('type', 'unknown')
        counts[atype] += 1

    return dict(counts)


def compute_stats(events, alerts):
    """
    compute all stats at once — called after each upload
    returns a dict ready for jsonify
    """
    return {
        'total_events': len(events),
        'total_alerts': len(alerts),
        'critical_alerts': sum(1 for a in alerts if a.get('severity') == 'critical'),
        'high_alerts': sum(1 for a in alerts if a.get('severity') == 'high'),
        'top_ips': get_top_ips(events),
        'events_by_hour': get_events_by_hour(events),
        'severity_breakdown': get_severity_breakdown(events),
        'event_types': get_event_type_breakdown(events),
        'alert_types': get_alert_type_breakdown(alerts),
    }
