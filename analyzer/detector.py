"""
threat detection engine
nothing fancy — just pattern matching and thresholds
but it catches the obvious stuff that matters

detection rules loosely mapped to MITRE ATT&CK:
  - brute force:  T1110
  - port scan:    T1046
  - suspicious UA: T1595 (active scanning)
"""

from collections import defaultdict

# thresholds — tune these based on your environment
BRUTE_FORCE_THRESHOLD = 5     # failed attempts from same IP
BRUTE_FORCE_WINDOW = 60       # seconds (not really enforced yet, TODO)
PORT_SCAN_THRESHOLD = 20      # unique ports from same IP
PORT_SCAN_WINDOW = 30         # seconds (same TODO)

# known malicious user agents — just the common scanners
# not comprehensive but catches the script kiddies
SUSPICIOUS_USER_AGENTS = [
    'nikto',
    'sqlmap',
    'nmap',
    'masscan',
    'dirbuster',
    'gobuster',
    'wfuzz',
    'hydra',
    'metasploit',
    'burpsuite',
    'zap',          # OWASP ZAP
    'w3af',
    'acunetix',
    'nessus',
]

# paths that get probed in basically every scan ever
SUSPICIOUS_PATHS = [
    '/wp-admin',
    '/wp-login.php',
    '/phpmyadmin',
    '/.env',
    '/admin',
    '/config.php',
    '/backup',
    '/.git',
    '/shell',
    '/cmd',
    '/etc/passwd',
    '/../',          # path traversal attempt
]


def detect_brute_force(events):
    """
    detect brute force attempts — mitre att&ck T1110
    groups failed ssh by source IP and flags if over threshold
    """
    failed_by_ip = defaultdict(list)

    for evt in events:
        if evt.get('event_type') == 'ssh_failed':
            ip = evt.get('source_ip', 'unknown')
            failed_by_ip[ip].append(evt)

    alerts = []
    for ip, attempts in failed_by_ip.items():
        if len(attempts) >= BRUTE_FORCE_THRESHOLD:
            # this IP is being naughty
            usernames = list(set(a.get('user', '?') for a in attempts))
            alerts.append({
                'type': 'brute_force',
                'severity': 'critical',
                'source_ip': ip,
                'count': len(attempts),
                'usernames': usernames,
                'mitre': 'T1110',
                'description': f'Brute force detected: {len(attempts)} failed SSH attempts from {ip} targeting {", ".join(usernames[:3])}'
            })

    return alerts


def detect_port_scan(events):
    """
    detect port scanning — mitre att&ck T1046
    looks for same IP hitting many different ports
    """
    ports_by_ip = defaultdict(set)

    for evt in events:
        ip = evt.get('source_ip')
        port = evt.get('port')
        if ip and port:
            ports_by_ip[ip].add(str(port))

    alerts = []
    for ip, ports in ports_by_ip.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            alerts.append({
                'type': 'port_scan',
                'severity': 'high',
                'source_ip': ip,
                'ports_scanned': len(ports),
                'mitre': 'T1046',
                'description': f'Port scan detected: {ip} probed {len(ports)} unique ports'
            })

    return alerts


def detect_suspicious_ua(events):
    """
    flag requests from known scanning tools — T1595
    checks user-agent strings against known bad actors
    """
    alerts = []
    seen = set()  # dedupe alerts for same IP+tool combo

    for evt in events:
        ua = evt.get('user_agent', '').lower()
        ip = evt.get('source_ip', 'unknown')

        for tool in SUSPICIOUS_USER_AGENTS:
            if tool in ua:
                key = f'{ip}:{tool}'
                if key not in seen:
                    seen.add(key)
                    alerts.append({
                        'type': 'suspicious_ua',
                        'severity': 'high',
                        'source_ip': ip,
                        'tool': tool,
                        'user_agent': evt.get('user_agent', ''),
                        'mitre': 'T1595',
                        'description': f'Scanning tool detected: {tool} from {ip}'
                    })

    return alerts


def detect_path_traversal(events):
    """
    flag suspicious path access attempts
    common in automated vulnerability scanners
    """
    alerts = []
    seen = set()

    for evt in events:
        path = evt.get('path', '').lower()
        ip = evt.get('source_ip', 'unknown')

        for sus_path in SUSPICIOUS_PATHS:
            if sus_path.lower() in path:
                key = f'{ip}:{sus_path}'
                if key not in seen:
                    seen.add(key)
                    alerts.append({
                        'type': 'suspicious_path',
                        'severity': 'warning',
                        'source_ip': ip,
                        'path': evt.get('path', ''),
                        'description': f'Suspicious path access: {evt.get("path")} from {ip}'
                    })

    return alerts


def detect_threats(events):
    """
    run all detection rules against a set of events
    returns combined list of alerts sorted by severity
    """
    all_alerts = []

    all_alerts.extend(detect_brute_force(events))
    all_alerts.extend(detect_port_scan(events))
    all_alerts.extend(detect_suspicious_ua(events))
    all_alerts.extend(detect_path_traversal(events))

    # sort by severity — criticals first
    severity_order = {'critical': 0, 'high': 1, 'warning': 2, 'info': 3}
    all_alerts.sort(key=lambda a: severity_order.get(a.get('severity', 'info'), 99))

    return all_alerts
