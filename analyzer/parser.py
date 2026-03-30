"""
log parsers for various formats
the regex here is gnarly but it handles real-world logs pretty well
tested against auth.log from my own server (rip that box)
"""

import re
from datetime import datetime


# syslog RFC 3164 — the "standard" that nobody follows consistently
# format: <priority>timestamp hostname app[pid]: message
# but half the time priority is missing so we handle both
SYSLOG_PATTERN = re.compile(
    r'^(?:<(\d+)>)?'                          # optional priority
    r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})' # timestamp (Jan  5 14:23:01)
    r'\s+(\S+)'                                # hostname
    r'\s+(\S+?)(?:\[(\d+)\])?:\s*'             # app[pid]
    r'(.+)$'                                   # message — the good stuff
)

# auth.log ssh patterns — mitre att&ck T1110 (brute force) detection starts here
SSH_FAILED_PATTERN = re.compile(
    r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)'
)
SSH_SUCCESS_PATTERN = re.compile(
    r'Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)'
)
# sudo stuff — privilege escalation attempts (T1548)
SUDO_PATTERN = re.compile(
    r'(\S+)\s*:\s*.*COMMAND=(.+)$'
)
SUDO_FAIL_PATTERN = re.compile(
    r'(\S+)\s*:\s*.*authentication failure'
)

# apache/nginx combined log format
# regex from hell but it works — matches the standard combined format
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.1" 200 2326 "http://ref" "Mozilla/4.0"
ACCESS_LOG_PATTERN = re.compile(
    r'^(\S+)\s+'        # client ip
    r'(\S+)\s+'         # ident (usually -)
    r'(\S+)\s+'         # auth user (usually -)
    r'\[([^\]]+)\]\s+'  # timestamp in brackets
    r'"(\S+)\s+'        # method
    r'(\S+)\s+'         # path
    r'(\S+)"\s+'        # protocol
    r'(\d{3})\s+'       # status code
    r'(\d+|-)\s*'       # bytes
    r'(?:"([^"]*)"\s*)?'  # referer (optional)
    r'(?:"([^"]*)")?'    # user agent (optional)
)


def detect_log_type(raw_text):
    """
    figure out what kind of log we're looking at
    not bulletproof but works for the common cases
    """
    lines = raw_text.strip().split('\n')[:10]  # just peek at first 10 lines

    access_hits = 0
    syslog_hits = 0

    for line in lines:
        if ACCESS_LOG_PATTERN.match(line.strip()):
            access_hits += 1
        if SYSLOG_PATTERN.match(line.strip()):
            syslog_hits += 1

    if access_hits > syslog_hits:
        return 'access'
    elif syslog_hits > 0:
        return 'syslog'
    else:
        return 'unknown'


def parse_syslog_line(line):
    """parse a single syslog/auth.log line into a structured dict"""
    m = SYSLOG_PATTERN.match(line.strip())
    if not m:
        return None

    priority, timestamp, hostname, app, pid, message = m.groups()

    event = {
        'timestamp': timestamp,
        'hostname': hostname,
        'app': app,
        'pid': pid,
        'message': message,
        'severity': 'info',
        'event_type': 'generic',
        'raw': line.strip()
    }

    # check for ssh failures — this is where the fun begins
    ssh_fail = SSH_FAILED_PATTERN.search(message)
    if ssh_fail:
        event['event_type'] = 'ssh_failed'
        event['severity'] = 'warning'
        event['user'] = ssh_fail.group(1)
        event['source_ip'] = ssh_fail.group(2)
        event['port'] = ssh_fail.group(3)
        return event

    # ssh success
    ssh_ok = SSH_SUCCESS_PATTERN.search(message)
    if ssh_ok:
        event['event_type'] = 'ssh_success'
        event['severity'] = 'info'
        event['user'] = ssh_ok.group(1)
        event['source_ip'] = ssh_ok.group(2)
        event['port'] = ssh_ok.group(3)
        return event

    # sudo commands
    sudo = SUDO_PATTERN.search(message)
    if sudo and 'sudo' in app.lower():
        event['event_type'] = 'sudo_command'
        event['severity'] = 'info'
        event['user'] = sudo.group(1)
        event['command'] = sudo.group(2).strip()
        return event

    # sudo failures — someone trying stuff they shouldn't
    sudo_fail = SUDO_FAIL_PATTERN.search(message)
    if sudo_fail:
        event['event_type'] = 'sudo_failure'
        event['severity'] = 'warning'
        event['user'] = sudo_fail.group(1)
        return event

    return event


def parse_access_line(line):
    """parse an apache/nginx combined log line"""
    m = ACCESS_LOG_PATTERN.match(line.strip())
    if not m:
        return None

    groups = m.groups()
    status = int(groups[7])

    # severity based on status code — simple but effective
    if status >= 500:
        severity = 'critical'
    elif status >= 400:
        severity = 'warning'
    else:
        severity = 'info'

    event = {
        'source_ip': groups[0],
        'ident': groups[1],
        'auth_user': groups[2],
        'timestamp': groups[3],
        'method': groups[4],
        'path': groups[5],
        'protocol': groups[6],
        'status': status,
        'bytes': int(groups[8]) if groups[8] != '-' else 0,
        'referer': groups[9] if groups[9] else '-',
        'user_agent': groups[10] if groups[10] else '-',
        'severity': severity,
        'event_type': 'http_request',
        'raw': line.strip()
    }

    return event


def parse_log_file(raw_text, log_type=None):
    """
    parse a whole log file and return list of event dicts
    auto-detects type if not specified
    """
    if log_type is None:
        log_type = detect_log_type(raw_text)

    lines = raw_text.strip().split('\n')
    events = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if log_type == 'access':
            event = parse_access_line(line)
        else:
            # default to syslog parser — handles auth.log too
            event = parse_syslog_line(line)

        if event:
            event['log_type'] = log_type
            events.append(event)

    return events
