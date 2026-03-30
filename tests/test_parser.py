"""
tests for the log parser
covers syslog, auth.log ssh events, and access log parsing
run with: pytest tests/test_parser.py -v
"""

import sys
import os

# add project root to path so imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.parser import (
    parse_syslog_line,
    parse_access_line,
    parse_log_file,
    detect_log_type,
)


class TestSyslogParser:
    """test the syslog/auth.log line parser"""

    def test_basic_syslog_line(self):
        line = 'Jan 15 08:23:01 webserver sshd[12041]: some message here'
        result = parse_syslog_line(line)
        assert result is not None
        assert result['hostname'] == 'webserver'
        assert result['app'] == 'sshd'
        assert result['pid'] == '12041'
        assert result['message'] == 'some message here'

    def test_ssh_failed_password(self):
        line = 'Jan 15 08:23:01 webserver sshd[12041]: Failed password for invalid user admin from 192.168.1.100 port 54312'
        result = parse_syslog_line(line)
        assert result is not None
        assert result['event_type'] == 'ssh_failed'
        assert result['severity'] == 'warning'
        assert result['user'] == 'admin'
        assert result['source_ip'] == '192.168.1.100'
        assert result['port'] == '54312'

    def test_ssh_accepted(self):
        line = 'Jan 15 08:24:15 webserver sshd[12050]: Accepted password for vikrant from 10.0.0.5 port 49812'
        result = parse_syslog_line(line)
        assert result is not None
        assert result['event_type'] == 'ssh_success'
        assert result['user'] == 'vikrant'
        assert result['source_ip'] == '10.0.0.5'

    def test_sudo_command(self):
        line = 'Jan 15 08:25:02 webserver sudo[12055]: vikrant : TTY=pts/0 ; PWD=/home/vikrant ; USER=root ; COMMAND=/usr/bin/apt update'
        result = parse_syslog_line(line)
        assert result is not None
        assert result['event_type'] == 'sudo_command'
        assert result['user'] == 'vikrant'

    def test_malformed_line_returns_none(self):
        result = parse_syslog_line('this is not a log line at all')
        assert result is None

    def test_empty_line(self):
        result = parse_syslog_line('')
        assert result is None


class TestAccessLogParser:
    """test apache/nginx combined log format parser"""

    def test_basic_access_line(self):
        line = '192.168.1.50 - - [15/Jan/2025:10:30:22 +0000] "GET /index.html HTTP/1.1" 200 5123 "-" "Mozilla/5.0"'
        result = parse_access_line(line)
        assert result is not None
        assert result['source_ip'] == '192.168.1.50'
        assert result['method'] == 'GET'
        assert result['path'] == '/index.html'
        assert result['status'] == 200
        assert result['severity'] == 'info'

    def test_404_is_warning(self):
        line = '10.0.0.1 - - [15/Jan/2025:10:30:22 +0000] "GET /nonexistent HTTP/1.1" 404 0 "-" "curl/7.68"'
        result = parse_access_line(line)
        assert result is not None
        assert result['status'] == 404
        assert result['severity'] == 'warning'

    def test_500_is_critical(self):
        line = '10.0.0.1 - - [15/Jan/2025:10:30:22 +0000] "POST /api/data HTTP/1.1" 500 0 "-" "Python-urllib/3.9"'
        result = parse_access_line(line)
        assert result is not None
        assert result['status'] == 500
        assert result['severity'] == 'critical'

    def test_malformed_access_line(self):
        result = parse_access_line('not an access log')
        assert result is None


class TestLogTypeDetection:
    """test automatic log format detection"""

    def test_detects_syslog(self):
        text = """Jan 15 08:23:01 webserver sshd[12041]: Failed password for root from 1.2.3.4 port 22
Jan 15 08:23:02 webserver sshd[12042]: Failed password for root from 1.2.3.4 port 22"""
        assert detect_log_type(text) == 'syslog'

    def test_detects_access_log(self):
        text = """192.168.1.1 - - [15/Jan/2025:10:30:22 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.2 - - [15/Jan/2025:10:30:23 +0000] "GET /style.css HTTP/1.1" 200 567 "-" "Mozilla/5.0" """
        assert detect_log_type(text) == 'access'


class TestParseLogFile:
    """integration test — parse a whole file"""

    def test_parse_auth_log_sample(self):
        sample_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'sample_logs', 'auth.log.sample'
        )
        if not os.path.exists(sample_path):
            return  # skip if sample not available

        with open(sample_path) as f:
            raw = f.read()

        events = parse_log_file(raw, 'syslog')
        assert len(events) > 0

        # should have some ssh failures in there
        failed = [e for e in events if e['event_type'] == 'ssh_failed']
        assert len(failed) >= 5, "sample should have multiple ssh failures"

        # and some successes
        success = [e for e in events if e['event_type'] == 'ssh_success']
        assert len(success) >= 1

    def test_empty_input(self):
        events = parse_log_file('', 'syslog')
        assert events == []


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])
