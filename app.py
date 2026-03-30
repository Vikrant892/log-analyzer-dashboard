"""
log-analyzer-dashboard
lightweight siem thing i built because splunk costs more than my rent
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for
from werkzeug.utils import secure_filename
import os
import json
from analyzer.parser import parse_log_file, detect_log_type
from analyzer.detector import detect_threats
from analyzer.stats import compute_stats

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', os.urandom(32).hex())
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16mb should be plenty
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# in-memory store because i'm not dragging in sqlite for a dashboard
# TODO: maybe add sqlite later if logs get huge
parsed_events = []
alerts = []
current_stats = {}


@app.route('/')
def dashboard():
    """main dashboard view with charts and alert table"""
    return render_template('dashboard.html', alerts=alerts, stats=current_stats)


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """upload a log file for analysis"""
    if request.method == 'GET':
        return render_template('upload.html')

    if 'logfile' not in request.files:
        return render_template('upload.html', error='No file selected')

    f = request.files['logfile']
    if f.filename == '':
        return render_template('upload.html', error='No file selected')

    # save it temporarily
    filepath = os.path.join(UPLOAD_FOLDER, secure_filename(f.filename))
    f.save(filepath)

    try:
        raw_text = open(filepath, 'r', errors='ignore').read()
        log_type = detect_log_type(raw_text)
        events = parse_log_file(raw_text, log_type)

        # run threat detection on parsed events
        global parsed_events, alerts, current_stats
        parsed_events.extend(events)
        new_alerts = detect_threats(events)
        alerts.extend(new_alerts)
        current_stats = compute_stats(parsed_events, alerts)

        return redirect(url_for('dashboard'))
    except Exception as e:
        return render_template('upload.html', error=f'Parse error: {str(e)}')
    finally:
        # cleanup uploaded file
        if os.path.exists(filepath):
            os.remove(filepath)


@app.route('/alerts')
def alerts_view():
    """json dump of all alerts for the frontend"""
    return jsonify(alerts)


@app.route('/api/stats')
def api_stats():
    """stats endpoint for chart.js to consume"""
    return jsonify(current_stats)


@app.route('/api/upload', methods=['POST'])
def api_upload():
    """api endpoint for programmatic uploads — curl friendly"""
    if 'logfile' not in request.files:
        return jsonify({'error': 'no file provided'}), 400

    f = request.files['logfile']
    filepath = os.path.join(UPLOAD_FOLDER, secure_filename(f.filename))
    f.save(filepath)

    try:
        raw_text = open(filepath, 'r', errors='ignore').read()
        log_type = detect_log_type(raw_text)
        events = parse_log_file(raw_text, log_type)

        global parsed_events, alerts, current_stats
        parsed_events.extend(events)
        new_alerts = detect_threats(events)
        alerts.extend(new_alerts)
        current_stats = compute_stats(parsed_events, alerts)

        return jsonify({
            'status': 'ok',
            'events_parsed': len(events),
            'new_alerts': len(new_alerts),
            'log_type': log_type
        })
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


if __name__ == '__main__':
    # load sample logs on startup so the dashboard isn't empty
    sample_dir = os.path.join(os.path.dirname(__file__), 'sample_logs')
    if os.path.exists(sample_dir):
        for fname in os.listdir(sample_dir):
            fpath = os.path.join(sample_dir, fname)
            if os.path.isfile(fpath):
                raw = open(fpath, 'r', errors='ignore').read()
                ltype = detect_log_type(raw)
                evts = parse_log_file(raw, ltype)
                parsed_events.extend(evts)
                new = detect_threats(evts)
                alerts.extend(new)
        current_stats = compute_stats(parsed_events, alerts)
        print(f'[*] loaded {len(parsed_events)} events, {len(alerts)} alerts from sample logs')

    app.run(debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true', port=5000)
