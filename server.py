# ShadowWatch - Web Dashboard Server
# Author: rudranoir0-dot

from flask import Flask, render_template, jsonify, send_file
from flask_socketio import SocketIO
import json
import os
import glob
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'shadowwatch_secret'
socketio = SocketIO(app)

LOG_FILE = "shadowwatch_log.txt"
BASELINE_FILE = "baseline.json"

def get_log_events():
    events = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
        for line in lines[-50:]:
            line = line.strip()
            if not line:
                continue
            if "ANOMALY" in line:
                event_type = "danger"
            elif "normal" in line:
                event_type = "success"
            elif "Baseline" in line or "loaded" in line:
                event_type = "info"
            elif "LOCKDOWN" in line:
                event_type = "critical"
            else:
                event_type = "info"
            events.append({"message": line, "type": event_type})
    return events

def get_baseline():
    if os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE, "r") as f:
            return json.load(f)
    return {}

def get_stats():
    events = get_log_events()
    anomalies = sum(1 for e in events if e["type"] == "danger")
    normal = sum(1 for e in events if e["type"] == "success")
    risk_scores = []
    for e in events:
        if "Risk Score:" in e["message"]:
            try:
                score = int(e["message"].split("Risk Score:")[1].split("/")[0].strip())
                risk_scores.append(score)
            except:
                pass
        elif "Risk:" in e["message"]:
            try:
                score = int(e["message"].split("Risk:")[1].split("/")[0].strip())
                risk_scores.append(score)
            except:
                pass
    avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
    if avg_risk >= 50:
        threat_level = "HIGH"
    elif avg_risk >= 25:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"
    return {
        "total_anomalies": anomalies,
        "normal_checks": normal,
        "avg_risk": round(avg_risk, 1),
        "threat_level": threat_level,
        "risk_scores": risk_scores[-20:]
    }

def get_reports():
    reports = glob.glob("shadowwatch_report_*.pdf")
    reports.sort(reverse=True)
    return reports

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/stats')
def stats():
    return jsonify(get_stats())

@app.route('/api/events')
def events():
    return jsonify(get_log_events())

@app.route('/api/baseline')
def baseline():
    return jsonify(get_baseline())

@app.route('/api/reports')
def reports():
    return jsonify(get_reports())

@app.route('/download/<filename>')
def download(filename):
    if filename.startswith("shadowwatch_report_") and filename.endswith(".pdf"):
        if os.path.exists(filename):
            return send_file(filename, as_attachment=True)
    return "File not found", 404

if __name__ == '__main__':
    print("=" * 55)
    print("   SHADOWWATCH - Web Dashboard")
    print("   Open: http://localhost:5000")
    print("=" * 55)
    socketio.run(app, debug=False, host='0.0.0.0', port=5000)
    