# ShadowWatch

A behavioral anomaly detection system that learns your normal computer 
usage patterns and detects impostors in real time.

## How it works

ShadowWatch builds a behavioral fingerprint of the real user by monitoring:
- Typing speed and rhythm
- Mouse movement patterns
- Active hours and time of use
- Running processes and applications
- CPU usage anomalies

If someone else uses the machine with different behavioral patterns,
ShadowWatch detects it instantly and triggers alerts.

## Features

- Real-time behavioral monitoring
- Risk scoring system (0-100)
- Auto lockdown after 3 anomalies
- Professional PDF report generation
- Live web dashboard with event log
- Risk score history visualization

## Setup

Install dependencies:
pip install pynput psutil reportlab flask flask-socketio

## Usage

Step 1 - Run the agent (learning + monitoring):
python agent.py

First run learns your behavior for 2 minutes, then switches to monitor mode.
Press Ctrl+C to stop and generate a PDF report.

Step 2 - Run the web dashboard:
python server.py

Open http://localhost:5000 to see live monitoring data.

## Dashboard

- Total anomalies detected
- Normal behavior checks
- Average risk score
- Threat level (LOW / MEDIUM / HIGH)
- Live color-coded event log
- Risk score history bars
- Downloadable PDF reports

## Example Output
SHADOWWATCH v3 - BEHAVIORAL ANOMALY DETECTOR
Baseline loaded. Monitor mode active.
[!!!] ANOMALY DETECTED - Alert #1 | Risk: 25/100


MOUSE ANOMALY - 113.8% deviation from baseline

TYPING ANOMALY - 68.2% deviation from baseline



## Author

rudranoir0-dot | CSE Cyber Security |