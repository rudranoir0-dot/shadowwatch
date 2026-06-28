# ShadowWatch - Behavioral Anomaly Detector v3
# Deep Behavioral Engine + PDF Report Generator
# Author: rudranoir0-dot

import time
import json
import os
import psutil
import threading
import subprocess
from pynput import keyboard, mouse
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

# Global state
keystroke_times = []
last_keystroke = None
mouse_speeds = []
last_mouse_pos = None
click_positions = []
alert_count = 0
baseline = {}
session_start = datetime.now()
session_events = []
all_risk_scores = []

BASELINE_FILE = "baseline.json"
LOG_FILE = "shadowwatch_log.txt"
MAX_ALERTS = 3

def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")
    session_events.append({"time": timestamp, "message": message})

def generate_pdf_report():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"shadowwatch_report_{timestamp}.pdf"
    session_end = datetime.now()
    duration = session_end - session_start
    duration_str = str(duration).split(".")[0]

    doc = SimpleDocTemplate(filename, pagesize=A4,
                           rightMargin=inch, leftMargin=inch,
                           topMargin=inch, bottomMargin=inch)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('title', parent=styles['Title'],
                                fontSize=24, textColor=colors.HexColor('#1a1a2e'),
                                spaceAfter=6)
    heading_style = ParagraphStyle('heading', parent=styles['Heading2'],
                                  fontSize=14, textColor=colors.HexColor('#16213e'),
                                  spaceBefore=12, spaceAfter=6)
    normal_style = styles['Normal']
    normal_style.fontSize = 11

    content = []

    content.append(Paragraph("SHADOWWATCH", title_style))
    content.append(Paragraph("Behavioral Anomaly Detection Report", styles['Heading2']))
    content.append(Spacer(1, 0.2*inch))

    avg_risk = sum(all_risk_scores) / len(all_risk_scores) if all_risk_scores else 0
    if avg_risk >= 50:
        threat_level = "HIGH"
        threat_color = colors.red
    elif avg_risk >= 25:
        threat_level = "MEDIUM"
        threat_color = colors.orange
    else:
        threat_level = "LOW"
        threat_color = colors.green

    summary_data = [
        ["Field", "Value"],
        ["Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Session Started", session_start.strftime("%Y-%m-%d %H:%M:%S")],
        ["Session Duration", duration_str],
        ["Total Anomalies", str(alert_count)],
        ["Average Risk Score", f"{avg_risk:.1f}/100"],
        ["Threat Level", threat_level],
        ["Checks Performed", str(len(all_risk_scores))],
    ]

    summary_table = Table(summary_data, colWidths=[2.5*inch, 3.5*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1),
         [colors.HexColor('#f8f9fa'), colors.white]),
        ('TEXTCOLOR', (0, 1), (0, -1), colors.HexColor('#16213e')),
        ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 1), (-1, -1), 11),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('ROWBACKGROUNDS', (0, 6), (-1, 6), [threat_color]),
        ('TEXTCOLOR', (0, 6), (-1, 6), colors.white),
        ('FONTNAME', (0, 6), (-1, 6), 'Helvetica-Bold'),
    ]))

    content.append(Paragraph("Session Summary", heading_style))
    content.append(summary_table)
    content.append(Spacer(1, 0.3*inch))

    if baseline:
        content.append(Paragraph("Behavioral Baseline", heading_style))
        baseline_data = [["Metric", "Baseline Value"]]
        if baseline.get("avg_typing_gap"):
            baseline_data.append(["Avg Typing Gap",
                                  f"{baseline['avg_typing_gap']:.3f} seconds"])
        if baseline.get("avg_mouse_speed"):
            baseline_data.append(["Avg Mouse Speed",
                                  f"{baseline['avg_mouse_speed']:.1f} px/move"])
        baseline_data.append(["Active Hours",
                              str(baseline.get("active_hours", []))])
        baseline_data.append(["Apps Tracked",
                              str(len(baseline.get("typical_apps", [])))])
        baseline_data.append(["Baseline Recorded",
                              baseline.get("recorded_at", "N/A")])

        baseline_table = Table(baseline_data, colWidths=[2.5*inch, 3.5*inch])
        baseline_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f3460')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
             [colors.HexColor('#e8f4f8'), colors.white]),
        ]))
        content.append(baseline_table)
        content.append(Spacer(1, 0.3*inch))

    content.append(Paragraph("Event Log", heading_style))
    anomaly_events = [e for e in session_events if "ANOMALY" in e["message"]
                     or "normal" in e["message"] or "Risk" in e["message"]]

    if anomaly_events:
        event_data = [["Timestamp", "Event"]]
        for event in anomaly_events[-20:]:
            msg = event["message"][:70]
            event_data.append([event["time"], msg])

        event_table = Table(event_data, colWidths=[2*inch, 4*inch])
        event_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
             [colors.HexColor('#fff3cd'), colors.white]),
        ]))
        content.append(event_table)
    else:
        content.append(Paragraph("No anomaly events recorded.",
                                normal_style))

    content.append(Spacer(1, 0.3*inch))
    content.append(Paragraph("─" * 70, normal_style))
    content.append(Paragraph(
        "Generated by ShadowWatch v3 | rudranoir0-dot | CSE Cyber Security | Parul University",
        ParagraphStyle('footer', parent=styles['Normal'],
                      fontSize=9, textColor=colors.grey)))

    doc.build(content)
    log(f"PDF report saved: {filename}")
    return filename

def lockdown():
    log("[!!!] LOCKDOWN INITIATED - Too many anomalies")
    generate_pdf_report()
    subprocess.run(["rundll32.exe", "user32.dll,LockWorkStation"])

def on_key_press(key):
    global last_keystroke
    now = time.time()
    if last_keystroke:
        gap = now - last_keystroke
        if gap < 5:
            keystroke_times.append(gap)
            if len(keystroke_times) > 200:
                keystroke_times.pop(0)
    last_keystroke = now

def on_move(x, y):
    global last_mouse_pos
    if last_mouse_pos:
        dx = x - last_mouse_pos[0]
        dy = y - last_mouse_pos[1]
        distance = (dx**2 + dy**2) ** 0.5
        if distance > 0:
            mouse_speeds.append(distance)
            if len(mouse_speeds) > 200:
                mouse_speeds.pop(0)
    last_mouse_pos = (x, y)

def on_click(x, y, button, pressed):
    if pressed:
        click_positions.append((x, y))

def get_active_apps():
    apps = []
    for proc in psutil.process_iter(['name', 'status']):
        try:
            if proc.info['status'] == 'running':
                apps.append(proc.info['name'])
        except:
            pass
    return list(set(apps))

def calculate_avg(data):
    if len(data) < 5:
        return None
    return sum(data) / len(data)

def calculate_deviation(current, baseline_val):
    if not baseline_val or baseline_val == 0:
        return 0
    return abs(current - baseline_val) / baseline_val * 100

def save_baseline():
    global baseline
    baseline = {
        "avg_typing_gap": calculate_avg(keystroke_times),
        "avg_mouse_speed": calculate_avg(mouse_speeds),
        "active_hours": [datetime.now().hour],
        "typical_apps": get_active_apps(),
        "avg_cpu": psutil.cpu_percent(interval=1),
        "recorded_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)
    log("Baseline saved successfully")

def load_baseline():
    global baseline
    if os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE, "r") as f:
            baseline = json.load(f)
        log(f"Baseline loaded - recorded at {baseline['recorded_at']}")
        return True
    return False

def detect_anomalies():
    global alert_count
    alerts = []
    risk_score = 0

    current_hour = datetime.now().hour
    if baseline.get("active_hours"):
        if current_hour not in baseline["active_hours"]:
            alerts.append(f"UNUSUAL TIME - activity at {current_hour}:00")
            risk_score += 20

    avg_typing = calculate_avg(keystroke_times)
    if avg_typing and baseline.get("avg_typing_gap"):
        dev = calculate_deviation(avg_typing, baseline["avg_typing_gap"])
        if dev > 50:
            alerts.append(f"TYPING ANOMALY - {dev:.1f}% deviation")
            risk_score += 30

    avg_mouse = calculate_avg(mouse_speeds)
    if avg_mouse and baseline.get("avg_mouse_speed"):
        dev = calculate_deviation(avg_mouse, baseline["avg_mouse_speed"])
        if dev > 60:
            alerts.append(f"MOUSE ANOMALY - {dev:.1f}% deviation")
            risk_score += 25

    current_apps = set(get_active_apps())
    baseline_apps = set(baseline.get("typical_apps", []))
    suspicious = [a for a in current_apps - baseline_apps
                 if any(s in a.lower() for s in
                 ["hack", "crack", "keylog", "spy",
                  "wireshark", "nmap", "metasploit", "burp"])]
    if suspicious:
        alerts.append(f"SUSPICIOUS APPS - {', '.join(suspicious)}")
        risk_score += 50

    cpu = psutil.cpu_percent(interval=1)
    if cpu > 90:
        alerts.append(f"HIGH CPU - {cpu}%")
        risk_score += 15

    all_risk_scores.append(risk_score)

    if alerts:
        alert_count += 1
        log(f"\n{'='*55}")
        log(f"[!!!] ANOMALY DETECTED - Alert #{alert_count} | Risk: {risk_score}/100")
        for alert in alerts:
            log(f"  >> {alert}")
        log(f"{'='*55}\n")
        if alert_count >= MAX_ALERTS:
            lockdown()
    else:
        log(f"Behavior normal - Risk Score: {risk_score}/100")

def monitor_loop():
    while True:
        time.sleep(30)
        if baseline:
            detect_anomalies()

def start_listeners():
    keyboard.Listener(on_press=on_key_press).start()
    mouse.Listener(on_click=on_click, on_move=on_move).start()

print("=" * 55)
print("   SHADOWWATCH v3 - BEHAVIORAL ANOMALY DETECTOR")
print("=" * 55)

baseline_exists = load_baseline()

if not baseline_exists:
    print("\nNo baseline found. Learning mode - 2 minutes.")
    print("Use the machine normally...\n")
    start_listeners()
    time.sleep(120)
    save_baseline()
    print("\nLearning complete. Monitor mode active.\n")
else:
    print(f"\nBaseline loaded. Monitoring active.")
    print(f"Lockdown after {MAX_ALERTS} anomalies.")
    print("PDF report generated on exit or lockdown.\n")
    start_listeners()

threading.Thread(target=monitor_loop, daemon=True).start()
log("ShadowWatch v3 active")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    log("ShadowWatch stopped by user")
    report = generate_pdf_report()
    print(f"\nReport saved: {report}")
    print("ShadowWatch stopped.")