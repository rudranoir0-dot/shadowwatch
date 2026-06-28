# ShadowWatch - Behavioral Anomaly Detector v2
# Deep Behavioral Engine
# Author: rudranoir0-dot

import time
import json
import os
import psutil
import threading
import subprocess
from pynput import keyboard, mouse
from datetime import datetime

# Global state
keystroke_times = []
last_keystroke = None
mouse_movements = []
last_mouse_pos = None
mouse_speeds = []
click_positions = []
app_usage = []
alert_count = 0
baseline = {}

BASELINE_FILE = "baseline.json"
LOG_FILE = "shadowwatch_log.txt"
MAX_ALERTS_BEFORE_LOCKDOWN = 3

def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def lockdown():
    log("[!!!] LOCKDOWN INITIATED - Too many anomalies detected")
    log("[!!!] Locking workstation...")
    subprocess.run(["rundll32.exe", "user32.dll,LockWorkStation"])

def on_key_press(key):
    global last_keystroke
    now = time.time()
    current_hour = datetime.now().hour
    if last_keystroke:
        gap = now - last_keystroke
        if gap < 5:
            keystroke_times.append(gap)
            if len(keystroke_times) > 200:
                keystroke_times.pop(0)
    last_keystroke = now

def on_move(x, y):
    global last_mouse_pos
    now = time.time()
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
        if len(click_positions) > 100:
            click_positions.pop(0)

def get_active_apps():
    apps = []
    for proc in psutil.process_iter(['name', 'status']):
        try:
            if proc.info['status'] == 'running':
                apps.append(proc.info['name'])
        except:
            pass
    return list(set(apps))

def get_cpu_usage():
    return psutil.cpu_percent(interval=1)

def get_memory_usage():
    return psutil.virtual_memory().percent

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
    avg_typing = calculate_avg(keystroke_times)
    avg_mouse = calculate_avg(mouse_speeds)
    current_hour = datetime.now().hour
    baseline = {
        "avg_typing_gap": avg_typing,
        "avg_mouse_speed": avg_mouse,
        "active_hours": [current_hour],
        "typical_apps": get_active_apps(),
        "avg_cpu": get_cpu_usage(),
        "avg_memory": get_memory_usage(),
        "recorded_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)
    log("Baseline saved successfully")
    log(f"  Typing gap: {avg_typing:.3f}s" if avg_typing else "  Typing gap: insufficient data")
    log(f"  Mouse speed: {avg_mouse:.1f}px/move" if avg_mouse else "  Mouse speed: insufficient data")
    log(f"  Active hour: {current_hour}:00")
    log(f"  Apps tracked: {len(baseline['typical_apps'])}")

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
            alerts.append(f"TYPING ANOMALY - {dev:.1f}% deviation from baseline")
            risk_score += 30

    avg_mouse = calculate_avg(mouse_speeds)
    if avg_mouse and baseline.get("avg_mouse_speed"):
        dev = calculate_deviation(avg_mouse, baseline["avg_mouse_speed"])
        if dev > 60:
            alerts.append(f"MOUSE ANOMALY - {dev:.1f}% deviation from baseline")
            risk_score += 25

    current_apps = set(get_active_apps())
    baseline_apps = set(baseline.get("typical_apps", []))
    suspicious_new = [a for a in current_apps - baseline_apps
                     if any(s in a.lower() for s in
                     ["hack", "crack", "keylog", "spy", "rat",
                      "wireshark", "nmap", "metasploit", "burp"])]
    if suspicious_new:
        alerts.append(f"SUSPICIOUS APPS - {', '.join(suspicious_new)}")
        risk_score += 50

    cpu = get_cpu_usage()
    if cpu > 90:
        alerts.append(f"HIGH CPU - {cpu}% usage, possible crypto mining or attack tool")
        risk_score += 15

    if alerts:
        alert_count += 1
        log(f"\n{'='*55}")
        log(f"[!!!] ANOMALY DETECTED - Alert #{alert_count} | Risk Score: {risk_score}/100")
        for alert in alerts:
            log(f"  >> {alert}")
        log(f"{'='*55}\n")
        if alert_count >= MAX_ALERTS_BEFORE_LOCKDOWN:
            lockdown()
    else:
        log(f"Behavior normal - Risk Score: {risk_score}/100")

def monitor_loop():
    while True:
        time.sleep(30)
        if baseline:
            detect_anomalies()

def start_listeners():
    kb_listener = keyboard.Listener(on_press=on_key_press)
    ms_listener = mouse.Listener(on_click=on_click, on_move=on_move)
    kb_listener.start()
    ms_listener.start()

print("=" * 55)
print("   SHADOWWATCH v2 - BEHAVIORAL ANOMALY DETECTOR")
print("=" * 55)

baseline_exists = load_baseline()

if not baseline_exists:
    print("\nNo baseline found. Learning mode activated.")
    print("Use this machine normally for 2 minutes.")
    print("Type, click, move mouse, open apps...\n")
    start_listeners()
    time.sleep(120)
    save_baseline()
    print("\nLearning complete. Switching to monitor mode.\n")
else:
    print("\nBaseline loaded. Monitor mode active.")
    print(f"Lockdown triggers after {MAX_ALERTS_BEFORE_LOCKDOWN} anomalies.")
    print("Checking behavior every 30 seconds...\n")
    start_listeners()

monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
monitor_thread.start()

log("ShadowWatch v2 active")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    log("ShadowWatch stopped by user")
    print("\nShadowWatch stopped.")