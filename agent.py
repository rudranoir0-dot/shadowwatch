# ShadowWatch - Behavioral Anomaly Detector
# Core Agent - learns and monitors user behavior
# Author: rudranoir0-dot

import time
import json
import os
import psutil
from pynput import keyboard, mouse
from datetime import datetime
import threading

# Data storage
behavior_data = {
    "keystrokes": [],
    "mouse_clicks": [],
    "active_hours": [],
    "processes": [],
    "typing_speed": []
}

baseline = {}
keystroke_times = []
last_keystroke = None
alert_count = 0

BASELINE_FILE = "baseline.json"
LOG_FILE = "shadowwatch_log.txt"

def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def on_key_press(key):
    global last_keystroke, keystroke_times
    now = time.time()
    current_hour = datetime.now().hour
    if current_hour not in behavior_data["active_hours"]:
        behavior_data["active_hours"].append(current_hour)
    if last_keystroke:
        gap = now - last_keystroke
        keystroke_times.append(gap)
        if len(keystroke_times) > 100:
            keystroke_times.pop(0)
    last_keystroke = now

def on_click(x, y, button, pressed):
    if pressed:
        behavior_data["mouse_clicks"].append({
            "x": x,
            "y": y,
            "time": time.time()
        })

def get_running_processes():
    processes = []
    for proc in psutil.process_iter(['name']):
        try:
            processes.append(proc.info['name'])
        except:
            pass
    return list(set(processes))

def calculate_avg_typing_speed():
    if len(keystroke_times) < 5:
        return None
    return sum(keystroke_times) / len(keystroke_times)

def save_baseline():
    global baseline
    avg_speed = calculate_avg_typing_speed()
    baseline = {
        "avg_typing_gap": avg_speed,
        "active_hours": behavior_data["active_hours"],
        "typical_processes": get_running_processes(),
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
    current_hour = datetime.now().hour
    avg_speed = calculate_avg_typing_speed()

    if baseline.get("active_hours"):
        if current_hour not in baseline["active_hours"]:
            alerts.append(f"UNUSUAL TIME - activity at hour {current_hour}, not in normal pattern")

    if avg_speed and baseline.get("avg_typing_gap"):
        baseline_speed = baseline["avg_typing_gap"]
        deviation = abs(avg_speed - baseline_speed) / baseline_speed * 100
        if deviation > 50:
            alerts.append(f"TYPING ANOMALY - current gap {avg_speed:.3f}s vs baseline {baseline_speed:.3f}s ({deviation:.1f}% deviation)")

    current_processes = get_running_processes()
    if baseline.get("typical_processes"):
        new_processes = set(current_processes) - set(baseline["typical_processes"])
        suspicious = [p for p in new_processes if any(s in p.lower() for s in 
                     ["hack", "crack", "keylog", "spy", "rat", "trojan", "wireshark", "nmap"])]
        if suspicious:
            alerts.append(f"SUSPICIOUS PROCESS - {', '.join(suspicious)}")

    if alerts:
        alert_count += 1
        log(f"\n{'='*50}")
        log(f"[!!!] ANOMALY DETECTED - Alert #{alert_count}")
        for alert in alerts:
            log(f"  >> {alert}")
        log(f"{'='*50}\n")
    else:
        log("Behavior normal - no anomalies detected")

def monitor_loop():
    while True:
        time.sleep(30)
        if baseline:
            detect_anomalies()

def start_listeners():
    kb_listener = keyboard.Listener(on_press=on_key_press)
    ms_listener = mouse.Listener(on_click=on_click)
    kb_listener.start()
    ms_listener.start()

print("=" * 50)
print("   SHADOWWATCH - BEHAVIORAL ANOMALY DETECTOR")
print("=" * 50)

baseline_exists = load_baseline()

if not baseline_exists:
    print("\nNo baseline found. Learning mode activated.")
    print("Use this machine normally for 2 minutes.")
    print("ShadowWatch is watching and learning...\n")
    start_listeners()
    time.sleep(120)
    save_baseline()
    print("\nLearning complete. Now switching to monitor mode.\n")
else:
    print("\nBaseline loaded. Monitor mode active.")
    print("Watching for anomalies every 30 seconds...\n")
    start_listeners()

monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
monitor_thread.start()

print("ShadowWatch is running. Press Ctrl+C to stop.\n")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    log("ShadowWatch stopped by user")
    print("\nShadowWatch stopped.")