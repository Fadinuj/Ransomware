import os
import time
import math
import shutil
import re
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import Counter

WATCHED_DIR = 'test_files'
QUARANTINE_DIR = os.path.join(WATCHED_DIR, "quarantine")
LOG_FILE = os.path.join(WATCHED_DIR, "suspicious_log.csv")
ENTROPY_THRESHOLD = 4.5
ASCII_RATIO_THRESHOLD = 0.8

os.makedirs(QUARANTINE_DIR, exist_ok=True)
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as f:
        f.write("timestamp,file_path,status,entropy,ascii_ratio\n")

# --- Detection Tools ---
def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())

def is_base64_like(text):
    return bool(re.search(r"[A-Za-z0-9+/]{16,}={0,2}", text))

def calculate_ascii_ratio(data: bytes) -> float:
    ascii_count = sum(32 <= b <= 126 or b in (9, 10, 13) for b in data)
    return ascii_count / len(data) if data else 0

def contains_keywords(text):
    keywords = ["ENCRYPTED", "LOCKED", "KEY", "PAYLOAD", "BEGIN"]
    return any(word in text for word in keywords)

# --- Logging ---
def log_suspicious(file_path, entropy, ascii_ratio, status):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now().isoformat()},{file_path},{status},{entropy:.2f},{ascii_ratio:.2f}\n")
    print(f"[LOG] {status.upper()} → {file_path} | entropy={entropy:.2f}, ascii_ratio={ascii_ratio:.2f}")

# --- Quarantine ---
def quarantine_file(file_path):
    fname = os.path.basename(file_path)
    qpath = os.path.join(QUARANTINE_DIR, fname)
    shutil.copy(file_path, qpath)
    print(f"[!!] Suspicious file copied to quarantine: {qpath}")

# --- File Scanning ---
def scan_file(file_path):
    if "suspicious_log.csv" in file_path or "quarantine" in file_path:
        return  # Skip log and quarantine

    try:
        with open(file_path, "rb") as f:
            data = f.read(4096)
    except Exception as e:
        print(f"[!] Error reading file: {file_path} – {e}")
        return

    entropy = calculate_entropy(data)
    ascii_ratio = calculate_ascii_ratio(data)
    decoded = data.decode(errors="ignore")
    base64_suspect = is_base64_like(decoded)
    keyword_suspect = contains_keywords(decoded)

    suspicious_score = 0
    if entropy > ENTROPY_THRESHOLD: suspicious_score += 1
    if ascii_ratio < ASCII_RATIO_THRESHOLD: suspicious_score += 1
    if base64_suspect: suspicious_score += 1
    if keyword_suspect: suspicious_score += 1

    if suspicious_score >= 2:
        log_suspicious(file_path, entropy, ascii_ratio, "suspicious")
        quarantine_file(file_path)
    else:
        log_suspicious(file_path, entropy, ascii_ratio, "clean")

# --- Watchdog Monitoring ---
class MonitorHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            scan_file(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            scan_file(event.src_path)

# --- Start Monitoring ---
if __name__ == "__main__":
    print(f"[*] Monitoring started: {WATCHED_DIR}")
    observer = Observer()
    observer.schedule(MonitorHandler(), path=WATCHED_DIR, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
