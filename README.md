# 🛡️ Lightweight Ransomware Detector

A resource-efficient **Cyber Security** tool designed to detect and mitigate ransomware activity in real-time. This Python script monitors a target directory, distinguishing between legitimate user modifications and malicious encryption attempts based on content analysis and statistical heuristics.

## 🚀 Key Features

### 🧠 Intelligent Detection Logic
The tool differentiates between "Human" edits and "Malware" encryption using:
* **Entropy Analysis:** Detects high randomness typical of encrypted data (Shannon Entropy).
* **Character Distribution:** Identifies sudden shifts from standard ASCII text to binary/non-printable characters.
* **Keyword Scanning:** Checks for common ransomware signatures or ransom notes (e.g., "encrypted", "pay").

### ⚡ Performance & Efficiency
* **Low Memory Footprint:** Optimized to run with minimal RAM usage (aiming for $O(1)$ regarding metadata storage where possible).
* **Fast Processing:** Analyze files on-the-fly without heavy overhead on the host system.

### 🔒 Active Defense
* **Quarantine Mechanism:** Automatically moves suspicious files to a secure `quarantine/` folder to prevent further spread or damage.
* **Logging:** Records all suspicious events to `suspicious_log.csv` for forensic analysis.

## 📂 Project Structure

```text
├── Ransomare_script/
│   ├── script.py               # Main detection engine
│   ├── test_files/             # Simulation environment
│   │   ├── normal.txt          # Benign file
│   │   ├── misleading.txt      # Benign file with unusual patterns (Edge case)
│   │   ├── base64_sample.txt   # High entropy test case
│   │   └── quarantine/         # Isolated threats
│   └── suspicious_log.csv      # Event logs
└── README.md
