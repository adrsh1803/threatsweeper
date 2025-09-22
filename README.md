# ThreatSweeper 🛡️

A Python-based malware detection tool with:
- **Signature-based scanning** (hashes/patterns)
- **VirusTotal API integration**
- **GUI for ease of use**
## Features
- 🔍 Hybrid detection (local + cloud)
- 🎨 Hacker-style terminal output
- 📊 Detailed threat reports
- 🚦 Real-time scanning

## Installation
```bash
git clone https://github.com/yourusername/ThreatSweeper.git
cd ThreatSweeper
pip install -r requirements.txt
```
Usage

```bash
python scanner_gui.py
```
1)Click "Scan File"

2)Select any executable/document

3)View the threat report

## Configuration
Get a VirusTotal API key from https://www.virustotal.com/

Add to config.ini:
```
[VIRUSTOTAL]
api_key = YOUR_API_KEY
```
