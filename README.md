# Automated Forensic Triage Collector

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-success)
![License](https://img.shields.io/badge/License-MIT-green)

## Overview

Automated Forensic Triage Collector is a Python-based DFIR (Digital Forensics and Incident Response) tool designed to quickly collect essential forensic artifacts from Windows systems.

The tool automates evidence collection during security incidents, helping investigators reduce manual effort while preserving valuable forensic data.

---

## Features

- Collects important Windows forensic artifacts
- System information collection
- Running processes
- Network configuration
- Active network connections
- User information
- Event logs
- Registry information
- Generates compressed ZIP archive
- Timestamped evidence collection
- Lightweight and easy to use

---

## Technologies Used

- Python
- OS Module
- Subprocess
- Shutil
- Zipfile
- Datetime

---

## Project Structure

```
automated-forensic-triage-collector/
│
├── automated_forensic_triage_collector.py
├── requirements.txt
├── README.md
└── LICENSE
```

---

## Installation

Clone the repository

```bash
git clone https://github.com/YourUsername/automated-forensic-triage-collector.git

cd automated-forensic-triage-collector
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

Run

```bash
python automated_forensic_triage_collector.py
```

The tool generates a timestamped ZIP archive containing collected forensic artifacts.

---

## Example Output

```
triage_collection_Asmit_20260731T154226Z.zip
```

---

## Use Cases

- Incident Response
- Digital Forensics
- Malware Investigation
- Security Audits
- Lab Practice
- Cybersecurity Learning

---

## Future Improvements

- Browser Artifact Collection
- Memory Dump Support
- Registry Hive Export
- Hash Generation
- Log Timeline Generation
- YARA Integration
- Volatility Integration
- GUI Version

---

## Disclaimer

This project is intended for educational purposes, authorized forensic investigations, and incident response activities only.

---

## Author

**Asmit**

Computer Engineering Student

Cybersecurity Enthusiast

---

## License

Licensed under the MIT License.