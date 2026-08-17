# Advanced Packet Sniffer + ARP Spoofing Detector

A defensive cybersecurity internship project built with Python and Scapy.

## Features

- Passive packet capture
- TCP/UDP/ARP/ICMP/DNS identification
- Source/destination IP visibility
- Port information
- ARP IP-to-MAC mapping
- Detection of an IP appearing with multiple MAC addresses
- Security alerts
- Packet and alert logging
- JSON session reports
- Command-line interface

## Architecture

Network Interface → Scapy Packet Capture → Packet Analyzer → ARP Monitor → Anomaly Detection → Alert + Logging → JSON Report

## Requirements

- Python 3
- Linux recommended
- Root/sudo permission for packet capture
- Scapy

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r src/requirements.txt
```

## Run

```bash
ip addr
sudo ./venv/bin/python src/main.py -i eth0 -t 60
```

Use only an interface on a network you own or are explicitly authorized to monitor.

## Testing

Normal traffic can be used for a safe demonstration:

```bash
ping -c 4 1.1.1.1
curl -I https://example.com
```

ARP anomaly detection should be tested only in an isolated, authorized lab. The project is designed for passive detection and does not perform ARP poisoning.

## Project Structure

```text
src/
├── main.py
├── packet_analyzer.py
├── arp_detector.py
├── logger_setup.py
├── report_generator.py
└── requirements.txt

docs/
├── PROJECT_REPORT.md
└── Advanced_Packet_Sniffer_ARP_Detector_Final_Report_With_Screenshots.docx

evidence/
├── 01_packet_capture_session.png
├── 02_arp_spoof_detection.png
├── 03_session_summary.png
└── 04_logs_and_project_files.png
```
