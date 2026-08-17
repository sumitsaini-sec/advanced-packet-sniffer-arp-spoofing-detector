# Internship Project Report
## Advanced Packet Sniffer + ARP Spoofing Detector

### 1. Objective
The objective is to build a defensive network-monitoring tool that captures packets, identifies common protocols, monitors ARP traffic, detects suspicious IP-to-MAC changes, and records security events.

### 2. Problem Statement
ARP spoofing can manipulate IP-to-MAC relationships on a local network. Monitoring ARP traffic and maintaining an IP-to-MAC baseline can help identify suspicious changes.

### 3. Technologies
- Python 3
- Scapy
- Linux
- JSON
- Python logging

### 4. Methodology
The tool captures packets from an authorized interface using Scapy. Packets are parsed to identify protocol, source, destination and useful protocol details. ARP packets are separately inspected. The detector stores the first observed MAC address for an IP and generates a HIGH severity alert if the same IP is later observed with another MAC address.

### 5. Detection Logic
IP → MAC baseline. If a known IP is observed with a different MAC address, the tool generates an alert, records the timestamp and old/new MAC values, writes the event to `logs/alerts.log`, and includes it in the JSON report.

### 6. Logging
Packet events are written to `logs/packets.log`. Detection events are written to `logs/alerts.log`. A session summary is exported as JSON.

### 7. Security / Ethical Scope
The project is designed for passive monitoring and defensive detection. It does not send ARP poisoning packets. Testing must be performed only on an owned or explicitly authorized network.

### 8. Results
The expected result is a working packet monitor capable of displaying packet information, maintaining ARP mappings, generating alerts for IP/MAC conflicts, and producing a machine-readable session report.

### 9. Limitations
A changed MAC address does not always mean an attack. Legitimate network changes can cause the same condition, so alerts should be correlated with other telemetry.

### 10. Future Scope
Integration with SIEM platforms such as Splunk/Wazuh, PCAP storage, a dashboard, database storage, severity scoring, and baseline learning can improve the project.
