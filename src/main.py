#!/usr/bin/env python3
import argparse
import json
import time
from collections import Counter
from datetime import datetime
from scapy.all import sniff, ARP
from arp_detector import ARPSpoofDetector
from logger_setup import setup_logger
from packet_analyzer import analyze_packet
from report_generator import save_report

class Monitor:
    def __init__(self, interface, duration, log_dir="logs"):
        self.interface = interface
        self.duration = duration
        self.start_time = datetime.now()
        self.packet_count = 0
        self.protocols = Counter()
        self.alerts = []
        self.arp_detector = ARPSpoofDetector(self.alerts, log_dir)
        self.logger = setup_logger(log_dir)

    def show_banner(self):
        print("\n╔══════════════════════════════════════════════════════╗\n║     ADVANCED PACKET SNIFFER + ARP SPOOF DETECTOR    ║\n║                    Scapy Edition                    ║\n╚══════════════════════════════════════════════════════╝")
        print(f"Interface : {self.interface or 'auto'}")
        print(f"Duration  : {self.duration}s")
        print("Mode      : Passive monitoring / detection")
        print("-" * 58)

    def handle_packet(self, pkt):
        self.packet_count += 1
        info = analyze_packet(pkt)
        self.protocols[info["protocol"]] += 1
        self.logger.info("PACKET %s", json.dumps(info, default=str))
        if ARP in pkt:
            alert = self.arp_detector.inspect(pkt)
            if alert:
                print_alert(alert)
        if self.packet_count <= 25:
            print_packet(info)

    def run(self):
        self.show_banner()
        start = time.time()
        try:
            sniff(iface=self.interface if self.interface else None, prn=self.handle_packet, store=False, timeout=self.duration)
        except PermissionError:
            print("\n[!] Permission denied. Run with sudo.")
            return
        except Exception as e:
            print(f"\n[!] Capture error: {e}")
            return
        elapsed = max(time.time() - start, 0.01)
        report = {"project": "Advanced Packet Sniffer + ARP Spoofing Detector", "start_time": self.start_time.isoformat(), "end_time": datetime.now().isoformat(), "interface": self.interface or "auto", "duration_seconds": round(elapsed, 2), "packets_captured": self.packet_count, "protocol_statistics": dict(self.protocols), "arp_alert_count": len(self.alerts), "alerts": self.alerts}
        path = save_report(report)
        print("\n" + "=" * 58 + "\nSESSION SUMMARY\n" + "=" * 58)
        print(f"Packets captured : {self.packet_count}")
        for p, n in self.protocols.most_common(): print(f"{p:16}: {n}")
        print(f"ARP alerts       : {len(self.alerts)}")
        print(f"Report           : {path}")
        print("Logs             : logs/packets.log and logs/alerts.log")

def print_packet(info):
    print(f"[{info['timestamp']}] {info['protocol']:<5} {info.get('src','-'):<22} -> {info.get('dst','-'):<22} {info.get('details','')}")

def print_alert(alert):
    print("\n" + "!" * 58 + "\nSECURITY ALERT - POSSIBLE ARP SPOOFING\n" + "!" * 58)
    print(f"Severity : {alert['severity']}\nIP       : {alert['ip']}\nOld MAC  : {alert['old_mac']}\nNew MAC  : {alert['new_mac']}\nReason   : {alert['reason']}")
    print("!" * 58 + "\n")

def main():
    parser = argparse.ArgumentParser(description="Passive packet sniffer and ARP spoofing detector")
    parser.add_argument("-i", "--interface", help="Interface, e.g. eth0/wlan0")
    parser.add_argument("-t", "--time", type=int, default=30, help="Capture duration in seconds")
    args = parser.parse_args()
    Monitor(args.interface, args.time).run()

if __name__ == "__main__":
    main()
