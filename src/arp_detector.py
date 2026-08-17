from pathlib import Path
from datetime import datetime
from scapy.all import ARP

class ARPSpoofDetector:
    """Defensive IP-to-MAC change detector; it does not send spoofing packets."""
    def __init__(self, alerts, log_dir="logs"):
        self.mapping = {}
        self.alerts = alerts
        self.log_file = Path(log_dir) / "alerts.log"
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def inspect(self, pkt):
        if ARP not in pkt:
            return None
        arp = pkt[ARP]
        ip = arp.psrc
        mac = arp.hwsrc.lower()
        if not ip or ip == "0.0.0.0":
            return None
        old_mac = self.mapping.get(ip)
        if old_mac is None:
            self.mapping[ip] = mac
            return None
        if old_mac != mac:
            alert = {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "severity": "HIGH",
                "ip": ip,
                "old_mac": old_mac,
                "new_mac": mac,
                "reason": "One IP address was observed with multiple MAC addresses"
            }
            self.alerts.append(alert)
            with self.log_file.open("a", encoding="utf-8") as f:
                f.write(str(alert) + "\n")
            self.mapping[ip] = mac
            return alert
        return None
