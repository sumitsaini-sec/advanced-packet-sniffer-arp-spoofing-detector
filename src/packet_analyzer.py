from datetime import datetime
from scapy.all import ARP, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR

def analyze_packet(pkt):
    result = {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "protocol": "OTHER", "src": "-", "dst": "-", "details": "", "length": len(pkt)}
    if ARP in pkt:
        result.update(protocol="ARP", src=pkt[ARP].psrc, dst=pkt[ARP].pdst)
        result["details"] = f"{'request' if pkt[ARP].op == 1 else 'reply'} {pkt[ARP].hwsrc} -> {pkt[ARP].hwdst}"
        return result
    if IP in pkt:
        result["src"], result["dst"] = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        result["src"], result["dst"] = pkt[IPv6].src, pkt[IPv6].dst
    if DNS in pkt and pkt[DNS].qd is not None:
        result["protocol"] = "DNS"
        try: result["details"] = f"query={pkt[DNSQR].qname.decode(errors='ignore')}"
        except Exception: result["details"] = "DNS query"
    elif TCP in pkt:
        result["protocol"], result["details"] = "TCP", f"{pkt[TCP].sport}->{pkt[TCP].dport}"
    elif UDP in pkt:
        result["protocol"], result["details"] = "UDP", f"{pkt[UDP].sport}->{pkt[UDP].dport}"
    elif ICMP in pkt:
        result["protocol"] = "ICMP"
    return result
