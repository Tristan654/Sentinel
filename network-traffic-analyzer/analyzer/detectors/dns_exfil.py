#---Import---
from scapy import DNS, DNSQR, IP
from config import DNS_MAX_DOMAIN_LEN,DNS_REQUEST_RATE,DNS_WINDOW
from alert import log_alert, Alert
from database import insert_alert
from collections import defaultdict
from datetime import datetime 
#---Config---
tracker = defaultdict(list)

#---Functions---

def detect(packet):
    if not (IP in packet and DNS in packet and DNSQR in packet):
        return
    src_ip = packet[IP].src
    tracker[src_ip].append(datetime.now())
    Domain_Name = packet[DNSQR].qname.decode()

    #Saanetize
    for timestamp in tracker[src_ip] : 
                if (datetime.now() - timestamp).seconds > DNS_WINDOW:
                    tracker[src_ip].remove(timestamp)

    #Condition
    if len(Domain_Name) > DNS_MAX_DOMAIN_LEN :
        alert = Alert("DNS_Exfiltration",src_ip,f"Domain exfiltration detected at {tracker[src_ip]}")
        insert_alert(alert)
        log_alert(alert)
    if len(tracker[src_ip]) > DNS_REQUEST_RATE:
        alert = Alert("DNS_Exfiltration",src_ip,f"Domain exfiltration detected at {tracker[src_ip]}")
        insert_alert(alert)
        log_alert(alert)
        
    return