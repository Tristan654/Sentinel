#---Import---
from scapy.all import sniff
from analyzer.detectors import port_scan, ssh_brute, dns_exfil
from config import INTERFACE
#---Config---

#---Functions---
def dispatch(packet):
    print("packet received")
    port_scan.detect(packet)
    ssh_brute.detect(packet)
    dns_exfil.detect(packet)

def start_capture():
    #prn = fonction a appliquer pour chaque packet 
    sniff(iface = INTERFACE, prn=dispatch, store=0)
   