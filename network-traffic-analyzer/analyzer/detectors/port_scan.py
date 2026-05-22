#------------Import-------------
from scapy.all import IP,TCP
from datetime import datetime
from collections import defaultdict
from config import PORT_SCAN_WINDOW,PORT_SCAN_THRESHOLD
from alert import log_alert,Alert
from database import insert_alert

#------------Variable-----------
tracker = defaultdict(list) # c un {} dont les valeurs sont des listes si plusieurs fois la meme clé


#------------Functions----------
def detect(packet):
    if not (IP in packet and TCP in packet):
        return
    if packet[TCP].flags == "S" :
        # "123.23.34.1" = [(temps1, port1), (temps2, port2), (temps3, port3)]
        src_ip = packet[IP].src
        port_dest = packet[TCP].dport
        tracker[src_ip].append((datetime.now(), port_dest))

        # Time Management
        for (timestamp,port) in tracker[src_ip] : 
            if (datetime.now() - timestamp).seconds > PORT_SCAN_WINDOW : 
                tracker[src_ip].remove((timestamp, port))

        # Scan Management
        if len(set(port for _, port in tracker[src_ip])) > PORT_SCAN_THRESHOLD: #copte le nombre de port dif
            alert = Alert("PORT_SCAN",tracker[src_ip],f"SYN scan detected from {src_ip} : {len(set(port for _, port in tracker[src_ip]))} ports in {PORT_SCAN_WINDOW}s")
            insert_alert(alert)
            log_alert(alert)

