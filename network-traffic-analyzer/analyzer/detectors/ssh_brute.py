#------------Import-------------
from scapy.all import IP,TCP
from datetime import datetime
from collections import defaultdict
from config import SSH_BRUTE_THRESHOLD,SSH_BRUTE_WINDOW
from alert import log_alert,Alert
from database import insert_alert

#------------Variable-----------
tracker = defaultdict(list)
port_ssh = 22


#------------Functions----------
def detect(packet):
    if not (IP in packet and TCP in packet):
        return
    if packet[TCP].flags == "S": #detect SYN for namp -sS
        if packet[TCP].dport == port_ssh:
            src_ip = packet[IP].src 
            tracker[src_ip].append(datetime.now())
        
            # Si je me connecte 6 fois dans la meme journée c OK c que si c très rapide
            for timestamp in tracker[src_ip] : 
                if (datetime.now() - timestamp).seconds > SSH_BRUTE_WINDOW:
                    tracker[src_ip].remove(timestamp)

            """
            tracker[src_ip] = [
            t for t in tracker[src_ip]
            if (datetime.now() - t).seconds <= SSH_BRUTE_WINDOW
        ]
            """

            if len(tracker[src_ip])>SSH_BRUTE_THRESHOLD:
                alert = Alert("Brute Force SSH",src_ip,f"SYN brute force detected from {src_ip} : {len(tracker[src_ip])} try to  connect in {SSH_BRUTE_WINDOW}")
                insert_alert(alert)
                log_alert(alert)


        
