#------------Import-------------
from scapy.all import *
from datetime import datetime
import config, alert, database

#------------Functions----------

def detect(packet):
    if packet[scapy.TCP].flags == "S" :

