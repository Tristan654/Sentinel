#----------------Import------------
from datetime import datetime
import logging



#----------------Class-------------
class Alert:
    def __init__(self, alert_type, src_ip, description):
        self.alert_type  = alert_type
        self.src_ip      = src_ip
        self.description = description
        self.timestamp   = datetime.now()

    def to_dict(self):
        return {
            "alert_type":  self.alert_type,
            "src_ip":      self.src_ip,
            "description": self.description,
            "timestamp":   str(self.timestamp)
        }
    
    def __str__(self):
        return f"[{self.timestamp}] {self.alert_type} | {self.src_ip} | {self.description}"



#--------------Function -----------
def log_alert(alert):
    logging.info(str(alert))