#----------------Import------------
from analyzer.alert import Alert
from config import DB_PATH
import sqlite3


#--------------Function -----------
def init_db():
    database = sqlite3.connect(DB_PATH)
    cur = database.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS Alert(id INTEGER PRIMARY KEY ,alert_type,src_ip,description,timestamp)")
    database.commit()
    database.close()

def insert_alert(alert : Alert):
    database = sqlite3.connect(DB_PATH)
    cur = database.cursor()
    A = alert.to_dict()
    cur.execute("INSERT INTO Alert (alert_type, src_ip, description, timestamp) VALUES (?,?,?,?)",(A["alert_type"], A["src_ip"], A["description"], A["timestamp"]))
    database.commit()
    database.close()