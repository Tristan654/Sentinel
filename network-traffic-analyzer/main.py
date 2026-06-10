#---Import---
from analyzer.database import init_db
from analyzer.capture import start_capture
#---Config---
if __name__ == "__main__":
    init_db()
    start_capture()
#---Function