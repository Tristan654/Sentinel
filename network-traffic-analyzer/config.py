# --- Network Interface ----------------------------------------------
INTERFACE = "eth0"

# ---Database ---------------------------------------------------------
DB_PATH = "alerts.db"

# --- Port Scan Detection ---------------------------------------------
PORT_SCAN_THRESHOLD = 10      # number of different ports
PORT_SCAN_WINDOW    = 5       # seconds

# ---SSH Brute Force Detection ---------------------------------------───────────────────────────────────────────────
SSH_BRUTE_THRESHOLD = 5       # number of connection attempts
SSH_BRUTE_WINDOW    = 60      # seconds

# --- DNS Exfiltration Detection --------------------------------------
DNS_MAX_DOMAIN_LEN  = 50      # max characters in domain name
DNS_REQUEST_RATE    = 10      # max requests per second per IP