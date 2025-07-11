# System Configuration
DEFAULT_KEY_LENGTH = 256
SERVER_HOST = 'localhost'
SERVER_PORT = 65432
MAX_PACKET_SIZE = 4096

# AI Security Parameters
ANOMALY_THRESHOLD = 0.7
CONTAMINATION_RATE = 0.05

# Cryptography Parameters
SCRYPT_PARAMS = {
    'N': 2**14,
    'r': 8,
    'p': 1
}
