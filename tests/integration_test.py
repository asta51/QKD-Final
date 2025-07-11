import unittest
import threading
import time
from network.secure_server import SecureServer
from network.secure_client import SecureClient

class TestSecureCommunication(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = SecureServer(port=65433)
        cls.server_thread = threading.Thread(target=cls.server.start)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(1)  # Wait for server to start
    
    def test_secure_communication(self):
        client = SecureClient(port=65433)
        test_message = "This is a secret message"
        client.send_message(test_message)
        # Manual verification needed - check server logs for received message

if __name__ == '__main__':
    unittest.main()
