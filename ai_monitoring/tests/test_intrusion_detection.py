import unittest
import numpy as np
from ai_security.intrusion_detection import AISecurityMonitor

class TestAISecurityMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = AISecurityMonitor()
    
    def test_training(self):
        results = self.monitor.train_models()
        self.assertGreater(results["accuracy"], 0.8)
    
    def test_threat_detection(self):
        self.monitor.train_models()
        normal_traffic = [0.5, 0.5, 0.5, 0.5, 0.5]
        attack_traffic = [0.1, 0.9, 0.1, 0.9, 0.1]
        
        normal_result = self.monitor.detect_threats(normal_traffic)
        attack_result = self.monitor.detect_threats(attack_traffic)
        
        self.assertFalse(normal_result["is_threat"])
        self.assertTrue(attack_result["is_threat"])

if __name__ == '__main__':
    unittest.main()
