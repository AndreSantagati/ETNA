import pytest
import unittest
from unittest.mock import patch, MagicMock
from src.cti_integration import EnhancedCTIManager

class TestEnhancedCTIManager(unittest.TestCase):
    def setUp(self):
        self.cti_manager = EnhancedCTIManager()
    
    @patch('src.cti_integration.requests.Session.get')  # Patch session.get instead
    def test_fetch_mitre_attack_data(self, mock_session_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {"objects": []}
        mock_response.raise_for_status.return_value = None
        mock_session_get.return_value = mock_response
        
        result = self.cti_manager.fetch_mitre_attack_data(force_download=True)
        self.assertIsInstance(result, dict)
        mock_session_get.assert_called_once()
    
    def test_technique_dataframe_creation(self):
        """Test MITRE techniques DataFrame creation."""
        # Set up test data that matches real MITRE ATT&CK format
        self.cti_manager.mitre_data = {
            "objects": [
                {
                    "type": "attack-pattern",
                    "name": "Test Technique",
                    "description": "Test description",
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": "T1234",
                            "url": "https://attack.mitre.org/techniques/T1234"
                        }
                    ]
                }
            ]
        }
        
        df = self.cti_manager.get_techniques_dataframe()
        self.assertFalse(df.empty)
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]['technique_id'], 'T1234')
        self.assertEqual(df.iloc[0]['name'], 'Test Technique')
        
    def test_ioc_validation(self):
        """Test IOC validation logic."""
        # Test valid IOCs
        valid_ip = "192.168.1.1"
        self.assertTrue(self.cti_manager._is_valid_ioc(valid_ip, 'ip'))
        
        valid_domain = "example.com"
        self.assertTrue(self.cti_manager._is_valid_ioc(valid_domain, 'domain'))
        
        # Test invalid IOCs
        invalid_ip = "999.999.999.999"
        self.assertFalse(self.cti_manager._is_valid_ioc(invalid_ip, 'ip'))
        
        empty_value = ""
        self.assertFalse(self.cti_manager._is_valid_ioc(empty_value, 'ip'))

if __name__ == '__main__':
    unittest.main()