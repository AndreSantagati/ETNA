import pytest
import unittest
from unittest.mock import patch, MagicMock
from src.cti_integration import EnhancedCTIManager

class TestEnhancedCTIManager(unittest.TestCase):
    def setUp(self):
        self.cti_manager = EnhancedCTIManager()
    
    @patch('requests.get')
    def test_fetch_mitre_attack_data(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {"objects": []}
        mock_get.return_value = mock_response
        
        result = self.cti_manager.fetch_mitre_attack_data(force_download=True)
        self.assertIsInstance(result, dict)
        mock_get.assert_called_once()