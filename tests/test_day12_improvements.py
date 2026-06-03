"""
Test suite for Day 12 improvements:
1. Duplicate IOC handling
2. Elasticsearch resilience with queueing
3. Firewall permission checks
4. Enhanced output formatting
"""

import unittest
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from core.database import remove_duplicate_iocs, insert_ioc
from policy_enforcer.firewall_manager import block_ip
from threat_queue.event_queue import save_failed_event, load_failed_events, clear_queued_events


class TestDuplicateIOCHandling(unittest.TestCase):
    """Test duplicate IOC detection and removal."""
    
    def test_detect_duplicate_iocs(self):
        """Verify duplicate detection aggregation pipeline."""
        # Mock MongoDB collection
        mock_collection = MagicMock()
        
        # Simulate duplicate records
        mock_collection.aggregate.return_value = [
            {
                "_id": "192.168.1.1",
                "ids": ["id1", "id2"],
                "count": 2
            }
        ]
        mock_collection.delete_many.return_value = MagicMock(deleted_count=1)
        
        duplicates_found, duplicates_removed = remove_duplicate_iocs(mock_collection)
        
        self.assertEqual(duplicates_found, 1)
        self.assertEqual(duplicates_removed, 1)
    
    def test_insert_ioc_graceful_duplicate_handling(self):
        """Verify insertion gracefully skips duplicates."""
        mock_collection = MagicMock()
        
        # First call - existing record found
        mock_collection.find_one.return_value = {"indicator": "10.0.0.1"}
        
        ioc = {"indicator": "10.0.0.1", "risk_score": 95}
        result = insert_ioc(mock_collection, ioc)
        
        self.assertFalse(result)
        mock_collection.insert_one.assert_not_called()


class TestElasticsearchResilience(unittest.TestCase):
    """Test SIEM forwarding with queue fallback."""
    
    def setUp(self):
        """Create temporary directory for queue tests."""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Cleanup temporary files."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_queue_failed_event(self):
        """Verify failed events are queued."""
        # Create temp queue file
        queue_file = Path(self.temp_dir) / "failed_events.json"
        
        # Patch the FAILED_EVENTS_FILE path
        with patch('threat_queue.event_queue.FAILED_EVENTS_FILE', queue_file):
            ioc = {
                "indicator": "192.168.1.100",
                "risk_score": 95,
                "source": "test"
            }
            
            result = save_failed_event(ioc)
            self.assertTrue(result)
            self.assertTrue(queue_file.exists())
            
            # Verify content
            with open(queue_file, 'r') as f:
                events = json.load(f)
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["indicator"], "192.168.1.100")
    
    def test_load_queued_events(self):
        """Verify queued events can be loaded."""
        queue_file = Path(self.temp_dir) / "failed_events.json"
        
        # Create mock queue file
        test_events = [
            {"indicator": "10.0.0.1", "risk_score": 85},
            {"indicator": "10.0.0.2", "risk_score": 90}
        ]
        queue_file.write_text(json.dumps(test_events))
        
        with patch('threat_queue.event_queue.FAILED_EVENTS_FILE', queue_file):
            events = load_failed_events()
            self.assertEqual(len(events), 2)
            self.assertEqual(events[0]["indicator"], "10.0.0.1")
    
    def test_clear_queue(self):
        """Verify queue can be cleared after successful forwarding."""
        queue_file = Path(self.temp_dir) / "failed_events.json"
        queue_file.write_text(json.dumps([{"indicator": "test"}]))
        
        with patch('threat_queue.event_queue.FAILED_EVENTS_FILE', queue_file):
            self.assertTrue(queue_file.exists())
            result = clear_queued_events()
            self.assertTrue(result)
            self.assertFalse(queue_file.exists())


class TestFirewallPermissions(unittest.TestCase):
    """Test firewall enforcement with permission checks."""
    
    @patch('os.geteuid')
    def test_block_ip_requires_root(self, mock_geteuid):
        """Verify firewall gracefully handles non-root execution."""
        mock_geteuid.return_value = 1000  # Non-root user
        
        result = block_ip("192.168.1.100")
        
        self.assertFalse(result)
    
    @patch('os.geteuid')
    @patch('subprocess.run')
    def test_block_ip_with_root(self, mock_run, mock_geteuid):
        """Verify firewall blocks IP when root."""
        mock_geteuid.return_value = 0  # Root user
        mock_run.return_value = MagicMock()
        
        with patch('core.config.FIREWALL_ENABLED', True):
            result = block_ip("192.168.1.100")
        
        self.assertTrue(result)
        self.assertTrue(mock_run.called)

    @patch('os.geteuid')
    @patch('subprocess.run')
    def test_unblock_ip_with_root(self, mock_run, mock_geteuid):
        """Verify rollback removes firewall rule when root."""
        mock_geteuid.return_value = 0
        mock_run.return_value = MagicMock()

        from policy_enforcer.firewall_manager import unblock_ip

        with patch('core.config.FIREWALL_ENABLED', True):
            result = unblock_ip("192.168.1.100")

        self.assertTrue(result)
        self.assertTrue(mock_run.called)

    @patch('core.config.FIREWALL_ENABLED', False)
    def test_firewall_disabled(self):
        """Verify firewall respects disabled configuration."""
        result = block_ip("192.168.1.100")
        self.assertFalse(result)


class TestEnhancedOutput(unittest.TestCase):
    """Test enhanced IOC output formatting."""
    
    def test_ioc_output_contains_required_fields(self):
        """Verify output includes all required information."""
        from main import format_ioc_output
        
        mock_ioc = {
            "indicator": "192.168.1.1",
            "risk_score": 95,
            "type": "ipv4",
            "source": "VirusTotal",
            "siem_status": "SUCCESS",
            "firewall_status": "BLOCKED"
        }
        
        output = format_ioc_output(mock_ioc)
        
        # Verify all required fields are in output
        self.assertIn("192.168.1.1", output)
        self.assertIn("95", output)
        self.assertIn("VirusTotal", output)
        self.assertIn("Stored:", output)
        self.assertIn("SIEM:", output)
        self.assertIn("Firewall:", output)


class TestIntegration(unittest.TestCase):
    """Integration tests for Day 12 improvements."""
    
    def test_duplicate_detection_workflow(self):
        """Test full duplicate detection workflow."""
        mock_collection = MagicMock()
        mock_collection.find_one.return_value = None
        
        # First insertion should succeed
        ioc1 = {"indicator": "10.10.10.10", "risk_score": 80}
        result1 = insert_ioc(mock_collection, ioc1)
        
        self.assertTrue(result1)
        self.assertTrue(mock_collection.insert_one.called)
    
    def test_resilience_workflow(self):
        """Test resilience pipeline: queue -> retry."""
        temp_dir = tempfile.mkdtemp()
        queue_file = Path(temp_dir) / "failed_events.json"
        
        try:
            with patch('threat_queue.event_queue.FAILED_EVENTS_FILE', queue_file):
                # Simulate failed SIEM forward
                ioc = {"indicator": "172.16.0.1", "risk_score": 90}
                save_failed_event(ioc)
                
                # Verify event was queued
                events = load_failed_events()
                self.assertEqual(len(events), 1)
                self.assertIn("queued_at", events[0])
        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
