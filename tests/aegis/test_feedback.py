import pytest
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
from argus_v.aegis.feedback_manager import FeedbackManager

class TestFeedbackManager:

    @pytest.fixture
    def feedback_manager(self, tmp_path):
        # Create temp dirs
        feedback_dir = tmp_path / "feedback"
        mnemosyne_dir = tmp_path / "mnemosyne"

        # Subclass for testing
        class TestableFeedbackManager(FeedbackManager):
            def __init__(self, config):
                self.config = config
                self.feedback_dir = feedback_dir
                self.trusted_ips_file = self.feedback_dir / "trusted_ips.json"
                self.retrain_flag_file = mnemosyne_dir / "trigger_retrain"
                self._trusted_ips_cache = None  # Initialize cache
                self._ensure_directories()

        return TestableFeedbackManager(MagicMock())

    def test_report_false_positive(self, feedback_manager):
        ip = "10.0.0.1"
        success = feedback_manager.report_false_positive(ip, "Test reason")

        assert success

        # Verify file content
        with open(feedback_manager.trusted_ips_file, 'r') as f:
            data = json.load(f)

        assert len(data) == 1
        assert data[0]['ip'] == ip
        assert data[0]['reason'] == "Test reason"
        assert data[0]['status'] == "active"

        # Verify cache was updated
        assert feedback_manager._trusted_ips_cache is not None
        assert len(feedback_manager._trusted_ips_cache) == 1

    def test_report_duplicate_ip(self, feedback_manager):
        ip = "10.0.0.1"
        feedback_manager.report_false_positive(ip)
        success = feedback_manager.report_false_positive(ip)

        assert success

        # Verify no duplicate
        with open(feedback_manager.trusted_ips_file, 'r') as f:
            data = json.load(f)

        assert len(data) == 1

    def test_trigger_retrain(self, feedback_manager):
        success = feedback_manager.trigger_retrain()

        assert success
        assert feedback_manager.retrain_flag_file.exists()

    def test_get_trusted_ips(self, feedback_manager):
        feedback_manager.report_false_positive("1.1.1.1")
        feedback_manager.report_false_positive("2.2.2.2")

        ips = feedback_manager.get_trusted_ips()
        assert len(ips) == 2
        assert any(x['ip'] == "1.1.1.1" for x in ips)
