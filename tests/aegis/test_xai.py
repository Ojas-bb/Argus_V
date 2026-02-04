import pytest
import pandas as pd
import numpy as np
from unittest.mock import MagicMock
from sklearn.preprocessing import StandardScaler
from argus_v.aegis.model_manager import ModelManager
from argus_v.aegis.config import ModelConfig

class TestXAI:

    @pytest.fixture
    def model_manager(self, tmp_path):
        # Create temp dirs to avoid PermissionError
        models_dir = tmp_path / "models"
        scalers_dir = tmp_path / "scalers"

        config = ModelConfig(
            model_local_path=str(models_dir),
            scaler_local_path=str(scalers_dir)
        )
        manager = ModelManager(config)

        # Setup a dummy scaler
        scaler = StandardScaler()
        # Fit on some simple data: mean=10, std=2
        # Data: [8, 12] -> mean 10, std 2
        data = np.array([[8], [12]])
        scaler.fit(data)

        # Override manager's scaler and feature columns
        manager._scaler = scaler
        manager.feature_columns = ['test_feature']

        return manager

    def test_explain_anomaly_high_value(self, model_manager):
        """Test explanation for a value significantly higher than mean."""
        # Mean=10, Std=2. Value=14 => Z = (14-10)/2 = 2.0
        flow = pd.Series({'test_feature': 14.0})

        explanation = model_manager.explain_anomaly(flow, top_k=1)

        assert len(explanation) == 1
        assert "test_feature (+2.0σ)" in explanation[0]

    def test_explain_anomaly_low_value(self, model_manager):
        """Test explanation for a value significantly lower than mean."""
        # Mean=10, Std=2. Value=4 => Z = (4-10)/2 = -3.0
        flow = pd.Series({'test_feature': 4.0})

        explanation = model_manager.explain_anomaly(flow, top_k=1)

        assert len(explanation) == 1
        assert "test_feature (-3.0σ)" in explanation[0]

    def test_multiple_features_ranking(self, tmp_path):
        """Test that features are ranked by absolute deviation."""
        # Create temp dirs to avoid PermissionError
        models_dir = tmp_path / "models"
        scalers_dir = tmp_path / "scalers"

        config = ModelConfig(
            model_local_path=str(models_dir),
            scaler_local_path=str(scalers_dir)
        )
        manager = ModelManager(config)

        # 3 features
        scaler = StandardScaler()
        # F1: mean=0, std=1
        # F2: mean=0, std=1
        # F3: mean=0, std=1
        data = np.array([
            [0, 0, 0],
            [0, 0, 0]
        ])
        # Force stats
        scaler.mean_ = np.array([0., 0., 0.])
        scaler.scale_ = np.array([1., 1., 1.])

        manager._scaler = scaler
        manager.feature_columns = ['F1', 'F2', 'F3']

        # Flow: F1=10 (Z=10), F2=-20 (Z=-20), F3=5 (Z=5)
        # Ranking should be: F2, F1, F3
        flow = pd.Series({'F1': 10, 'F2': -20, 'F3': 5})

        explanation = manager.explain_anomaly(flow, top_k=3)

        assert len(explanation) == 3
        assert "F2 (-20.0σ)" in explanation[0]
        assert "F1 (+10.0σ)" in explanation[1]
        assert "F3 (+5.0σ)" in explanation[2]

    def test_missing_features_handled(self, model_manager):
        """Test robustness when flow data is missing features."""
        # Flow missing 'test_feature'
        flow = pd.Series({'other_feature': 100})

        explanation = model_manager.explain_anomaly(flow)

        # Should handle gracefully
        assert explanation == []

    def test_no_scaler_loaded(self, tmp_path):
        """Test handling when no scaler is loaded."""
        # Create temp dirs to avoid PermissionError
        models_dir = tmp_path / "models"
        scalers_dir = tmp_path / "scalers"

        config = ModelConfig(
            model_local_path=str(models_dir),
            scaler_local_path=str(scalers_dir)
        )
        manager = ModelManager(config)
        manager._scaler = None

        flow = pd.Series({'F1': 10})
        explanation = manager.explain_anomaly(flow)

        assert explanation == ["Explanation unavailable (no scaler stats)"]
