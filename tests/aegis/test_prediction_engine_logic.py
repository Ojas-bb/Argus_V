
import pytest
import pandas as pd
from unittest.mock import MagicMock, call
from src.argus_v.aegis.prediction_engine import PredictionEngine

@pytest.fixture
def prediction_engine():
    mock_model_manager = MagicMock()
    mock_blacklist_manager = MagicMock()
    mock_feedback_manager = MagicMock()

    # Setup mocks
    mock_blacklist_manager.is_blacklisted.return_value = False
    mock_feedback_manager.get_trusted_ips.return_value = []

    engine = PredictionEngine(
        polling_config=MagicMock(),
        prediction_config=MagicMock(),
        model_manager=mock_model_manager,
        blacklist_manager=mock_blacklist_manager,
        feedback_manager=mock_feedback_manager
    )
    return engine

def test_prediction_engine_anomaly_detection(prediction_engine):
    """Verify anomalies trigger actions and stats updates."""
    df = pd.DataFrame([{
        'prediction': -1,
        'anomaly_score': 0.9,
        'risk_level': 'high',
        'src_ip': '1.2.3.4',
        'dst_ip': '5.6.7.8',
        'src_port': 80,
        'dst_port': 1234,
        'protocol': 'TCP',
        'bytes_in': 100,
        'bytes_out': 200
    }])

    prediction_engine._process_batch_predictions(df)

    assert prediction_engine._stats['anomalies_detected'] == 1
    assert prediction_engine._stats['blacklist_additions'] == 1
    prediction_engine.blacklist_manager.add_to_blacklist.assert_called_once()
    _, kwargs = prediction_engine.blacklist_manager.add_to_blacklist.call_args
    assert kwargs['ip_address'] == '1.2.3.4'
    assert 'risk_level' in kwargs
    assert kwargs['risk_level'] == 'high'

def test_prediction_engine_trusted_ip_suppression(prediction_engine):
    """Verify trusted IPs suppress anomalies."""
    df = pd.DataFrame([{
        'prediction': -1,
        'anomaly_score': 0.9,
        'risk_level': 'high',
        'src_ip': '10.0.0.1', # Trusted
        'dst_ip': '5.6.7.8'
    }])

    # Mock trusted IP
    prediction_engine.feedback_manager.get_trusted_ips.return_value = [{'ip': '10.0.0.1'}]

    prediction_engine._process_batch_predictions(df)

    # Should be suppressed
    assert prediction_engine._stats['anomalies_detected'] == 0
    assert prediction_engine._stats['blacklist_additions'] == 0
    prediction_engine.blacklist_manager.add_to_blacklist.assert_not_called()

def test_prediction_engine_blacklist_enforcement(prediction_engine):
    """Verify blacklisted IPs trigger enforcement even for normal traffic."""
    df = pd.DataFrame([{
        'prediction': 1, # Normal traffic
        'anomaly_score': 0.1,
        'risk_level': 'low',
        'src_ip': '192.168.1.100', # Blacklisted
        'dst_ip': '5.6.7.8'
    }])

    # Mock blacklisted IP
    prediction_engine.blacklist_manager.is_blacklisted.side_effect = lambda ip: ip == '192.168.1.100'

    prediction_engine._process_batch_predictions(df)

    # Should trigger enforcement
    assert prediction_engine._stats['anomalies_detected'] == 0 # Prediction was normal
    assert prediction_engine._stats['blacklist_additions'] == 1
    prediction_engine.blacklist_manager.add_to_blacklist.assert_called_once()
    _, kwargs = prediction_engine.blacklist_manager.add_to_blacklist.call_args
    assert kwargs['ip_address'] == '192.168.1.100'

def test_prediction_engine_mixed_batch(prediction_engine):
    """Verify mixed batch handling."""
    df = pd.DataFrame([
        {'prediction': -1, 'src_ip': '1.1.1.1', 'dst_ip': '2.2.2.2', 'risk_level': 'high'}, # Anomaly
        {'prediction': 1, 'src_ip': '3.3.3.3', 'dst_ip': '4.4.4.4', 'risk_level': 'low'}, # Normal
        {'prediction': 1, 'src_ip': '5.5.5.5', 'dst_ip': '6.6.6.6', 'risk_level': 'low'}  # Blacklisted
    ])

    prediction_engine.blacklist_manager.is_blacklisted.side_effect = lambda ip: ip == '5.5.5.5'

    prediction_engine._process_batch_predictions(df)

    assert prediction_engine._stats['anomalies_detected'] == 1
    assert prediction_engine._stats['blacklist_additions'] == 2 # 1 Anomaly + 1 Blacklisted

    # Verify calls
    assert prediction_engine.blacklist_manager.add_to_blacklist.call_count == 2

def test_prediction_engine_trusted_and_blacklisted_flow(prediction_engine):
    """Verify flow with Trusted Source AND Blacklisted Destination is allowed (trusted wins)."""
    df = pd.DataFrame([{
        'prediction': 1,
        'src_ip': '10.0.0.1', # Trusted
        'dst_ip': '6.6.6.6',  # Blacklisted
        'risk_level': 'low'
    }])

    # Mock trusted IP
    prediction_engine.feedback_manager.get_trusted_ips.return_value = [{'ip': '10.0.0.1'}]

    # Mock blacklist
    prediction_engine.blacklist_manager.is_blacklisted.side_effect = lambda ip: ip == '6.6.6.6'

    prediction_engine._process_batch_predictions(df)

    # Should be suppressed because src_ip is trusted, even if dst_ip is blacklisted
    assert prediction_engine._stats['blacklist_additions'] == 0
    prediction_engine.blacklist_manager.add_to_blacklist.assert_not_called()
