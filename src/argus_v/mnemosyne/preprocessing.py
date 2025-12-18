"""Preprocessing pipeline for Mnemosyne trainer.

This module provides functionality for preprocessing network flow data before training,
including log scaling, feature normalization, and contamination parameter tuning.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler, StandardScaler

from ..oracle_core.logging import log_event


logger = logging.getLogger(__name__)


class FlowPreprocessor:
    """Preprocesses network flow data for ML training."""
    
    def __init__(self, config):
        """Initialize preprocessor with configuration."""
        self.config = config
        self._scaler = None
        self._feature_columns = None
        
    def prepare_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Prepare feature matrix from flow data.
        
        Args:
            df: DataFrame with flow data
            
        Returns:
            DataFrame with prepared features
        """
        # Select relevant features for anomaly detection
        feature_columns = [
            'bytes_in', 'bytes_out', 'packets_in', 'packets_out', 'duration',
            'src_port', 'dst_port', 'protocol'
        ]
        
        # Ensure all feature columns exist
        missing_features = [col for col in feature_columns if col not in df.columns]
        if missing_features:
            raise ValueError(f"Missing required features: {missing_features}")
        
        # Create feature matrix
        features_df = df[feature_columns].copy()
        
        # Handle protocol as categorical feature
        if 'protocol' in features_df.columns:
            # Convert protocol to numeric (TCP=1, UDP=2, ICMP=3, etc.)
            protocol_map = {
                'TCP': 1, 'UDP': 2, 'ICMP': 3, 'IGMP': 4, 'OTHER': 5
            }
            features_df['protocol'] = features_df['protocol'].map(protocol_map).fillna(5)
        
        # Ensure ports are positive integers
        features_df['src_port'] = features_df['src_port'].abs()
        features_df['dst_port'] = features_df['dst_port'].abs()
        
        # Store feature columns for later use
        self._feature_columns = features_df.columns.tolist()
        
        log_event(
            logger,
            "features_prepared",
            level="info",
            original_rows=len(df),
            feature_count=len(feature_columns),
            feature_columns=feature_columns
        )
        
        return features_df
    
    def apply_log_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply log transformation to specified features.
        
        Args:
            df: DataFrame with features
            
        Returns:
            DataFrame with log-transformed features
        """
        transformed_df = df.copy()
        log_features = self.config.log_transform_features
        
        for feature in log_features:
            if feature in transformed_df.columns:
                # Add 1 to avoid log(0) issues, then log transform
                transformed_df[f"{feature}_log"] = np.log1p(transformed_df[feature])
                # Drop original column
                transformed_df = transformed_df.drop(columns=[feature])
        
        log_event(
            logger,
            "log_transform_applied",
            level="info",
            log_features=log_features,
            remaining_features=list(transformed_df.columns)
        )
        
        return transformed_df
    
    def normalize_features(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, Any]:
        """Normalize features using StandardScaler or RobustScaler.
        
        Args:
            df: DataFrame with features
            
        Returns:
            Tuple of (normalized_dataframe, fitted_scaler)
        """
        normalized_df = df.copy()
        
        # Choose scaler based on configuration
        if self.config.feature_normalization_method == "standard":
            self._scaler = StandardScaler()
        elif self.config.feature_normalization_method == "robust":
            self._scaler = RobustScaler()
        else:
            raise ValueError(f"Unknown normalization method: {self.config.feature_normalization_method}")
        
        # Fit and transform features
        normalized_features = self._scaler.fit_transform(normalized_df)
        
        # Convert back to DataFrame
        normalized_df = pd.DataFrame(
            normalized_features,
            columns=normalized_df.columns,
            index=normalized_df.index
        )
        
        log_event(
            logger,
            "features_normalized",
            level="info",
            normalization_method=self.config.feature_normalization_method,
            feature_count=normalized_df.shape[1],
            sample_count=normalized_df.shape[0]
        )
        
        return normalized_df, self._scaler
    
    def detect_feature_outliers(self, df: pd.DataFrame, threshold: float = 3.0) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Detect and optionally handle outliers using IQR method.
        
        Args:
            df: DataFrame with features
            threshold: IQR multiplier for outlier detection
            
        Returns:
            Tuple of (cleaned_dataframe, outlier_stats)
        """
        cleaned_df = df.copy()
        outlier_stats = {
            'total_outliers': 0,
            'outliers_by_feature': {},
            'removal_percentage': 0.0
        }
        
        initial_rows = len(cleaned_df)
        
        for column in cleaned_df.columns:
            if cleaned_df[column].dtype in ['int64', 'float64']:
                Q1 = cleaned_df[column].quantile(0.25)
                Q3 = cleaned_df[column].quantile(0.75)
                IQR = Q3 - Q1
                
                lower_bound = Q1 - threshold * IQR
                upper_bound = Q3 + threshold * IQR
                
                # Count outliers in this feature
                outliers = ((cleaned_df[column] < lower_bound) | (cleaned_df[column] > upper_bound))
                outlier_count = outliers.sum()
                
                outlier_stats['outliers_by_feature'][column] = {
                    'count': int(outlier_count),
                    'percentage': float(outlier_count / len(cleaned_df) * 100)
                }
                
                # Remove rows with outliers (only for the most extreme cases)
                if threshold >= 3.0:  # Only remove extreme outliers
                    cleaned_df = cleaned_df[~outliers]
        
        final_rows = len(cleaned_df)
        outlier_stats['total_outliers'] = initial_rows - final_rows
        outlier_stats['removal_percentage'] = float((initial_rows - final_rows) / initial_rows * 100)
        
        log_event(
            logger,
            "outlier_detection_completed",
            level="info",
            initial_rows=initial_rows,
            final_rows=final_rows,
            outlier_stats=outlier_stats
        )
        
        return cleaned_df, outlier_stats
    
    def tune_contamination_parameter(self, df: pd.DataFrame) -> Tuple[float, Dict[str, Any]]:
        """Automatically tune contamination parameter for IsolationForest.
        
        Args:
            df: DataFrame with preprocessed features
            
        Returns:
            Tuple of (optimal_contamination, tuning_stats)
        """
        from sklearn.ensemble import IsolationForest
        from sklearn.model_selection import cross_val_score
        
        tuning_stats = {
            'contamination_range': self.config.contamination_range,
            'scores': {},
            'best_contamination': None,
            'best_score': 0.0
        }
        
        min_contamination, max_contamination = self.config.contamination_range
        contamination_values = np.linspace(min_contamination, max_contamination, 10)
        
        best_contamination = min_contamination
        best_score = 0.0
        
        for contamination in contamination_values:
            try:
                # Create IsolationForest with current contamination
                forest = IsolationForest(
                    contamination=contamination,
                    random_state=self.config.random_state,
                    n_estimators=50,  # Reduced for faster tuning
                    n_jobs=1  # Single-threaded for reproducibility
                )
                
                # Perform cross-validation (using negative mean scores)
                scores = cross_val_score(
                    forest, df, cv=min(3, self.config.cross_validation_folds),
                    scoring='neg_mean_score', n_jobs=1
                )
                
                mean_score = scores.mean()
                tuning_stats['scores'][float(contamination)] = float(mean_score)
                
                # Track best contamination
                if mean_score > best_score:
                    best_score = mean_score
                    best_contamination = contamination
                    
            except Exception as e:
                log_event(
                    logger,
                    "contamination_tuning_failed_for_value",
                    level="warning",
                    contamination=contamination,
                    error=str(e)
                )
                continue
        
        # Ensure we have a valid contamination value
        if best_contamination is None:
            log_event(
                logger,
                "contamination_tuning_failed_using_default",
                level="warning",
                default_contamination=min_contamination
            )
            best_contamination = min_contamination
        
        tuning_stats['best_contamination'] = float(best_contamination)
        tuning_stats['best_score'] = float(best_score)
        
        log_event(
            logger,
            "contamination_tuning_completed",
            level="info",
            best_contamination=best_contamination,
            best_score=best_score,
            values_tested=len(tuning_stats['scores'])
        )
        
        return best_contamination, tuning_stats
    
    def preprocess_pipeline(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Run the complete preprocessing pipeline.
        
        Args:
            df: Raw flow DataFrame
            
        Returns:
            Tuple of (preprocessed_dataframe, preprocessing_stats)
        """
        stats = {
            'initial_rows': len(df),
            'feature_preparation': {},
            'log_transform': {},
            'outlier_detection': {},
            'normalization': {},
            'contamination_tuning': {}
        }
        
        # Step 1: Feature preparation
        features_df = self.prepare_features(df)
        stats['feature_preparation'] = {
            'feature_count': len(features_df.columns),
            'feature_columns': list(features_df.columns)
        }
        
        # Step 2: Log transformation
        log_df = self.apply_log_transform(features_df)
        stats['log_transform'] = {
            'log_features': self.config.log_transform_features,
            'final_features': list(log_df.columns)
        }
        
        # Step 3: Outlier detection and removal
        clean_df, outlier_stats = self.detect_feature_outliers(log_df, threshold=3.0)
        stats['outlier_detection'] = outlier_stats
        
        # Step 4: Feature normalization
        normalized_df, scaler = self.normalize_features(clean_df)
        stats['normalization'] = {
            'method': self.config.feature_normalization_method,
            'scaler_type': type(scaler).__name__
        }
        
        # Step 5: Contamination parameter tuning (if enabled)
        if self.config.contamination_auto_tune and len(normalized_df) >= self.config.min_samples_for_training:
            contamination, tuning_stats = self.tune_contamination_parameter(normalized_df)
            stats['contamination_tuning'] = tuning_stats
        else:
            # Use middle of range as default
            min_contam, max_contam = self.config.contamination_range
            contamination = (min_contam + max_contam) / 2
            stats['contamination_tuning'] = {
                'auto_tune_enabled': False,
                'selected_contamination': contamination,
                'reason': 'insufficient_samples' if len(normalized_df) < self.config.min_samples_for_training else 'auto_tune_disabled'
            }
        
        stats['final_rows'] = len(normalized_df)
        stats['final_features'] = len(normalized_df.columns)
        stats['optimal_contamination'] = contamination
        
        log_event(
            logger,
            "preprocessing_pipeline_completed",
            level="info",
            stats=stats
        )
        
        return normalized_df, stats