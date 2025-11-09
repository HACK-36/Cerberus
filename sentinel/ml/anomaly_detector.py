"""
Stage 3: Behavioral Anomaly Detector - ML model for scoring session sequences
Uses IsolationForest / sequence models to detect anomalous behavior
"""
import json
import os
from typing import Dict, List
import numpy as np
from datetime import datetime

# Try importing ML libraries
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    print("[WARNING] scikit-learn not installed. Using heuristic scoring only.")
    SKLEARN_AVAILABLE = False

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.utils.logging import get_logger

logger = get_logger(__name__)


class BehavioralAnomalyDetector:
    """
    Detects anomalous behavioral patterns in session sequences
    
    MVP: Uses IsolationForest on aggregated features
    Production: Use LSTM/Transformer on temporal sequences
    """
    
    def __init__(self, model_path: str = None):
        self.model_path = model_path or os.path.join(
            os.path.dirname(__file__), '..', '..', 'data', 'models', 'anomaly_detector.pkl'
        )
        
        if SKLEARN_AVAILABLE:
            self.scaler = StandardScaler()
            self.model = IsolationForest(
                contamination=0.1,  # 10% anomaly rate
                random_state=42,
                n_estimators=100
            )
            self.is_trained = False
            
            # Try loading existing model
            self._load_model()
        else:
            self.model = None
        
        logger.info("Behavioral anomaly detector initialized")
    
    def score(self, features: Dict) -> float:
        """
        Score a session's behavioral features for anomaly
        
        Args:
            features: Feature vector from FeatureExtractor
            
        Returns:
            Anomaly score in [0, 1] (higher = more anomalous)
        """
        try:
            # Extract relevant behavioral features
            feature_vector = self._extract_feature_vector(features)
            
            # If model is trained, use ML scoring
            if SKLEARN_AVAILABLE and self.is_trained:
                return self._ml_score(feature_vector)
            
            # Fallback to heuristic scoring
            return self._heuristic_score(features)
        
        except Exception as e:
            logger.error(f"Error scoring anomaly: {e}", exc_info=True)
            return 0.0
    
    def _extract_feature_vector(self, features: Dict) -> np.ndarray:
        """Extract numeric feature vector for ML model"""
        # List of features to use (must match training)
        feature_keys = [
            "n_requests",
            "method_diversity",
            "avg_path_depth",
            "max_path_depth",
            "avg_param_count",
            "max_param_count",
            "error_rate",
            "n_payloads",
            "max_payload_entropy",
            "avg_payload_entropy",
            "avg_payload_length",
            "max_payload_length",
            "special_char_ratio",
            "avg_inter_request_ms",
            "request_rate_per_min",
            "ua_fingerprint_score",
            "endpoint_diversity",
            "ua_changes"
        ]
        
        # Extract values (use 0 as default)
        vector = np.array([features.get(key, 0.0) for key in feature_keys])
        
        return vector.reshape(1, -1)
    
    def _ml_score(self, feature_vector: np.ndarray) -> float:
        """ML-based anomaly scoring"""
        try:
            # Scale features
            X_scaled = self.scaler.transform(feature_vector)
            
            # Get anomaly score
            # IsolationForest returns -1 for anomalies, 1 for normal
            # decision_function returns raw anomaly score (negative = anomaly)
            raw_score = self.model.decision_function(X_scaled)[0]
            
            # Normalize to [0, 1] (0 = normal, 1 = anomaly)
            # Scores typically range from -0.5 to 0.5
            normalized_score = 1.0 / (1.0 + np.exp(raw_score * 2))  # Sigmoid
            
            logger.info(f"ML anomaly score: {normalized_score:.3f}")
            
            return float(normalized_score)
        
        except Exception as e:
            logger.error(f"ML scoring failed: {e}")
            return 0.5
    
    def _heuristic_score(self, features: Dict) -> float:
        """
        Heuristic-based anomaly scoring
        Uses weighted combination of suspicious indicators
        """
        score = 0.0
        
        # High request rate (potential scanning)
        request_rate = features.get("request_rate_per_min", 0)
        if request_rate > 100:
            score += 0.3
        elif request_rate > 50:
            score += 0.2
        elif request_rate > 20:
            score += 0.1
        
        # High error rate (probing)
        error_rate = features.get("error_rate", 0)
        if error_rate > 0.5:
            score += 0.25
        elif error_rate > 0.3:
            score += 0.15
        
        # Suspicious payloads
        if features.get("contains_sql_keywords", 0) == 1:
            score += 0.25
        if features.get("contains_xss_patterns", 0) == 1:
            score += 0.25
        if features.get("contains_cmd_patterns", 0) == 1:
            score += 0.3
        
        # High payload entropy (obfuscation)
        max_entropy = features.get("max_payload_entropy", 0)
        if max_entropy > 7.5:
            score += 0.2
        elif max_entropy > 6.5:
            score += 0.1
        
        # User-Agent changes (fingerprint evasion)
        ua_changes = features.get("ua_changes", 0)
        n_requests = features.get("n_requests", 1)
        if ua_changes / n_requests > 0.5:
            score += 0.15
        
        # Unusual request patterns
        method_diversity = features.get("method_diversity", 0)
        if method_diversity > 0.8:  # Using many different methods
            score += 0.1
        
        # Deep path traversal attempts
        max_path_depth = features.get("max_path_depth", 0)
        if max_path_depth > 10:
            score += 0.15
        
        # Prior POI history
        prior_poi = features.get("prior_poi_count", 0)
        if prior_poi > 0:
            score += min(0.2, prior_poi * 0.05)
        
        # Cap at 1.0
        final_score = min(1.0, score)
        
        logger.info(f"Heuristic anomaly score: {final_score:.3f}")
        
        return final_score
    
    def train(self, feature_samples: List[Dict]):
        """
        Train anomaly detector on benign traffic
        
        Args:
            feature_samples: List of feature dicts from normal sessions
        """
        if not SKLEARN_AVAILABLE:
            logger.error("Cannot train: scikit-learn not available")
            return
        
        if len(feature_samples) < 20:
            logger.warning(f"Training data too small: {len(feature_samples)} samples")
            return
        
        try:
            logger.info(f"Training anomaly detector on {len(feature_samples)} samples...")
            
            # Extract feature vectors
            X = np.vstack([
                self._extract_feature_vector(features)[0]
                for features in feature_samples
            ])
            
            # Fit scaler
            X_scaled = self.scaler.fit_transform(X)
            
            # Train IsolationForest
            self.model.fit(X_scaled)
            self.is_trained = True
            
            # Save model
            self._save_model()
            
            logger.info("Anomaly detector training complete")
        
        except Exception as e:
            logger.error(f"Error training anomaly detector: {e}", exc_info=True)
    
    def _save_model(self):
        """Save trained model to disk"""
        try:
            model_dir = os.path.dirname(self.model_path)
            os.makedirs(model_dir, exist_ok=True)
            
            model_data = {
                "scaler": self.scaler,
                "model": self.model,
                "trained_at": datetime.utcnow().isoformat()
            }
            
            joblib.dump(model_data, self.model_path)
            logger.info(f"Anomaly detector saved to {self.model_path}")
        
        except Exception as e:
            logger.error(f"Error saving model: {e}", exc_info=True)
    
    def _load_model(self):
        """Load trained model from disk"""
        try:
            if not os.path.exists(self.model_path):
                logger.info("No saved anomaly model found.")
                return
            
            model_data = joblib.load(self.model_path)
            self.scaler = model_data["scaler"]
            self.model = model_data["model"]
            self.is_trained = True
            
            logger.info(f"Anomaly detector loaded from {self.model_path}")
        
        except Exception as e:
            logger.warning(f"Could not load anomaly model: {e}")
            self.is_trained = False


# CLI entry point
if __name__ == "__main__":
    detector = BehavioralAnomalyDetector()
    
    # Example test
    sample_features = {
        "n_requests": 50,
        "method_diversity": 0.4,
        "avg_path_depth": 3.2,
        "max_path_depth": 7,
        "avg_param_count": 2.5,
        "max_param_count": 8,
        "error_rate": 0.6,
        "n_payloads": 5,
        "max_payload_entropy": 7.8,
        "avg_payload_entropy": 6.2,
        "avg_payload_length": 45,
        "max_payload_length": 120,
        "special_char_ratio": 0.4,
        "avg_inter_request_ms": 200,
        "request_rate_per_min": 60,
        "ua_fingerprint_score": 0.3,
        "endpoint_diversity": 0.7,
        "ua_changes": 2,
        "contains_sql_keywords": 1,
        "contains_xss_patterns": 0,
        "contains_cmd_patterns": 0
    }
    
    score = detector.score(sample_features)
    print(f"\nAnomaly Score: {score:.3f}")
    
    if score >= 0.7:
        print("Verdict: HIGH ANOMALY - Recommend simulation")
    elif score >= 0.5:
        print("Verdict: MEDIUM ANOMALY - Tag as POI")
    else:
        print("Verdict: LOW ANOMALY - Likely benign")
