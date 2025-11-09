"""
Stage 3: Inference Engine - Orchestrates model inference and verdict generation
Combines payload classification + behavioral anomaly detection
"""
import json
import os
from typing import Dict, List
from datetime import datetime

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from sentinel.ml.payload_classifier import PayloadClassifier
from sentinel.ml.anomaly_detector import BehavioralAnomalyDetector
from sentinel.ml.feature_extractor import FeatureExtractor
from shared.utils.logging import get_logger
from shared.utils.metrics import EVIDENCE_OPERATIONS

logger = get_logger(__name__)


class InferenceEngine:
    """
    Orchestrates ML inference pipeline:
    1. Feature extraction
    2. Payload classification
    3. Behavioral anomaly detection
    4. Combine scores → final verdict
    """
    
    # Thresholds
    SIMULATE_THRESHOLD = 0.75
    TAG_THRESHOLD = 0.50
    
    # Score weights
    PAYLOAD_WEIGHT = 0.6
    BEHAVIOR_WEIGHT = 0.4
    
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.payload_classifier = PayloadClassifier()
        self.anomaly_detector = BehavioralAnomalyDetector()
        
        logger.info("Inference engine initialized")
    
    def analyze(self, evidence: Dict) -> Dict:
        """
        Full analysis pipeline: evidence → verdict
        
        Args:
            evidence: Raw evidence package from MinIO
            
        Returns:
            Verdict dict with:
            {
                "session_id": "...",
                "verdict": "simulate" | "tag" | "benign",
                "final_score": 0.88,
                "payload_predictions": [...],
                "behavioral_score": 0.82,
                "explain": {...}
            }
        """
        session_id = evidence.get("session_id", "unknown")
        logger.info(f"[INFERENCE] Analyzing session: {session_id}")
        
        try:
            # Stage 1: Extract features
            features = self.feature_extractor.extract(evidence)
            
            if not features:
                logger.error(f"Feature extraction failed for {session_id}")
                return self._benign_verdict(session_id, "feature_extraction_failed")
            
            # Stage 2: Classify payloads
            payloads = evidence.get("extracted_payloads", [])
            payload_predictions = self._classify_payloads(payloads)
            
            # Stage 3: Behavioral anomaly score
            behavioral_score = self.anomaly_detector.score(features)
            
            # Stage 4: Combine scores
            final_score, verdict = self._combine_scores(
                payload_predictions,
                behavioral_score,
                features
            )
            
            # Stage 5: Generate explanation
            explanation = self._generate_explanation(
                features,
                payload_predictions,
                behavioral_score
            )
            
            # Build result
            result = {
                "session_id": session_id,
                "timestamp": datetime.utcnow().isoformat(),
                "verdict": verdict,
                "final_score": final_score,
                "payload_predictions": payload_predictions,
                "behavioral_score": behavioral_score,
                "features": features,
                "explain": explanation
            }
            
            logger.info(
                f"[INFERENCE] Session {session_id}: verdict={verdict}, "
                f"score={final_score:.2f}"
            )
            
            EVIDENCE_OPERATIONS.labels(
                operation="inference",
                status=verdict
            ).inc()
            
            return result
        
        except Exception as e:
            logger.error(f"Inference error for {session_id}: {e}", exc_info=True)
            return self._benign_verdict(session_id, "inference_error")
    
    def _classify_payloads(self, payloads: List[Dict]) -> List[Dict]:
        """Classify all payloads in session"""
        predictions = []
        
        for payload in payloads:
            payload_value = payload.get("value", "")
            payload_id = payload.get("id", f"p_{len(predictions)}")
            
            # Classify
            pred = self.payload_classifier.predict(payload_value)
            
            predictions.append({
                "payload_id": payload_id,
                "payload_value": payload_value[:100],  # Truncate for storage
                "class": pred["class"],
                "confidence": pred["confidence"],
                "method": pred.get("method", "unknown")
            })
        
        return predictions
    
    def _combine_scores(
        self,
        payload_predictions: List[Dict],
        behavioral_score: float,
        features: Dict
    ) -> tuple[float, str]:
        """
        Combine payload and behavioral scores into final verdict
        
        Returns:
            (final_score, verdict)
        """
        # Aggregate payload scores
        if payload_predictions:
            # Get max confidence for malicious classes
            malicious_scores = [
                p["confidence"]
                for p in payload_predictions
                if p["class"] != "benign"
            ]
            
            payload_score = max(malicious_scores) if malicious_scores else 0.0
        else:
            payload_score = 0.0
        
        # Weighted combination
        final_score = (
            self.PAYLOAD_WEIGHT * payload_score +
            self.BEHAVIOR_WEIGHT * behavioral_score
        )
        
        # Boost if multiple indicators present
        if payload_score > 0.7 and behavioral_score > 0.7:
            final_score = min(1.0, final_score * 1.2)  # 20% boost
        
        # Determine verdict
        if final_score >= self.SIMULATE_THRESHOLD:
            verdict = "simulate"
        elif final_score >= self.TAG_THRESHOLD:
            verdict = "tag"
        else:
            verdict = "benign"
        
        return final_score, verdict
    
    def _generate_explanation(
        self,
        features: Dict,
        payload_predictions: List[Dict],
        behavioral_score: float
    ) -> Dict:
        """
        Generate human-readable explanation
        
        Simplified version of SHAP - identifies top contributing features
        """
        top_features = []
        
        # Check high-impact features
        if features.get("contains_sql_keywords", 0) == 1:
            top_features.append({
                "feature": "contains_sql_keywords",
                "value": 1,
                "impact": "high",
                "description": "SQL injection keywords detected"
            })
        
        if features.get("contains_xss_patterns", 0) == 1:
            top_features.append({
                "feature": "contains_xss_patterns",
                "value": 1,
                "impact": "high",
                "description": "XSS patterns detected"
            })
        
        if features.get("contains_cmd_patterns", 0) == 1:
            top_features.append({
                "feature": "contains_cmd_patterns",
                "value": 1,
                "impact": "high",
                "description": "Command injection patterns detected"
            })
        
        if features.get("max_payload_entropy", 0) > 7.0:
            top_features.append({
                "feature": "max_payload_entropy",
                "value": features["max_payload_entropy"],
                "impact": "medium",
                "description": "High payload entropy (possible obfuscation)"
            })
        
        if features.get("error_rate", 0) > 0.5:
            top_features.append({
                "feature": "error_rate",
                "value": features["error_rate"],
                "impact": "medium",
                "description": "High error rate (probing behavior)"
            })
        
        if features.get("request_rate_per_min", 0) > 50:
            top_features.append({
                "feature": "request_rate_per_min",
                "value": features["request_rate_per_min"],
                "impact": "medium",
                "description": "High request rate (scanning)"
            })
        
        # Attack classes detected
        attack_classes = [
            p["class"]
            for p in payload_predictions
            if p["class"] != "benign"
        ]
        
        explanation = {
            "top_features": top_features[:5],  # Top 5
            "attack_classes_detected": list(set(attack_classes)),
            "behavioral_anomaly_score": behavioral_score,
            "n_malicious_payloads": len(attack_classes),
            "summary": self._generate_summary(top_features, attack_classes)
        }
        
        return explanation
    
    def _generate_summary(self, top_features: List[Dict], attack_classes: List[str]) -> str:
        """Generate human-readable summary"""
        if not attack_classes and not top_features:
            return "No suspicious patterns detected. Session appears benign."
        
        parts = []
        
        if attack_classes:
            attacks = ", ".join(set(attack_classes))
            parts.append(f"Attack types detected: {attacks}")
        
        if top_features:
            features_str = ", ".join(f["feature"] for f in top_features[:3])
            parts.append(f"Suspicious indicators: {features_str}")
        
        return ". ".join(parts) + "."
    
    def _benign_verdict(self, session_id: str, reason: str) -> Dict:
        """Return benign verdict (fallback)"""
        return {
            "session_id": session_id,
            "timestamp": datetime.utcnow().isoformat(),
            "verdict": "benign",
            "final_score": 0.0,
            "payload_predictions": [],
            "behavioral_score": 0.0,
            "explain": {"summary": f"Analysis failed: {reason}"}
        }
    
    def save_verdict(self, verdict: Dict):
        """Save verdict to disk"""
        try:
            verdicts_dir = os.path.join(
                os.path.dirname(__file__), '..', '..', 'data', 'verdicts'
            )
            os.makedirs(verdicts_dir, exist_ok=True)
            
            session_id = verdict["session_id"]
            verdict_file = os.path.join(verdicts_dir, f"{session_id}_verdict.json")
            
            with open(verdict_file, 'w') as f:
                json.dump(verdict, f, indent=2)
            
            logger.info(f"Verdict saved: {verdict_file}")
        
        except Exception as e:
            logger.error(f"Error saving verdict: {e}", exc_info=True)


# CLI entry point
if __name__ == "__main__":
    engine = InferenceEngine()
    
    # Example evidence
    sample_evidence = {
        "session_id": "test_sqli_001",
        "har": {
            "log": {
                "entries": [
                    {
                        "startedDateTime": "2025-11-08T22:00:00Z",
                        "time": 150,
                        "request": {
                            "method": "GET",
                            "url": "http://example.com/admin?id=1' OR '1'='1",
                            "headers": [{"name": "User-Agent", "value": "sqlmap/1.0"}],
                            "queryString": [{"name": "id", "value": "1' OR '1'='1"}]
                        },
                        "response": {"status": 500, "bodySize": 1024}
                    }
                ] * 10  # 10 similar requests
            }
        },
        "extracted_payloads": [
            {
                "id": "p1",
                "type": "sql_injection",
                "value": "1' OR '1'='1",
                "confidence": 0.95
            }
        ],
        "enrichment": {
            "tags": ["poi", "sql_injection-suspected"],
            "meta": {}
        }
    }
    
    verdict = engine.analyze(sample_evidence)
    
    print("\n=== Analysis Result ===\n")
    print(json.dumps(verdict, indent=2))
