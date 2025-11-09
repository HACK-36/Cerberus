"""
Stage 9: Model Server - High-performance model serving with caching and monitoring
Optimized for low-latency inference with Prometheus metrics
"""
import json
import os
import time
from typing import Dict, Optional
from datetime import datetime, timedelta
from functools import lru_cache

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from sentinel.ml.payload_classifier import PayloadClassifier
from sentinel.ml.anomaly_detector import BehavioralAnomalyDetector
from sentinel.ml.inference_engine import InferenceEngine
from shared.utils.logging import get_logger
from shared.utils.metrics import (
    SENTINEL_INFERENCE_LATENCY,
    SENTINEL_PREDICTIONS,
    SENTINEL_CACHE_HITS
)

logger = get_logger(__name__)


class ModelServer:
    """
    Production model serving with:
    - Model caching and warming
    - Prediction caching
    - Performance monitoring
    - Canary routing
    - Circuit breaker
    """
    
    # Performance settings
    CACHE_SIZE = 10000  # Cache up to 10k predictions
    CACHE_TTL_SECONDS = 3600  # 1 hour TTL
    INFERENCE_TIMEOUT_MS = 5000  # 5 second timeout
    
    # Circuit breaker settings
    ERROR_THRESHOLD = 0.2  # Open circuit if 20% errors
    ERROR_WINDOW_SIZE = 100  # Track last 100 requests
    
    def __init__(self, canary_percent: int = 0):
        """
        Args:
            canary_percent: Percentage of traffic to route to canary model (0-100)
        """
        self.canary_percent = canary_percent
        
        # Initialize models
        self.production_engine = InferenceEngine()
        self.canary_engine = None  # Loaded only if canary enabled
        
        # Prediction cache
        self.prediction_cache: Dict[str, Dict] = {}
        self.cache_timestamps: Dict[str, datetime] = {}
        
        # Circuit breaker state
        self.recent_errors = []
        self.circuit_open = False
        
        # Warm up models
        self._warm_up()
        
        logger.info(f"Model server initialized (canary={canary_percent}%)")
    
    def predict(self, evidence: Dict, use_cache: bool = True) -> Dict:
        """
        Main prediction endpoint with caching and monitoring
        
        Args:
            evidence: Evidence package
            use_cache: Whether to use prediction cache
            
        Returns:
            Prediction dict with verdict and scores
        """
        start_time = time.time()
        
        try:
            session_id = evidence.get("session_id", "unknown")
            
            # Check circuit breaker
            if self.circuit_open:
                logger.warning("Circuit breaker OPEN - returning degraded response")
                return self._degraded_prediction(session_id)
            
            # Check cache
            if use_cache:
                cached = self._get_from_cache(session_id)
                if cached:
                    SENTINEL_CACHE_HITS.labels(cache_type="prediction", status="hit").inc()
                    
                    # Record latency (cache hit)
                    latency_ms = (time.time() - start_time) * 1000
                    SENTINEL_INFERENCE_LATENCY.labels(model="cached").observe(latency_ms / 1000)
                    
                    return cached
            
            SENTINEL_CACHE_HITS.labels(cache_type="prediction", status="miss").inc()
            
            # Select engine (canary or production)
            engine = self._select_engine()
            
            # Run inference
            prediction = engine.analyze(evidence)
            
            # Cache result
            if use_cache:
                self._add_to_cache(session_id, prediction)
            
            # Record success
            self._record_result(success=True)
            
            # Emit metrics
            verdict = prediction.get("verdict", "unknown")
            SENTINEL_PREDICTIONS.labels(verdict=verdict, model="production").inc()
            
            # Record latency
            latency_ms = (time.time() - start_time) * 1000
            SENTINEL_INFERENCE_LATENCY.labels(model="production").observe(latency_ms / 1000)
            
            logger.info(
                f"Prediction complete: session={session_id}, verdict={verdict}, "
                f"latency={latency_ms:.1f}ms"
            )
            
            return prediction
        
        except Exception as e:
            logger.error(f"Prediction error: {e}", exc_info=True)
            
            # Record failure
            self._record_result(success=False)
            
            # Return degraded prediction
            return self._degraded_prediction(evidence.get("session_id", "unknown"))
    
    def predict_payload(self, payload: str, context: Dict = None) -> Dict:
        """
        Fast payload-only prediction (for inline inspection)
        
        Optimized for low latency (<10ms target)
        """
        start_time = time.time()
        
        try:
            # Check cache
            cache_key = self._payload_cache_key(payload)
            cached = self._get_from_cache(cache_key)
            
            if cached:
                SENTINEL_CACHE_HITS.labels(cache_type="payload", status="hit").inc()
                return cached
            
            SENTINEL_CACHE_HITS.labels(cache_type="payload", status="miss").inc()
            
            # Fast classification
            classifier = self.production_engine.payload_classifier
            prediction = classifier.predict(payload, context)
            
            # Cache
            self._add_to_cache(cache_key, prediction)
            
            # Metrics
            latency_ms = (time.time() - start_time) * 1000
            SENTINEL_INFERENCE_LATENCY.labels(model="payload_only").observe(latency_ms / 1000)
            
            logger.debug(f"Payload prediction: {prediction['class']} ({latency_ms:.1f}ms)")
            
            return prediction
        
        except Exception as e:
            logger.error(f"Payload prediction error: {e}")
            return {"class": "benign", "confidence": 0.0, "error": str(e)}
    
    def _select_engine(self) -> InferenceEngine:
        """
        Select engine based on canary routing
        
        Routes canary_percent% of traffic to canary model
        """
        if self.canary_percent == 0 or not self.canary_engine:
            return self.production_engine
        
        # Simple random routing based on timestamp
        if (int(time.time() * 1000) % 100) < self.canary_percent:
            logger.debug("Routing to CANARY model")
            return self.canary_engine
        
        return self.production_engine
    
    def _get_from_cache(self, key: str) -> Optional[Dict]:
        """Get prediction from cache if not expired"""
        if key not in self.prediction_cache:
            return None
        
        # Check TTL
        timestamp = self.cache_timestamps.get(key)
        if timestamp:
            age = (datetime.utcnow() - timestamp).total_seconds()
            if age > self.CACHE_TTL_SECONDS:
                # Expired
                del self.prediction_cache[key]
                del self.cache_timestamps[key]
                return None
        
        return self.prediction_cache[key]
    
    def _add_to_cache(self, key: str, prediction: Dict):
        """Add prediction to cache"""
        # LRU eviction if cache full
        if len(self.prediction_cache) >= self.CACHE_SIZE:
            # Remove oldest entry
            oldest_key = min(self.cache_timestamps, key=self.cache_timestamps.get)
            del self.prediction_cache[oldest_key]
            del self.cache_timestamps[oldest_key]
        
        self.prediction_cache[key] = prediction
        self.cache_timestamps[key] = datetime.utcnow()
    
    def _payload_cache_key(self, payload: str) -> str:
        """Generate cache key for payload"""
        import hashlib
        return f"payload_{hashlib.md5(payload.encode()).hexdigest()[:16]}"
    
    def _record_result(self, success: bool):
        """Record result for circuit breaker"""
        self.recent_errors.append(0 if success else 1)
        
        # Keep only last ERROR_WINDOW_SIZE results
        if len(self.recent_errors) > self.ERROR_WINDOW_SIZE:
            self.recent_errors.pop(0)
        
        # Check if circuit should open
        if len(self.recent_errors) >= self.ERROR_WINDOW_SIZE:
            error_rate = sum(self.recent_errors) / len(self.recent_errors)
            
            if error_rate >= self.ERROR_THRESHOLD:
                if not self.circuit_open:
                    logger.error(
                        f"Circuit breaker OPENED: error_rate={error_rate:.2%} "
                        f">= threshold={self.ERROR_THRESHOLD:.2%}"
                    )
                    self.circuit_open = True
            else:
                if self.circuit_open:
                    logger.info("Circuit breaker CLOSED: error rate normalized")
                    self.circuit_open = False
    
    def _degraded_prediction(self, session_id: str) -> Dict:
        """Return degraded prediction when service unhealthy"""
        return {
            "session_id": session_id,
            "timestamp": datetime.utcnow().isoformat(),
            "verdict": "tag",  # Conservative fallback
            "final_score": 0.5,
            "degraded": True,
            "reason": "circuit_breaker_open" if self.circuit_open else "error",
            "explain": {"summary": "Service degraded - using fallback classification"}
        }
    
    def _warm_up(self):
        """
        Warm up models by running test predictions
        
        Ensures models are loaded and JIT compiled
        """
        logger.info("Warming up models...")
        
        try:
            # Test payload prediction
            test_payload = "SELECT * FROM users"
            self.production_engine.payload_classifier.predict(test_payload)
            
            # Test full analysis (minimal evidence)
            test_evidence = {
                "session_id": "warmup_test",
                "har": {"log": {"entries": []}},
                "extracted_payloads": [],
                "enrichment": {"tags": [], "meta": {}}
            }
            self.production_engine.analyze(test_evidence)
            
            logger.info("Model warmup complete")
        
        except Exception as e:
            logger.warning(f"Model warmup failed: {e}")
    
    def get_health(self) -> Dict:
        """Get health status"""
        return {
            "status": "degraded" if self.circuit_open else "healthy",
            "circuit_breaker": {
                "open": self.circuit_open,
                "recent_error_rate": sum(self.recent_errors) / len(self.recent_errors)
                if self.recent_errors else 0
            },
            "cache": {
                "size": len(self.prediction_cache),
                "max_size": self.CACHE_SIZE
            },
            "canary_percent": self.canary_percent
        }
    
    def clear_cache(self):
        """Clear prediction cache"""
        self.prediction_cache.clear()
        self.cache_timestamps.clear()
        logger.info("Prediction cache cleared")


# Singleton instance
_model_server_instance: Optional[ModelServer] = None


def get_model_server(canary_percent: int = 0) -> ModelServer:
    """Get singleton model server instance"""
    global _model_server_instance
    
    if _model_server_instance is None:
        _model_server_instance = ModelServer(canary_percent=canary_percent)
    
    return _model_server_instance


# CLI entry point
if __name__ == "__main__":
    server = get_model_server()
    
    # Test prediction
    sample_evidence = {
        "session_id": "test_server_001",
        "har": {
            "log": {
                "entries": [
                    {
                        "startedDateTime": "2025-11-08T22:00:00Z",
                        "time": 150,
                        "request": {
                            "method": "GET",
                            "url": "http://example.com/admin?id=1' OR '1'='1",
                            "headers": [],
                            "queryString": []
                        },
                        "response": {"status": 500, "bodySize": 1024}
                    }
                ]
            }
        },
        "extracted_payloads": [
            {"value": "1' OR '1'='1"}
        ],
        "enrichment": {"tags": ["poi"], "meta": {}}
    }
    
    # Test full prediction
    print("\n=== Testing Full Prediction ===\n")
    result1 = server.predict(sample_evidence)
    print(f"Verdict: {result1.get('verdict')}, Score: {result1.get('final_score')}")
    
    # Test cache hit
    result2 = server.predict(sample_evidence)
    print(f"Cache hit: {result1 == result2}")
    
    # Test fast payload prediction
    print("\n=== Testing Fast Payload Prediction ===\n")
    payload_result = server.predict_payload("1' OR '1'='1")
    print(f"Class: {payload_result['class']}, Confidence: {payload_result['confidence']}")
    
    # Health check
    print("\n=== Health Status ===\n")
    health = server.get_health()
    print(json.dumps(health, indent=2))
