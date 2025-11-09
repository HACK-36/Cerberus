"""
Stage 2: Feature Extraction - ML-based feature engineering
Converts raw evidence into model-ready structured features
"""
import json
import re
import hashlib
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import numpy as np
from urllib.parse import urlparse, parse_qs
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.utils.logging import get_logger
from shared.utils.metrics import EVIDENCE_OPERATIONS

logger = get_logger(__name__)


class FeatureExtractor:
    """
    Extract ML-ready features from raw evidence packages
    
    Produces:
    - Static features (method, path depth, param count, etc.)
    - Payload features (tokenized text, n-grams, entropy)
    - Behavioral features (sequence embeddings)
    - Metadata features (geo, IP reputation, etc.)
    """
    
    # SQL injection keywords
    SQL_KEYWORDS = [
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
        'UNION', 'WHERE', 'FROM', 'ORDER', 'GROUP', 'HAVING', 'EXEC',
        'EXECUTE', 'CAST', 'CONVERT', 'DECLARE', 'WAITFOR', 'BENCHMARK'
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r'<script[^>]*>',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe',
        r'<object',
        r'<embed'
    ]
    
    # Command injection patterns
    CMD_PATTERNS = [
        r'[;&|]\s*(cat|ls|whoami|wget|curl|bash|sh|nc|id|pwd)',
        r'\$\(.*?\)',
        r'`.*?`'
    ]
    
    def __init__(self):
        logger.info("Feature extractor initialized")
    
    def extract(self, evidence: Dict) -> Dict:
        """
        Main extraction pipeline
        
        Args:
            evidence: Raw evidence package from MinIO
            
        Returns:
            Feature vector dict with all extracted features
        """
        session_id = evidence.get("session_id", "unknown")
        logger.info(f"Extracting features for session: {session_id}")
        
        try:
            # Parse HAR data
            har_data = evidence.get("har", {})
            requests = self._parse_har(har_data)
            
            # Extract payloads
            payloads = evidence.get("extracted_payloads", [])
            
            # Static features
            static_features = self._extract_static_features(requests)
            
            # Payload features
            payload_features = self._extract_payload_features(payloads, requests)
            
            # Behavioral features
            behavioral_features = self._extract_behavioral_features(requests)
            
            # Metadata features
            metadata_features = self._extract_metadata_features(evidence)
            
            # Combine all features
            feature_vector = {
                "session_id": session_id,
                "timestamp": datetime.utcnow().isoformat(),
                **static_features,
                **payload_features,
                **behavioral_features,
                **metadata_features
            }
            
            logger.info(f"Feature extraction complete for {session_id}: {len(feature_vector)} features")
            EVIDENCE_OPERATIONS.labels(operation="feature_extract", status="success").inc()
            
            return feature_vector
        
        except Exception as e:
            logger.error(f"Error extracting features: {e}", exc_info=True)
            EVIDENCE_OPERATIONS.labels(operation="feature_extract", status="failed").inc()
            return {}
    
    def _parse_har(self, har_data: Dict) -> List[Dict]:
        """Parse HAR format and extract request timeline"""
        try:
            entries = har_data.get("log", {}).get("entries", [])
            
            requests = []
            for entry in entries:
                request = entry.get("request", {})
                response = entry.get("response", {})
                
                requests.append({
                    "timestamp": entry.get("startedDateTime"),
                    "time_ms": entry.get("time", 0),
                    "method": request.get("method", "GET"),
                    "url": request.get("url", ""),
                    "headers": {h["name"]: h["value"] for h in request.get("headers", [])},
                    "query_params": {p["name"]: p["value"] for p in request.get("queryString", [])},
                    "post_data": request.get("postData", {}).get("text", ""),
                    "response_status": response.get("status", 0),
                    "response_size": response.get("bodySize", 0)
                })
            
            return requests
        
        except Exception as e:
            logger.error(f"Error parsing HAR: {e}")
            return []
    
    def _extract_static_features(self, requests: List[Dict]) -> Dict:
        """
        Extract static request-level features
        
        Features:
        - Request count
        - HTTP methods distribution
        - Path depth statistics
        - Parameter count statistics
        - Response status codes
        """
        if not requests:
            return {
                "n_requests": 0,
                "method_diversity": 0,
                "avg_path_depth": 0,
                "avg_param_count": 0,
                "error_rate": 0
            }
        
        methods = [r["method"] for r in requests]
        
        # Parse URLs
        paths = []
        param_counts = []
        status_codes = []
        
        for req in requests:
            url = req["url"]
            parsed = urlparse(url)
            
            # Path depth
            path_parts = [p for p in parsed.path.split("/") if p]
            paths.append(len(path_parts))
            
            # Param count
            params = parse_qs(parsed.query)
            param_counts.append(len(params))
            
            # Status
            status_codes.append(req["response_status"])
        
        # Calculate features
        features = {
            "n_requests": len(requests),
            "method_diversity": len(set(methods)) / len(methods),
            "method_get_ratio": methods.count("GET") / len(methods),
            "method_post_ratio": methods.count("POST") / len(methods),
            "avg_path_depth": np.mean(paths),
            "max_path_depth": np.max(paths),
            "avg_param_count": np.mean(param_counts),
            "max_param_count": np.max(param_counts),
            "error_rate": sum(1 for s in status_codes if s >= 400) / len(status_codes),
            "avg_response_size": np.mean([r["response_size"] for r in requests]),
            "total_time_ms": sum(r["time_ms"] for r in requests)
        }
        
        return features
    
    def _extract_payload_features(self, payloads: List[Dict], requests: List[Dict]) -> Dict:
        """
        Extract payload-specific features
        
        Features:
        - Payload count and types
        - Entropy
        - Length statistics
        - Keyword presence
        - N-grams
        """
        if not payloads:
            return {
                "n_payloads": 0,
                "max_payload_entropy": 0,
                "avg_payload_length": 0,
                "contains_sql_keywords": 0,
                "contains_xss_patterns": 0,
                "contains_cmd_patterns": 0
            }
        
        payload_texts = [p.get("value", "") for p in payloads]
        
        # Entropy
        entropies = [self._calculate_entropy(text) for text in payload_texts]
        
        # Lengths
        lengths = [len(text) for text in payload_texts]
        
        # Keyword detection
        combined_text = " ".join(payload_texts).upper()
        contains_sql = any(kw in combined_text for kw in self.SQL_KEYWORDS)
        
        # Pattern detection
        combined_lower = combined_text.lower()
        contains_xss = any(re.search(pattern, combined_lower) for pattern in self.XSS_PATTERNS)
        contains_cmd = any(re.search(pattern, combined_lower) for pattern in self.CMD_PATTERNS)
        
        # Special characters
        special_char_ratio = sum(
            sum(1 for c in text if not c.isalnum()) / (len(text) + 1)
            for text in payload_texts
        ) / len(payload_texts)
        
        features = {
            "n_payloads": len(payloads),
            "max_payload_entropy": max(entropies) if entropies else 0,
            "avg_payload_entropy": np.mean(entropies) if entropies else 0,
            "avg_payload_length": np.mean(lengths),
            "max_payload_length": max(lengths),
            "contains_sql_keywords": 1 if contains_sql else 0,
            "contains_xss_patterns": 1 if contains_xss else 0,
            "contains_cmd_patterns": 1 if contains_cmd else 0,
            "special_char_ratio": special_char_ratio
        }
        
        return features
    
    def _extract_behavioral_features(self, requests: List[Dict]) -> Dict:
        """
        Extract behavioral sequence features
        
        Features:
        - Request timing patterns
        - Endpoint sequence patterns
        - User-Agent fingerprint
        - Cookie behavior
        """
        if not requests:
            return {
                "avg_inter_request_ms": 0,
                "request_rate_per_min": 0,
                "ua_fingerprint_score": 0,
                "session_age_seconds": 0
            }
        
        # Timing analysis
        timestamps = [
            datetime.fromisoformat(r["timestamp"].replace("Z", "+00:00"))
            for r in requests if r["timestamp"]
        ]
        
        if len(timestamps) > 1:
            deltas = [(timestamps[i+1] - timestamps[i]).total_seconds() * 1000
                     for i in range(len(timestamps) - 1)]
            avg_inter_request_ms = np.mean(deltas)
            session_duration = (timestamps[-1] - timestamps[0]).total_seconds()
            request_rate = len(requests) / (session_duration / 60) if session_duration > 0 else 0
        else:
            avg_inter_request_ms = 0
            session_duration = 0
            request_rate = 0
        
        # User-Agent fingerprinting
        user_agents = [r["headers"].get("User-Agent", "") for r in requests]
        ua_changes = len(set(user_agents))
        ua_fingerprint_score = ua_changes / len(requests)  # More changes = more suspicious
        
        # Endpoint diversity
        endpoints = [urlparse(r["url"]).path for r in requests]
        endpoint_diversity = len(set(endpoints)) / len(requests)
        
        features = {
            "avg_inter_request_ms": avg_inter_request_ms,
            "request_rate_per_min": request_rate,
            "ua_fingerprint_score": ua_fingerprint_score,
            "session_age_seconds": session_duration,
            "endpoint_diversity": endpoint_diversity,
            "ua_changes": ua_changes
        }
        
        return features
    
    def _extract_metadata_features(self, evidence: Dict) -> Dict:
        """
        Extract metadata features
        
        Features:
        - GeoIP data
        - IP reputation
        - Prior POI count
        - Tags
        """
        enrichment = evidence.get("enrichment", {})
        meta = enrichment.get("meta", {})
        
        # Tags analysis
        tags = enrichment.get("tags", [])
        tag_score = len([t for t in tags if "injection" in t or "xss" in t or "attack" in t]) / (len(tags) + 1)
        
        features = {
            "has_poi_tag": 1 if "poi" in tags else 0,
            "tag_severity_score": tag_score,
            "n_tags": len(tags),
            "is_from_tor": meta.get("is_tor", 0),
            "is_from_vpn": meta.get("is_vpn", 0),
            "prior_poi_count": meta.get("prior_poi_count", 0)
        }
        
        return features
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        # Count character frequencies
        freqs = {}
        for char in text:
            freqs[char] = freqs.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        
        for count in freqs.values():
            prob = count / text_len
            entropy -= prob * np.log2(prob)
        
        return entropy
    
    def save_features(self, session_id: str, features: Dict):
        """Save feature vector to disk"""
        try:
            # Create features directory
            features_dir = os.path.join(
                os.path.dirname(__file__), '..', '..', 'data', 'features'
            )
            os.makedirs(features_dir, exist_ok=True)
            
            # Save features
            feature_file = os.path.join(features_dir, f"{session_id}_features.json")
            with open(feature_file, 'w') as f:
                json.dump(features, f, indent=2)
            
            logger.info(f"Features saved: {feature_file}")
        
        except Exception as e:
            logger.error(f"Error saving features: {e}", exc_info=True)
    
    def create_sequence_embedding(self, requests: List[Dict]) -> np.ndarray:
        """
        Create sequence embedding for temporal models
        
        In production: use transformer/LSTM to encode request sequence
        For now: simple hand-crafted embedding
        """
        if not requests:
            return np.zeros(128)  # 128-dim embedding
        
        # Extract sequence of operations
        operations = []
        for req in requests:
            method = req["method"]
            path = urlparse(req["url"]).path
            
            # Encode operation
            op_vector = self._encode_operation(method, path)
            operations.append(op_vector)
        
        # Aggregate into single embedding (mean pooling)
        embedding = np.mean(operations, axis=0) if operations else np.zeros(128)
        
        return embedding
    
    def _encode_operation(self, method: str, path: str) -> np.ndarray:
        """
        Encode single operation (method + path) into vector
        
        Simple hash-based encoding for now
        In production: use learned embeddings
        """
        # Create simple feature vector
        vector = np.zeros(128)
        
        # Method encoding (one-hot-ish)
        method_map = {"GET": 0, "POST": 32, "PUT": 64, "DELETE": 96}
        method_idx = method_map.get(method, 16)
        vector[method_idx:method_idx+8] = 1.0
        
        # Path encoding (hash-based)
        path_hash = int(hashlib.md5(path.encode()).hexdigest()[:8], 16)
        hash_indices = [path_hash % 128, (path_hash // 128) % 128, (path_hash // 256) % 128]
        for idx in hash_indices:
            vector[idx] = 1.0
        
        return vector


# CLI entry point
if __name__ == "__main__":
    extractor = FeatureExtractor()
    
    # Example usage
    sample_evidence = {
        "session_id": "test_123",
        "har": {
            "log": {
                "entries": [
                    {
                        "startedDateTime": "2025-11-08T22:00:00Z",
                        "time": 150,
                        "request": {
                            "method": "GET",
                            "url": "http://example.com/admin?id=1' OR '1'='1",
                            "headers": [{"name": "User-Agent", "value": "Mozilla/5.0"}],
                            "queryString": [{"name": "id", "value": "1' OR '1'='1"}]
                        },
                        "response": {"status": 200, "bodySize": 1024}
                    }
                ]
            }
        },
        "extracted_payloads": [
            {"type": "sql_injection", "value": "1' OR '1'='1", "confidence": 0.95}
        ],
        "enrichment": {
            "tags": ["poi", "sql_injection-suspected"],
            "meta": {}
        }
    }
    
    features = extractor.extract(sample_evidence)
    print(json.dumps(features, indent=2))
