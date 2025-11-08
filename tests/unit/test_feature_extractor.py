"""
Unit tests for Feature Extractor
"""
import pytest
from gatekeeper.ml.feature_extractor import FeatureExtractor


class TestFeatureExtractor:
    
    def setup_method(self):
        self.extractor = FeatureExtractor()
    
    def test_basic_features_extraction(self):
        """Test basic request feature extraction"""
        request = {
            "method": "GET",
            "url": "/api/users?id=1",
            "headers": {"User-Agent": "Mozilla/5.0", "Host": "example.com"},
            "body": "",
            "query_params": {"id": "1"}
        }
        
        features = self.extractor.extract(request)
        
        assert "request_length" in features
        assert "method_is_get" in features
        assert features["method_is_get"] == 1.0
        assert features["has_query_params"] == 1.0
        assert len(features) == 102  # All 102 features extracted
    
    def test_sql_injection_detection(self):
        """Test SQL injection pattern detection"""
        request = {
            "method": "GET",
            "url": "/users?id=1' OR '1'='1",
            "headers": {},
            "body": "",
            "query_params": {"id": "1' OR '1'='1"}
        }
        
        features = self.extractor.extract(request)
        
        assert features["sql_keyword_count"] > 0
        assert features["quote_count"] > 0
        assert features["has_select"] == 0.0  # No SELECT in this payload
        assert features["has_union"] == 0.0
    
    def test_xss_pattern_detection(self):
        """Test XSS pattern detection"""
        request = {
            "method": "POST",
            "url": "/comment",
            "headers": {"Content-Type": "application/json"},
            "body": '{"text":"<script>alert(1)</script>"}',
            "query_params": {}
        }
        
        features = self.extractor.extract(request)
        
        assert features["xss_pattern_count"] > 0
        assert features["has_script_tag"] == 1.0
        assert features["angle_bracket_count"] > 0
    
    def test_entropy_calculation(self):
        """Test entropy features"""
        # High entropy (random) string
        random_request = {
            "method": "GET",
            "url": "/api?token=xK9mP2nQ7vR4sT1w",
            "headers": {},
            "body": "",
            "query_params": {}
        }
        
        features_random = self.extractor.extract(random_request)
        
        # Low entropy (normal) string
        normal_request = {
            "method": "GET",
            "url": "/api/users",
            "headers": {},
            "body": "",
            "query_params": {}
        }
        
        features_normal = self.extractor.extract(normal_request)
        
        # Random string should have higher entropy
        assert features_random["entropy_url"] > features_normal["entropy_url"]
    
    def test_command_injection_detection(self):
        """Test command injection pattern detection"""
        request = {
            "method": "POST",
            "url": "/exec",
            "headers": {},
            "body": "cmd=ls -la; cat /etc/passwd",
            "query_params": {}
        }
        
        features = self.extractor.extract(request)
        
        assert features["command_pattern_count"] > 0
        assert features["semicolon_count"] > 0
    
    def test_path_traversal_detection(self):
        """Test path traversal detection"""
        request = {
            "method": "GET",
            "url": "/files?path=../../../../etc/passwd",
            "headers": {},
            "body": "",
            "query_params": {"path": "../../../../etc/passwd"}
        }
        
        features = self.extractor.extract(request)
        
        assert features["path_traversal_count"] > 0
        assert features["dot_dot_slash"] > 0
    
    def test_consistent_feature_count(self):
        """Test that all requests return exactly 102 features"""
        requests = [
            {"method": "GET", "url": "/", "headers": {}, "body": "", "query_params": {}},
            {"method": "POST", "url": "/api/users", "headers": {}, "body": '{"name":"test"}', "query_params": {}},
            {"method": "DELETE", "url": "/api/users/1", "headers": {}, "body": "", "query_params": {}}
        ]
        
        for req in requests:
            features = self.extractor.extract(req)
            assert len(features) == 102, f"Expected 102 features, got {len(features)}"
