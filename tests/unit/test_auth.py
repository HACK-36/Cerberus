"""
Unit tests for Authentication System
"""
import pytest
from datetime import datetime, timedelta

from shared.auth.jwt_handler import (
    create_access_token,
    decode_token,
    verify_token,
    get_password_hash,
    verify_password,
    create_api_key,
    hash_api_key,
    verify_api_key,
    get_service_token,
    verify_service_api_key,
    TokenData
)


class TestJWTHandler:
    """Test suite for JWT authentication"""
    
    def test_create_and_decode_token(self):
        """Test token creation and decoding"""
        token = create_access_token(
            data={
                "username": "admin",
                "service": "gatekeeper",
                "roles": ["admin"]
            }
        )
        
        assert token is not None
        assert isinstance(token, str)
        
        # Decode token
        token_data = decode_token(token)
        assert token_data is not None
        assert token_data.username == "admin"
        assert token_data.service == "gatekeeper"
        assert "admin" in token_data.roles
    
    def test_token_with_custom_expiry(self):
        """Test token with custom expiration"""
        token = create_access_token(
            data={"username": "test", "service": "test", "roles": []},
            expires_delta=timedelta(minutes=5)
        )
        
        token_data = decode_token(token)
        assert token_data is not None
    
    def test_invalid_token_returns_none(self):
        """Test that invalid token returns None"""
        invalid_token = "invalid.token.here"
        token_data = decode_token(invalid_token)
        assert token_data is None
    
    def test_verify_token_with_service(self):
        """Test token verification with service requirement"""
        token = create_access_token(
            data={"username": "gatekeeper", "service": "gatekeeper", "roles": ["service"]}
        )
        
        # Correct service
        assert verify_token(token, required_service="gatekeeper") == True
        
        # Wrong service
        assert verify_token(token, required_service="sentinel") == False
    
    def test_verify_token_with_roles(self):
        """Test token verification with role requirements"""
        # Admin token
        admin_token = create_access_token(
            data={"username": "admin", "service": "gatekeeper", "roles": ["admin"]}
        )
        
        assert verify_token(admin_token, required_roles=["admin"]) == True
        assert verify_token(admin_token, required_roles=["readonly"]) == False
        
        # Multiple roles
        analyst_token = create_access_token(
            data={"username": "analyst", "service": "sentinel", "roles": ["analyst", "readonly"]}
        )
        
        assert verify_token(analyst_token, required_roles=["analyst"]) == True
        assert verify_token(analyst_token, required_roles=["readonly"]) == True
        assert verify_token(analyst_token, required_roles=["admin"]) == False


class TestPasswordHashing:
    """Test suite for password hashing"""
    
    def test_password_hashing(self):
        """Test password hash and verify"""
        password = "test_password_123"
        hashed = get_password_hash(password)
        
        assert hashed != password
        assert len(hashed) > 20
        assert verify_password(password, hashed) == True
    
    def test_wrong_password_fails(self):
        """Test wrong password verification fails"""
        password = "correct_password"
        wrong_password = "wrong_password"
        
        hashed = get_password_hash(password)
        assert verify_password(wrong_password, hashed) == False
    
    def test_same_password_different_hashes(self):
        """Test that same password produces different hashes (salt)"""
        password = "test_password"
        hash1 = get_password_hash(password)
        hash2 = get_password_hash(password)
        
        # Different hashes (due to salt)
        assert hash1 != hash2
        
        # Both verify correctly
        assert verify_password(password, hash1) == True
        assert verify_password(password, hash2) == True


class TestAPIKeys:
    """Test suite for API key management"""
    
    def test_create_api_key_format(self):
        """Test API key creation format"""
        api_key = create_api_key("test-user", "gatekeeper")
        
        assert api_key.startswith("cerberus_gatekeeper_")
        assert len(api_key) > 30
    
    def test_hash_and_verify_api_key(self):
        """Test API key hashing and verification"""
        api_key = create_api_key("test-user", "sentinel")
        hashed_key = hash_api_key(api_key)
        
        assert hashed_key != api_key
        assert verify_api_key(api_key, hashed_key) == True
    
    def test_wrong_api_key_fails_verification(self):
        """Test wrong API key fails verification"""
        api_key = create_api_key("test", "test")
        hashed_key = hash_api_key(api_key)
        
        wrong_key = create_api_key("test", "test")  # Different key
        assert verify_api_key(wrong_key, hashed_key) == False


class TestServiceAccounts:
    """Test suite for service accounts"""
    
    def test_get_service_token(self):
        """Test getting service token"""
        token = get_service_token("gatekeeper")
        assert token is not None
        
        token_data = decode_token(token)
        assert token_data is not None
        assert token_data.service == "gatekeeper"
        assert "service" in token_data.roles
    
    def test_get_service_token_invalid_service(self):
        """Test getting token for invalid service"""
        token = get_service_token("invalid_service")
        assert token is None
    
    def test_verify_service_api_key(self):
        """Test service API key verification"""
        # Using predefined service API key from environment defaults
        service_info = verify_service_api_key("gatekeeper-dev-key-change-me")
        
        assert service_info is not None
        assert service_info["service"] == "gatekeeper"
        assert "service" in service_info["roles"]
    
    def test_verify_invalid_service_api_key(self):
        """Test invalid service API key returns None"""
        service_info = verify_service_api_key("invalid-api-key")
        assert service_info is None
    
    def test_all_service_accounts_exist(self):
        """Test that all expected service accounts exist"""
        expected_services = ["gatekeeper", "switch", "labyrinth", "sentinel", "warroom"]
        
        for service in expected_services:
            token = get_service_token(service)
            assert token is not None, f"Service {service} should have account"
            
            token_data = decode_token(token)
            assert token_data.service == service


class TestTokenData:
    """Test TokenData model"""
    
    def test_token_data_creation(self):
        """Test TokenData model creation"""
        token_data = TokenData(
            username="test_user",
            service="gatekeeper",
            roles=["admin", "analyst"]
        )
        
        assert token_data.username == "test_user"
        assert token_data.service == "gatekeeper"
        assert len(token_data.roles) == 2
        assert "admin" in token_data.roles
    
    def test_token_data_with_optional_fields(self):
        """Test TokenData with optional expiry"""
        exp_time = datetime.utcnow() + timedelta(hours=1)
        token_data = TokenData(
            username="test",
            service="test",
            roles=[],
            exp=exp_time
        )
        
        assert token_data.exp == exp_time


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
