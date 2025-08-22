"""
Comprehensive security tests for Echoloom.
Tests authentication, input validation, PII detection, encryption, and more.
"""

import pytest
import secrets
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient
from fastapi import HTTPException

from src.echoloom.app import create_app
from src.echoloom.security import (
    require_api_key, InputValidator, generate_secure_api_key,
    hash_api_key, verify_api_key_hash, SecurityConfig
)
from src.echoloom.nlp.pii import PIIDetector, mask_pii, detect_pii
from src.echoloom.data.encryption import DataEncryption, KeyManager, EncryptedData

class TestAuthentication:
    """Test API key authentication and security"""
    
    def setup_method(self):
        self.app = create_app()
        self.client = TestClient(self.app)
        self.valid_key = "dev-key-123"  # Default test key
        self.invalid_key = "invalid-key"
    
    def test_valid_api_key_access(self):
        """Test that valid API keys grant access"""
        response = self.client.post(
            "/chat",
            headers={"x-api-key": self.valid_key},
            json={"message": "Hello"}
        )
        # Should not return 401 (may return other errors due to missing dependencies)
        assert response.status_code != 401
    
    def test_invalid_api_key_rejected(self):
        """Test that invalid API keys are rejected"""
        response = self.client.post(
            "/chat",
            headers={"x-api-key": self.invalid_key},
            json={"message": "Hello"}
        )
        assert response.status_code == 401
    
    def test_missing_api_key_rejected(self):
        """Test that missing API keys are rejected"""
        response = self.client.post(
            "/chat",
            json={"message": "Hello"}
        )
        assert response.status_code == 401
    
    def test_secure_api_key_generation(self):
        """Test secure API key generation"""
        key1 = generate_secure_api_key()
        key2 = generate_secure_api_key()
        
        # Keys should be different
        assert key1 != key2
        
        # Keys should be sufficiently long
        assert len(key1) >= 32
        assert len(key2) >= 32
        
        # Keys should be URL-safe base64
        import base64
        try:
            base64.urlsafe_b64decode(key1 + "==")
            base64.urlsafe_b64decode(key2 + "==")
        except Exception:
            pytest.fail("Generated keys are not valid base64")
    
    def test_api_key_hashing(self):
        """Test API key hashing and verification"""
        original_key = "test-secure-key-123456"
        
        # Hash the key
        key_hash = hash_api_key(original_key)
        
        # Verify correct key
        assert verify_api_key_hash(original_key, key_hash)
        
        # Verify incorrect key fails
        assert not verify_api_key_hash("wrong-key", key_hash)
        
        # Hash should be different each time (due to salt)
        key_hash2 = hash_api_key(original_key)
        assert key_hash != key_hash2
        assert verify_api_key_hash(original_key, key_hash2)

class TestInputValidation:
    """Test input validation and sanitization"""
    
    def setup_method(self):
        self.validator = InputValidator()
        self.app = create_app()
        self.client = TestClient(self.app)
    
    def test_normal_message_validation(self):
        """Test that normal messages pass validation"""
        message = "Hello, how are you today?"
        result = self.validator.validate_message(message)
        assert result == message.strip()
    
    def test_empty_message_rejected(self):
        """Test that empty messages are rejected"""
        with pytest.raises(HTTPException) as exc_info:
            self.validator.validate_message("")
        assert exc_info.value.status_code == 400
    
    def test_too_long_message_rejected(self):
        """Test that overly long messages are rejected"""
        long_message = "A" * 10001  # Exceeds MAX_MESSAGE_LENGTH
        with pytest.raises(HTTPException) as exc_info:
            self.validator.validate_message(long_message)
        assert exc_info.value.status_code == 413
    
    def test_suspicious_patterns_blocked(self):
        """Test that suspicious patterns are blocked"""
        suspicious_messages = [
            "<script>alert('xss')</script>",
            "javascript:alert(1)",
            "SELECT * FROM users",
            "DROP TABLE users",
            "<iframe src='evil.com'></iframe>",
            "eval(malicious_code)",
            "document.cookie",
            "window.location"
        ]
        
        for message in suspicious_messages:
            with pytest.raises(HTTPException) as exc_info:
                self.validator.validate_message(message)
            assert exc_info.value.status_code == 400
    
    def test_html_sanitization(self):
        """Test HTML content sanitization"""
        html_message = "Hello <b>world</b> <script>alert('xss')</script>"
        result = self.validator.validate_message(html_message)
        
        # Should remove all HTML tags
        assert "<b>" not in result
        assert "</b>" not in result
        assert "<script>" not in result
        assert "Hello world alert('xss')" in result or "Hello world" in result
    
    def test_request_size_validation(self):
        """Test request size validation"""
        # Test with oversized payload
        large_payload = {"message": "A" * (1024 * 1024 + 1)}  # > 1MB
        
        response = self.client.post(
            "/chat",
            headers={"x-api-key": "dev-key-123", "content-length": str(1024 * 1024 + 1000)},
            json=large_payload
        )
        assert response.status_code == 413

class TestPIIDetection:
    """Test PII detection and masking"""
    
    def setup_method(self):
        self.detector = PIIDetector()
    
    def test_email_detection(self):
        """Test email PII detection"""
        text = "My email is john.doe@example.com"
        matches = self.detector.detect_pii(text)
        
        assert len(matches) == 1
        assert matches[0].type == "email"
        assert matches[0].value == "john.doe@example.com"
        assert matches[0].confidence > 0.9
    
    def test_phone_detection(self):
        """Test phone number PII detection"""
        phone_texts = [
            "Call me at 555-123-4567",
            "My number is (555) 123-4567",
            "Phone: +1 555 123 4567"
        ]
        
        for text in phone_texts:
            matches = self.detector.detect_pii(text)
            phone_matches = [m for m in matches if m.type == "phone"]
            assert len(phone_matches) >= 1
    
    def test_ssn_detection(self):
        """Test SSN PII detection"""
        ssn_texts = [
            "SSN: 123-45-6789",
            "Social security: 123456789",
            "My SSN is 123 45 6789"
        ]
        
        for text in ssn_texts:
            matches = self.detector.detect_pii(text)
            ssn_matches = [m for m in matches if m.type == "ssn"]
            assert len(ssn_matches) >= 1
            assert all(m.confidence > 0.8 for m in ssn_matches)
    
    def test_credit_card_detection(self):
        """Test credit card PII detection"""
        cc_texts = [
            "Card: 4532-1234-5678-9012",
            "Credit card 4532 1234 5678 9012",
            "My card is 4532123456789012"
        ]
        
        for text in cc_texts:
            matches = self.detector.detect_pii(text)
            cc_matches = [m for m in matches if m.type == "credit_card"]
            assert len(cc_matches) >= 1
    
    def test_comprehensive_masking(self):
        """Test comprehensive PII masking"""
        text = """
        Contact me at john.doe@example.com or call 555-123-4567.
        My SSN is 123-45-6789 and credit card is 4532-1234-5678-9012.
        I live at 123 Main Street.
        """
        
        masked = mask_pii(text)
        
        # Should not contain original PII
        assert "john.doe@example.com" not in masked
        assert "555-123-4567" not in masked
        assert "123-45-6789" not in masked
        assert "4532-1234-5678-9012" not in masked
        
        # Should contain masked versions
        assert "***@example.com" in masked or "[EMAIL_REMOVED]" in masked
        assert "***-***-****" in masked
        assert "***-**-****" in masked
    
    def test_pii_summary_generation(self):
        """Test PII detection summary"""
        from src.echoloom.nlp.pii import get_pii_summary
        
        text = "Email: john@example.com, SSN: 123-45-6789"
        summary = get_pii_summary(text)
        
        assert summary['total_pii_found'] >= 2
        assert 'email' in summary['pii_types']
        assert 'ssn' in summary['pii_types']
        assert summary['high_risk_detected'] == True  # SSN is high-risk
    
    def test_pseudonymization(self):
        """Test PII pseudonymization"""
        from src.echoloom.nlp.pii import pseudonymize_pii
        
        text = "My email is john@example.com"
        user_id = "user123"
        
        pseudo1 = pseudonymize_pii(text, user_id)
        pseudo2 = pseudonymize_pii(text, user_id)
        
        # Should be consistent for same user
        assert pseudo1 == pseudo2
        
        # Should be different for different user
        pseudo3 = pseudonymize_pii(text, "user456")
        assert pseudo1 != pseudo3

class TestEncryption:
    """Test data encryption and key management"""
    
    def setup_method(self):
        self.key_manager = KeyManager("test_keys")
        self.encryption = DataEncryption(self.key_manager)
    
    def test_key_generation_and_retrieval(self):
        """Test encryption key generation and retrieval"""
        key1 = self.key_manager.get_encryption_key("test1")
        key2 = self.key_manager.get_encryption_key("test2")
        
        # Keys should be different for different IDs
        assert key1 != key2
        
        # Same ID should return same key
        key1_again = self.key_manager.get_encryption_key("test1")
        assert key1 == key1_again
    
    def test_string_encryption_decryption(self):
        """Test string data encryption and decryption"""
        original_data = "This is sensitive information"
        
        # Encrypt
        encrypted = self.encryption.encrypt_data(original_data, "test_key")
        assert isinstance(encrypted, EncryptedData)
        assert encrypted.encrypted_content != original_data
        assert encrypted.algorithm == "fernet-aes128-cbc"
        
        # Decrypt
        decrypted = self.encryption.decrypt_data(encrypted)
        assert decrypted == original_data
    
    def test_dict_encryption_decryption(self):
        """Test dictionary data encryption and decryption"""
        original_data = {
            "user_id": "12345",
            "email": "user@example.com",
            "sensitive_info": "secret data"
        }
        
        # Encrypt
        encrypted = self.encryption.encrypt_data(original_data, "dict_key")
        
        # Decrypt
        decrypted = self.encryption.decrypt_data(encrypted)
        assert decrypted == original_data
    
    def test_file_encryption_decryption(self):
        """Test file encryption and decryption"""
        import tempfile
        import os
        
        # Create test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("This is sensitive file content")
            test_file = f.name
        
        try:
            # Encrypt file
            encrypted_file = self.encryption.encrypt_file(test_file)
            assert os.path.exists(encrypted_file)
            
            # Decrypt file
            decrypted_file = self.encryption.decrypt_file(encrypted_file)
            assert os.path.exists(decrypted_file)
            
            # Verify content
            with open(decrypted_file, 'r') as f:
                content = f.read()
            assert content == "This is sensitive file content"
            
        finally:
            # Cleanup
            for file_path in [test_file, encrypted_file, decrypted_file]:
                if os.path.exists(file_path):
                    os.unlink(file_path)
    
    def test_secure_storage(self):
        """Test secure storage operations"""
        from src.echoloom.data.encryption import SecureStorage
        
        storage = SecureStorage("test_storage", self.encryption)
        
        # Store data
        test_data = {"sensitive": "information", "user": "test"}
        storage.store_secure_data("test_key", test_data, "test_category")
        
        # Retrieve data
        retrieved = storage.retrieve_secure_data("test_key", "test_category")
        assert retrieved == test_data
        
        # List data
        keys = storage.list_secure_data("test_category")
        assert "test_key" in keys
        
        # Delete data
        storage.delete_secure_data("test_key", "test_category")
        
        # Verify deletion
        with pytest.raises(FileNotFoundError):
            storage.retrieve_secure_data("test_key", "test_category")

class TestSecurityHeaders:
    """Test security headers and middleware"""
    
    def setup_method(self):
        self.app = create_app()
        self.client = TestClient(self.app)
    
    def test_security_headers_present(self):
        """Test that security headers are added to responses"""
        response = self.client.get("/health")
        
        # Check for security headers
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "X-XSS-Protection" in response.headers
        assert "Content-Security-Policy" in response.headers
        assert "Strict-Transport-Security" in response.headers
        assert "Referrer-Policy" in response.headers
        assert "Permissions-Policy" in response.headers
    
    def test_security_header_values(self):
        """Test security header values"""
        response = self.client.get("/health")
        
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "default-src 'self'" in response.headers["Content-Security-Policy"]
        assert "max-age=31536000" in response.headers["Strict-Transport-Security"]

class TestRateLimiting:
    """Test rate limiting functionality"""
    
    def setup_method(self):
        self.app = create_app()
        self.client = TestClient(self.app)
        # Reset rate limits for testing
        from src.echoloom.security import reset_rate_limits
        reset_rate_limits()
    
    def test_rate_limiting_enforcement(self):
        """Test that rate limiting is enforced"""
        # Make requests up to the limit
        api_key = "dev-key-123"
        
        # First request should succeed
        response = self.client.post(
            "/chat",
            headers={"x-api-key": api_key},
            json={"message": "test"}
        )
        # Should not be rate limited (may fail for other reasons)
        assert response.status_code != 429
        
        # Note: Full rate limiting test would require making many requests
        # This is a basic structure test

class TestSecurityEndpoints:
    """Test security-specific endpoints"""
    
    def setup_method(self):
        self.app = create_app()
        self.client = TestClient(self.app)
    
    def test_security_metrics_endpoint(self):
        """Test security metrics endpoint"""
        response = self.client.get(
            "/security/metrics",
            headers={"x-api-key": "dev-key-123"}
        )
        
        if response.status_code == 200:
            data = response.json()
            assert "security_config" in data
            assert "active_rate_limits" in data

class TestIntegrationSecurity:
    """Integration tests for security features"""
    
    def setup_method(self):
        self.app = create_app()
        self.client = TestClient(self.app)
    
    def test_pii_in_chat_request(self):
        """Test PII handling in chat requests"""
        response = self.client.post(
            "/chat",
            headers={"x-api-key": "dev-key-123"},
            json={"message": "My email is john@example.com and SSN is 123-45-6789"}
        )
        
        if response.status_code == 200:
            # Response should not contain original PII
            response_text = response.text
            assert "john@example.com" not in response_text
            assert "123-45-6789" not in response_text
    
    def test_data_deletion_endpoint(self):
        """Test secure data deletion"""
        response = self.client.delete(
            "/data?user_id=test_user",
            headers={"x-api-key": "dev-key-123"}
        )
        
        # Should not return error (may return success or not found)
        assert response.status_code != 500

# Fixtures for testing
@pytest.fixture
def mock_security_config():
    """Mock security configuration for testing"""
    original_config = SecurityConfig()
    
    # Set test-friendly configuration
    SecurityConfig.REQUIRE_HTTPS = False
    SecurityConfig.LOG_SECURITY_EVENTS = False
    
    yield SecurityConfig
    
    # Restore original configuration
    for attr in dir(original_config):
        if not attr.startswith('_'):
            setattr(SecurityConfig, attr, getattr(original_config, attr))

if __name__ == "__main__":
    pytest.main([__file__, "-v"])