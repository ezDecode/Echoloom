import time
import secrets
import hashlib
import logging
from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Set
import re

from fastapi import Header, HTTPException, status, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, validator
import bleach

from .config import get_api_keys, get_rate_limit_per_minute

# Configure security logging
security_logger = logging.getLogger("echoloom.security")

# Request tracking for rate limiting
_request_log: Dict[str, Deque[float]] = defaultdict(deque)

# Security constants
MAX_MESSAGE_LENGTH = 10000  # Maximum message length
MAX_REQUEST_SIZE = 1024 * 1024  # 1MB max request size
ALLOWED_HTML_TAGS = []  # No HTML allowed in inputs
SUSPICIOUS_PATTERNS = [
    r'<script[^>]*>.*?</script>',  # Script tags
    r'javascript:',               # JavaScript URLs
    r'on\w+\s*=',                # Event handlers
    r'<iframe[^>]*>',            # Iframes
    r'eval\s*\(',                # eval() calls
    r'document\.',               # DOM access
    r'window\.',                 # Window object access
    r'\bselect\b.*\bfrom\b',     # SQL SELECT
    r'\binsert\b.*\binto\b',     # SQL INSERT
    r'\bupdate\b.*\bset\b',      # SQL UPDATE
    r'\bdelete\b.*\bfrom\b',     # SQL DELETE
    r'\bdrop\b.*\btable\b',      # SQL DROP
    r'\bunion\b.*\bselect\b',    # SQL UNION
]

class SecurityConfig:
    """Security configuration settings"""
    REQUIRE_HTTPS = True
    ENABLE_SECURITY_HEADERS = True
    LOG_SECURITY_EVENTS = True
    BLOCK_SUSPICIOUS_PATTERNS = True
    ENABLE_INPUT_SANITIZATION = True

class SecurityViolation(Exception):
    """Raised when a security violation is detected"""
    def __init__(self, violation_type: str, details: str):
        self.violation_type = violation_type
        self.details = details
        super().__init__(f"Security violation: {violation_type} - {details}")

class InputValidator:
    """Comprehensive input validation and sanitization"""
    
    def __init__(self):
        self.suspicious_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in SUSPICIOUS_PATTERNS]
    
    def validate_message(self, message: str) -> str:
        """Validate and sanitize user message input"""
        if not message or not isinstance(message, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Message must be a non-empty string"
            )
        
        # Length validation
        if len(message) > MAX_MESSAGE_LENGTH:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Message too long. Maximum length: {MAX_MESSAGE_LENGTH}"
            )
        
        # Check for suspicious patterns
        if SecurityConfig.BLOCK_SUSPICIOUS_PATTERNS:
            for pattern in self.suspicious_patterns:
                if pattern.search(message):
                    security_logger.warning(f"Suspicious pattern detected: {pattern.pattern}")
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Message contains potentially harmful content"
                    )
        
        # HTML sanitization
        if SecurityConfig.ENABLE_INPUT_SANITIZATION:
            sanitized = bleach.clean(message, tags=ALLOWED_HTML_TAGS, strip=True)
            if sanitized != message:
                security_logger.info("HTML content stripped from message")
                message = sanitized
        
        return message.strip()
    
    def validate_api_key(self, api_key: str) -> bool:
        """Validate API key format and strength"""
        if not api_key:
            return False
        
        # Check for development/weak keys
        weak_keys = {'dev-key-123', 'test', 'admin', 'password', '123456'}
        if api_key.lower() in weak_keys:
            security_logger.warning(f"Weak API key detected: {api_key}")
            return False
        
        # Minimum length requirement
        if len(api_key) < 16:
            return False
        
        return True

# Global validator instance
_validator = InputValidator()

def generate_secure_api_key() -> str:
    """Generate a cryptographically secure API key"""
    return secrets.token_urlsafe(32)

def hash_api_key(api_key: str) -> str:
    """Hash API key for secure storage"""
    salt = secrets.token_bytes(32)
    key_hash = hashlib.pbkdf2_hmac('sha256', api_key.encode(), salt, 100000)
    return salt.hex() + key_hash.hex()

def verify_api_key_hash(api_key: str, stored_hash: str) -> bool:
    """Verify API key against stored hash"""
    try:
        salt = bytes.fromhex(stored_hash[:64])
        stored_key_hash = stored_hash[64:]
        key_hash = hashlib.pbkdf2_hmac('sha256', api_key.encode(), salt, 100000)
        return key_hash.hex() == stored_key_hash
    except (ValueError, IndexError):
        return False

def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Enhanced API key validation with security logging"""
    if not x_api_key:
        security_logger.warning("API request without key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="API key required",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    # Validate key format
    if not _validator.validate_api_key(x_api_key):
        security_logger.warning(f"Invalid API key format: {x_api_key[:8]}...")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid API key format"
        )
    
    # Check against configured keys
    keys = get_api_keys()
    if x_api_key not in keys:
        security_logger.warning(f"Unauthorized API key: {x_api_key[:8]}...")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid API key"
        )
    
    security_logger.debug(f"Valid API key authenticated: {x_api_key[:8]}...")

def rate_limit(request: Request, x_api_key: str | None = Header(default=None)) -> None:
    """Enhanced rate limiting with security logging"""
    # Only enforce limit on chat endpoint
    if request.url.path != "/chat":
        return
    
    limit = get_rate_limit_per_minute()
    window = 60.0
    now = time.time()
    
    # Use API key or IP for rate limiting
    identifier = x_api_key or request.client.host if request.client else "unknown"
    log = _request_log[identifier]
    
    # Purge old requests
    while log and now - log[0] > window:
        log.popleft()
    
    if len(log) >= limit:
        security_logger.warning(f"Rate limit exceeded for {identifier}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, 
            detail="Rate limit exceeded. Please try again later.",
            headers={"Retry-After": "60"}
        )
    
    log.append(now)

def validate_request_size(request: Request) -> None:
    """Validate request size to prevent DoS attacks"""
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_REQUEST_SIZE:
        security_logger.warning(f"Request too large: {content_length} bytes")
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Request too large. Maximum size: {MAX_REQUEST_SIZE} bytes"
        )

def add_security_headers(response: Response) -> Response:
    """Add comprehensive security headers to response"""
    if not SecurityConfig.ENABLE_SECURITY_HEADERS:
        return response
    
    security_headers = {
        # Prevent XSS attacks
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        
        # Content Security Policy
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        ),
        
        # HTTPS enforcement
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        
        # Referrer policy
        "Referrer-Policy": "strict-origin-when-cross-origin",
        
        # Permissions policy
        "Permissions-Policy": (
            "camera=(), microphone=(), geolocation=(), "
            "payment=(), usb=(), magnetometer=(), gyroscope=()"
        )
    }
    
    for header, value in security_headers.items():
        response.headers[header] = value
    
    return response

def log_security_event(event_type: str, details: dict, request: Request = None) -> None:
    """Log security events for monitoring and analysis"""
    if not SecurityConfig.LOG_SECURITY_EVENTS:
        return
    
    event_data = {
        "timestamp": time.time(),
        "event_type": event_type,
        "details": details
    }
    
    if request:
        event_data.update({
            "client_ip": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("user-agent", "unknown"),
            "endpoint": str(request.url.path),
            "method": request.method
        })
    
    security_logger.info(f"Security event: {event_type}", extra=event_data)

class SecureMessageRequest(BaseModel):
    """Secure message request model with validation"""
    message: str
    
    @validator('message')
    def validate_message(cls, v):
        return _validator.validate_message(v)
    
    class Config:
        max_anystr_length = MAX_MESSAGE_LENGTH

def check_https_requirement(request: Request) -> None:
    """Enforce HTTPS in production environments"""
    if not SecurityConfig.REQUIRE_HTTPS:
        return
    
    # Check if request is over HTTPS
    if request.url.scheme != "https":
        # Allow HTTP for localhost/development
        if request.client and request.client.host in ["127.0.0.1", "localhost"]:
            return
        
        security_logger.warning(f"HTTP request rejected: {request.url}")
        raise HTTPException(
            status_code=status.HTTP_426_UPGRADE_REQUIRED,
            detail="HTTPS required"
        )

# Security monitoring functions
def get_security_metrics() -> dict:
    """Get security-related metrics for monitoring"""
    return {
        "active_rate_limits": len(_request_log),
        "total_requests_tracked": sum(len(log) for log in _request_log.values()),
        "security_config": {
            "require_https": SecurityConfig.REQUIRE_HTTPS,
            "security_headers_enabled": SecurityConfig.ENABLE_SECURITY_HEADERS,
            "input_sanitization_enabled": SecurityConfig.ENABLE_INPUT_SANITIZATION,
            "suspicious_pattern_blocking": SecurityConfig.BLOCK_SUSPICIOUS_PATTERNS
        }
    }

def reset_rate_limits() -> None:
    """Reset all rate limiting data (for testing/admin use)"""
    _request_log.clear()
    security_logger.info("Rate limiting data reset")