import re
import hashlib
from typing import List, Tuple, Dict, Any
from dataclasses import dataclass

# Comprehensive PII patterns
EMAIL_RE = re.compile(r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?[0-9]{3}\)?[-.\s]?)?[0-9]{3}[-.\s]?[0-9]{4}\b")
SSN_RE = re.compile(r"\b(?:\d{3}[-.\s]?\d{2}[-.\s]?\d{4}|\d{9})\b")
CREDIT_CARD_RE = re.compile(r"\b(?:\d{4}[-.\s]?){3}\d{4}\b")
IP_ADDRESS_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
URL_RE = re.compile(r"https?://[^\s<>\"']+")
PASSPORT_RE = re.compile(r"\b[A-Z]{1,2}[0-9]{6,9}\b")
DRIVER_LICENSE_RE = re.compile(r"\b[A-Z]{1,2}[0-9]{6,8}\b")
BANK_ACCOUNT_RE = re.compile(r"\b[0-9]{8,17}\b")
DATE_OF_BIRTH_RE = re.compile(r"\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12][0-9]|3[01])[/-](?:19|20)\d{2}\b")

# Address patterns (basic)
ADDRESS_RE = re.compile(r"\b\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Circle|Cir|Way|Place|Pl)\b", re.IGNORECASE)

# Name patterns (common first/last name combinations)
NAME_RE = re.compile(r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b")

@dataclass
class PIIMatch:
    """Represents a detected PII match"""
    type: str
    value: str
    start: int
    end: int
    confidence: float
    masked_value: str

class PIIDetector:
    """Enhanced PII detection and masking system"""
    
    def __init__(self):
        self.patterns = {
            'email': EMAIL_RE,
            'phone': PHONE_RE,
            'ssn': SSN_RE,
            'credit_card': CREDIT_CARD_RE,
            'ip_address': IP_ADDRESS_RE,
            'url': URL_RE,
            'passport': PASSPORT_RE,
            'driver_license': DRIVER_LICENSE_RE,
            'bank_account': BANK_ACCOUNT_RE,
            'date_of_birth': DATE_OF_BIRTH_RE,
            'address': ADDRESS_RE,
            'name': NAME_RE
        }
        
        self.masking_strategies = {
            'email': self._mask_email,
            'phone': lambda x: "***-***-****",
            'ssn': lambda x: "***-**-****",
            'credit_card': lambda x: "****-****-****-" + x[-4:] if len(x) >= 4 else "****-****-****-****",
            'ip_address': lambda x: "***.***.***.***.***",
            'url': lambda x: "[URL_REMOVED]",
            'passport': lambda x: "[PASSPORT_REMOVED]",
            'driver_license': lambda x: "[LICENSE_REMOVED]",
            'bank_account': lambda x: "[ACCOUNT_REMOVED]",
            'date_of_birth': lambda x: "**/**/****",
            'address': lambda x: "[ADDRESS_REMOVED]",
            'name': lambda x: "[NAME_REMOVED]"
        }
        
        # High-risk patterns that should never appear in logs
        self.high_risk_patterns = {'ssn', 'credit_card', 'bank_account', 'passport', 'driver_license'}
    
    def _mask_email(self, email: str) -> str:
        """Mask email while preserving domain for debugging"""
        if '@' in email:
            local, domain = email.split('@', 1)
            masked_local = local[0] + '*' * (len(local) - 1) if len(local) > 1 else '*'
            return f"{masked_local}@{domain}"
        return "[EMAIL_REMOVED]"
    
    def detect_pii(self, text: str) -> List[PIIMatch]:
        """Detect all PII in text and return matches with metadata"""
        matches = []
        
        for pii_type, pattern in self.patterns.items():
            for match in pattern.finditer(text):
                confidence = self._calculate_confidence(pii_type, match.group())
                if confidence > 0.5:  # Only include high-confidence matches
                    masked_value = self.masking_strategies[pii_type](match.group())
                    matches.append(PIIMatch(
                        type=pii_type,
                        value=match.group(),
                        start=match.start(),
                        end=match.end(),
                        confidence=confidence,
                        masked_value=masked_value
                    ))
        
        # Sort by position to handle overlapping matches
        return sorted(matches, key=lambda x: x.start)
    
    def _calculate_confidence(self, pii_type: str, value: str) -> float:
        """Calculate confidence score for PII detection"""
        # Basic confidence scoring - in production, use ML models
        confidence_scores = {
            'email': 0.95 if '@' in value and '.' in value else 0.3,
            'phone': 0.9 if len(re.sub(r'[^\d]', '', value)) >= 10 else 0.5,
            'ssn': 0.95 if len(re.sub(r'[^\d]', '', value)) == 9 else 0.6,
            'credit_card': 0.9 if len(re.sub(r'[^\d]', '', value)) >= 13 else 0.5,
            'ip_address': 0.8,
            'url': 0.9 if value.startswith(('http://', 'https://')) else 0.6,
            'passport': 0.8,
            'driver_license': 0.7,
            'bank_account': 0.7,
            'date_of_birth': 0.8,
            'address': 0.6,  # Lower confidence as it's more prone to false positives
            'name': 0.4      # Very low confidence for names to avoid false positives
        }
        return confidence_scores.get(pii_type, 0.5)
    
    def mask_pii(self, text: str, preserve_structure: bool = True) -> str:
        """Mask PII in text while optionally preserving structure"""
        matches = self.detect_pii(text)
        if not matches:
            return text
        
        # Apply masking from end to start to maintain indices
        result = text
        for match in reversed(matches):
            result = result[:match.start] + match.masked_value + result[match.end:]
        
        return result
    
    def get_pii_summary(self, text: str) -> Dict[str, Any]:
        """Get summary of PII found in text for logging/auditing"""
        matches = self.detect_pii(text)
        summary = {
            'total_pii_found': len(matches),
            'pii_types': list(set(match.type for match in matches)),
            'high_risk_detected': any(match.type in self.high_risk_patterns for match in matches),
            'matches': [
                {
                    'type': match.type,
                    'confidence': match.confidence,
                    'position': f"{match.start}-{match.end}"
                } for match in matches
            ]
        }
        return summary
    
    def pseudonymize_pii(self, text: str, user_id: str = None) -> str:
        """Replace PII with consistent pseudonyms for the same user"""
        matches = self.detect_pii(text)
        if not matches:
            return text
        
        result = text
        for match in reversed(matches):
            # Generate consistent pseudonym based on user_id and original value
            if user_id:
                seed = f"{user_id}_{match.type}_{match.value}"
                hash_obj = hashlib.sha256(seed.encode())
                pseudo_id = hash_obj.hexdigest()[:8]
                pseudonym = f"[{match.type.upper()}_{pseudo_id}]"
            else:
                pseudonym = match.masked_value
            
            result = result[:match.start] + pseudonym + result[match.end:]
        
        return result

# Global detector instance
_detector = PIIDetector()

# Backward compatibility functions
def mask_pii(text: str) -> str:
    """Mask PII in text - backward compatible function"""
    return _detector.mask_pii(text)

def detect_pii(text: str) -> List[PIIMatch]:
    """Detect PII in text"""
    return _detector.detect_pii(text)

def get_pii_summary(text: str) -> Dict[str, Any]:
    """Get PII detection summary"""
    return _detector.get_pii_summary(text)

def pseudonymize_pii(text: str, user_id: str = None) -> str:
    """Pseudonymize PII in text"""
    return _detector.pseudonymize_pii(text, user_id)