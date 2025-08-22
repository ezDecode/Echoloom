"""
Data encryption and security utilities for Echoloom.
Provides encryption at rest, key management, and secure data handling.
"""

import os
import base64
import secrets
import hashlib
import json
import logging
from typing import Dict, Any, Optional, Union, List
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configure encryption logging
encryption_logger = logging.getLogger("echoloom.encryption")

@dataclass
class EncryptionConfig:
    """Configuration for encryption settings"""
    encryption_enabled: bool = True
    key_rotation_days: int = 90
    backup_keys_count: int = 3
    use_hardware_security_module: bool = False
    key_derivation_iterations: int = 100000

@dataclass
class EncryptedData:
    """Container for encrypted data with metadata"""
    encrypted_content: str
    key_id: str
    algorithm: str
    created_at: str
    iv: Optional[str] = None
    tag: Optional[str] = None

class KeyManager:
    """Secure key management system"""
    
    def __init__(self, key_dir: str = "keys"):
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(exist_ok=True, mode=0o700)  # Restrictive permissions
        self.config = EncryptionConfig()
        self._active_keys: Dict[str, bytes] = {}
        self._load_keys()
    
    def _load_keys(self) -> None:
        """Load encryption keys from secure storage"""
        master_key_path = self.key_dir / "master.key"
        
        if not master_key_path.exists():
            self._generate_master_key()
        
        try:
            with open(master_key_path, 'rb') as f:
                self._master_key = f.read()
            encryption_logger.info("Master key loaded successfully")
        except Exception as e:
            encryption_logger.error(f"Failed to load master key: {e}")
            raise
    
    def _generate_master_key(self) -> None:
        """Generate a new master encryption key"""
        master_key = Fernet.generate_key()
        master_key_path = self.key_dir / "master.key"
        
        try:
            with open(master_key_path, 'wb') as f:
                f.write(master_key)
            os.chmod(master_key_path, 0o600)  # Read-write for owner only
            self._master_key = master_key
            encryption_logger.info("New master key generated")
        except Exception as e:
            encryption_logger.error(f"Failed to generate master key: {e}")
            raise
    
    def get_encryption_key(self, key_id: str = "default") -> bytes:
        """Get or generate encryption key for specific use"""
        if key_id in self._active_keys:
            return self._active_keys[key_id]
        
        # Derive key from master key
        key_info = f"echoloom-{key_id}".encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=key_info,
            iterations=self.config.key_derivation_iterations,
        )
        
        derived_key = kdf.derive(self._master_key)
        self._active_keys[key_id] = derived_key
        
        encryption_logger.debug(f"Derived encryption key for: {key_id}")
        return derived_key
    
    def rotate_keys(self) -> None:
        """Rotate encryption keys for security"""
        encryption_logger.info("Starting key rotation")
        
        # Backup current master key
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.key_dir / f"master_backup_{timestamp}.key"
        
        try:
            master_key_path = self.key_dir / "master.key"
            if master_key_path.exists():
                with open(master_key_path, 'rb') as src, open(backup_path, 'wb') as dst:
                    dst.write(src.read())
                os.chmod(backup_path, 0o600)
        
            # Generate new master key
            self._generate_master_key()
            self._active_keys.clear()  # Clear cached keys
            
            encryption_logger.info("Key rotation completed successfully")
            
        except Exception as e:
            encryption_logger.error(f"Key rotation failed: {e}")
            raise
    
    def cleanup_old_keys(self) -> None:
        """Remove old backup keys beyond retention limit"""
        backup_files = list(self.key_dir.glob("master_backup_*.key"))
        if len(backup_files) > self.config.backup_keys_count:
            # Sort by creation time and remove oldest
            backup_files.sort(key=lambda x: x.stat().st_ctime)
            for old_key in backup_files[:-self.config.backup_keys_count]:
                old_key.unlink()
                encryption_logger.info(f"Removed old backup key: {old_key.name}")

class DataEncryption:
    """Main data encryption service"""
    
    def __init__(self, key_manager: KeyManager = None):
        self.key_manager = key_manager or KeyManager()
        self.config = EncryptionConfig()
    
    def encrypt_data(self, data: Union[str, bytes, dict], key_id: str = "default") -> EncryptedData:
        """Encrypt data with specified key"""
        if not self.config.encryption_enabled:
            encryption_logger.warning("Encryption disabled - returning plaintext")
            return EncryptedData(
                encrypted_content=str(data),
                key_id=key_id,
                algorithm="none",
                created_at=datetime.now().isoformat()
            )
        
        try:
            # Convert data to bytes
            if isinstance(data, dict):
                data_bytes = json.dumps(data).encode('utf-8')
            elif isinstance(data, str):
                data_bytes = data.encode('utf-8')
            else:
                data_bytes = data
            
            # Get encryption key
            key = self.key_manager.get_encryption_key(key_id)
            
            # Use Fernet for symmetric encryption (AES 128 in CBC mode)
            fernet = Fernet(base64.urlsafe_b64encode(key))
            encrypted_bytes = fernet.encrypt(data_bytes)
            
            # Encode for storage
            encrypted_content = base64.b64encode(encrypted_bytes).decode('utf-8')
            
            result = EncryptedData(
                encrypted_content=encrypted_content,
                key_id=key_id,
                algorithm="fernet-aes128-cbc",
                created_at=datetime.now().isoformat()
            )
            
            encryption_logger.debug(f"Data encrypted with key: {key_id}")
            return result
            
        except Exception as e:
            encryption_logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt_data(self, encrypted_data: EncryptedData) -> Union[str, bytes, dict]:
        """Decrypt encrypted data"""
        if not self.config.encryption_enabled or encrypted_data.algorithm == "none":
            return encrypted_data.encrypted_content
        
        try:
            # Get decryption key
            key = self.key_manager.get_encryption_key(encrypted_data.key_id)
            
            if encrypted_data.algorithm == "fernet-aes128-cbc":
                # Decode from storage format
                encrypted_bytes = base64.b64decode(encrypted_data.encrypted_content.encode('utf-8'))
                
                # Decrypt with Fernet
                fernet = Fernet(base64.urlsafe_b64encode(key))
                decrypted_bytes = fernet.decrypt(encrypted_bytes)
                
                # Try to parse as JSON, fallback to string
                try:
                    return json.loads(decrypted_bytes.decode('utf-8'))
                except json.JSONDecodeError:
                    return decrypted_bytes.decode('utf-8')
            
            else:
                raise ValueError(f"Unsupported encryption algorithm: {encrypted_data.algorithm}")
                
        except Exception as e:
            encryption_logger.error(f"Decryption failed: {e}")
            raise
    
    def encrypt_file(self, file_path: str, output_path: str = None, key_id: str = "files") -> str:
        """Encrypt a file and save to disk"""
        input_path = Path(file_path)
        if not input_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        output_path = Path(output_path or f"{file_path}.encrypted")
        
        try:
            # Read file content
            with open(input_path, 'rb') as f:
                file_content = f.read()
            
            # Encrypt content
            encrypted_data = self.encrypt_data(file_content, key_id)
            
            # Save encrypted file with metadata
            encrypted_file_data = {
                'metadata': asdict(encrypted_data),
                'content': encrypted_data.encrypted_content
            }
            
            with open(output_path, 'w') as f:
                json.dump(encrypted_file_data, f)
            
            encryption_logger.info(f"File encrypted: {input_path} -> {output_path}")
            return str(output_path)
            
        except Exception as e:
            encryption_logger.error(f"File encryption failed: {e}")
            raise
    
    def decrypt_file(self, encrypted_file_path: str, output_path: str = None) -> str:
        """Decrypt an encrypted file"""
        input_path = Path(encrypted_file_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Encrypted file not found: {encrypted_file_path}")
        
        try:
            # Read encrypted file
            with open(input_path, 'r') as f:
                encrypted_file_data = json.load(f)
            
            # Reconstruct encrypted data object
            encrypted_data = EncryptedData(**encrypted_file_data['metadata'])
            
            # Decrypt content
            decrypted_content = self.decrypt_data(encrypted_data)
            
            # Save decrypted file
            output_path = Path(output_path or input_path.with_suffix('').name)
            
            if isinstance(decrypted_content, bytes):
                with open(output_path, 'wb') as f:
                    f.write(decrypted_content)
            else:
                with open(output_path, 'w') as f:
                    f.write(str(decrypted_content))
            
            encryption_logger.info(f"File decrypted: {input_path} -> {output_path}")
            return str(output_path)
            
        except Exception as e:
            encryption_logger.error(f"File decryption failed: {e}")
            raise

class SecureStorage:
    """Secure storage interface with encryption"""
    
    def __init__(self, storage_dir: str = "secure_data", encryption: DataEncryption = None):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True, mode=0o700)
        self.encryption = encryption or DataEncryption()
    
    def store_secure_data(self, key: str, data: Any, category: str = "general") -> None:
        """Store data securely with encryption"""
        try:
            # Encrypt the data
            encrypted_data = self.encryption.encrypt_data(data, f"{category}-{key}")
            
            # Create category directory
            category_dir = self.storage_dir / category
            category_dir.mkdir(exist_ok=True, mode=0o700)
            
            # Store encrypted data
            file_path = category_dir / f"{key}.enc"
            with open(file_path, 'w') as f:
                json.dump(asdict(encrypted_data), f)
            
            os.chmod(file_path, 0o600)  # Restrictive permissions
            encryption_logger.info(f"Secure data stored: {category}/{key}")
            
        except Exception as e:
            encryption_logger.error(f"Failed to store secure data: {e}")
            raise
    
    def retrieve_secure_data(self, key: str, category: str = "general") -> Any:
        """Retrieve and decrypt stored data"""
        try:
            file_path = self.storage_dir / category / f"{key}.enc"
            
            if not file_path.exists():
                raise FileNotFoundError(f"Secure data not found: {category}/{key}")
            
            # Load encrypted data
            with open(file_path, 'r') as f:
                encrypted_dict = json.load(f)
            
            encrypted_data = EncryptedData(**encrypted_dict)
            
            # Decrypt and return
            decrypted_data = self.encryption.decrypt_data(encrypted_data)
            encryption_logger.debug(f"Secure data retrieved: {category}/{key}")
            
            return decrypted_data
            
        except Exception as e:
            encryption_logger.error(f"Failed to retrieve secure data: {e}")
            raise
    
    def delete_secure_data(self, key: str, category: str = "general") -> None:
        """Securely delete stored data"""
        try:
            file_path = self.storage_dir / category / f"{key}.enc"
            
            if file_path.exists():
                # Overwrite file with random data before deletion
                file_size = file_path.stat().st_size
                with open(file_path, 'wb') as f:
                    f.write(secrets.token_bytes(file_size))
                
                file_path.unlink()
                encryption_logger.info(f"Secure data deleted: {category}/{key}")
            
        except Exception as e:
            encryption_logger.error(f"Failed to delete secure data: {e}")
            raise
    
    def list_secure_data(self, category: str = "general") -> List[str]:
        """List available secure data keys"""
        category_dir = self.storage_dir / category
        
        if not category_dir.exists():
            return []
        
        return [f.stem for f in category_dir.glob("*.enc")]

# Global instances
_key_manager = KeyManager()
_encryption = DataEncryption(_key_manager)
_secure_storage = SecureStorage(encryption=_encryption)

# Convenience functions
def encrypt_sensitive_data(data: Any, key_id: str = "default") -> EncryptedData:
    """Encrypt sensitive data"""
    return _encryption.encrypt_data(data, key_id)

def decrypt_sensitive_data(encrypted_data: EncryptedData) -> Any:
    """Decrypt sensitive data"""
    return _encryption.decrypt_data(encrypted_data)

def store_encrypted(key: str, data: Any, category: str = "general") -> None:
    """Store data with encryption"""
    _secure_storage.store_secure_data(key, data, category)

def retrieve_encrypted(key: str, category: str = "general") -> Any:
    """Retrieve encrypted data"""
    return _secure_storage.retrieve_secure_data(key, category)

def secure_delete(key: str, category: str = "general") -> None:
    """Securely delete encrypted data"""
    _secure_storage.delete_secure_data(key, category)

def rotate_encryption_keys() -> None:
    """Rotate all encryption keys"""
    _key_manager.rotate_keys()