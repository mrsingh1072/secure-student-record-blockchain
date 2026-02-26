"""
Encryption utilities for secure data storage using Fernet (AES 128).

Enhancements (v2):
  - EncryptionError / DecryptionError typed exceptions
  - Key-versioned ciphertext prefix: 'v1:<base64>'  allows future key rotation
  - validate_round_trip() health-check method
  - encrypt_data / decrypt_data both handle versioned and legacy payloads
"""

import os
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ---------------------------------------------------------------------------
# Typed exceptions
# ---------------------------------------------------------------------------

class EncryptionError(Exception):
    """Raised when encryption fails."""

class DecryptionError(Exception):
    """Raised when decryption fails (wrong key, corrupted data, etc.)."""

KEY_VERSION = "v1"      # bump to v2 when rotating keys

class EncryptionUtils:
    """
    Handles encryption and decryption of sensitive student record data
    """
    
    def __init__(self, password=None):
        """
        Initialize encryption utilities
        
        Args:
            password (str, optional): Master password for key derivation
        """
        self.password = password or self._get_master_password()
        self.salt = self._get_or_create_salt()
        self.fernet = self._initialize_fernet()
    
    def _get_master_password(self):
        """
        Get master password from environment or use default
        
        Returns:
            str: Master password for encryption
        """
        master_password = os.getenv('ENCRYPTION_MASTER_PASSWORD')
        if not master_password:
            # In production, this should come from secure key management
            master_password = 'SecureStudentRecords2024!DefaultKey'
            print("Warning: Using default encryption password. Set ENCRYPTION_MASTER_PASSWORD environment variable.")
        
        return master_password
    
    def _get_or_create_salt(self):
        """
        Get existing salt or create new one
        
        Returns:
            bytes: Salt for key derivation
        """
        salt_file = 'encryption_salt.key'
        
        if os.path.exists(salt_file):
            with open(salt_file, 'rb') as f:
                return f.read()
        else:
            # Generate new salt
            salt = os.urandom(16)
            with open(salt_file, 'wb') as f:
                f.write(salt)
            print("New encryption salt generated")
            return salt
    
    def _initialize_fernet(self):
        """
        Initialize Fernet cipher with derived key
        
        Returns:
            Fernet: Initialized Fernet cipher
        """
        # Derive key from password using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(self.password.encode()))
        return Fernet(key)
    
    def encrypt_data(self, data):
        """
        Encrypt data using Fernet (AES 128).

        Returns versioned ciphertext: 'v1:<base64_fernet_token>'
        The key-version prefix allows safe key rotation in decrypt_data.
        """
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            encrypted_bytes = self.fernet.encrypt(data)
            payload = base64.b64encode(encrypted_bytes).decode('utf-8')
            return f"{KEY_VERSION}:{payload}"
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}") from e
    
    def decrypt_data(self, encrypted_data):
        """
        Decrypt data using Fernet.

        Accepts both versioned payloads ('v1:<base64>') and
        legacy unversioned payloads for backward compatibility.
        """
        try:
            payload = encrypted_data
            if isinstance(encrypted_data, str) and ':' in encrypted_data:
                # Strip key-version prefix
                _, payload = encrypted_data.split(':', 1)
            encrypted_bytes = base64.b64decode(payload.encode('utf-8'))
            decrypted_bytes = self.fernet.decrypt(encrypted_bytes)
            return decrypted_bytes.decode('utf-8')
        except InvalidToken as e:
            raise DecryptionError("Decryption failed: invalid token or wrong key") from e
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {e}") from e
    
    def encrypt_file(self, file_path, output_path=None):
        """
        Encrypt a file
        
        Args:
            file_path (str): Path to file to encrypt
            output_path (str, optional): Path for encrypted file
            
        Returns:
            str: Path to encrypted file
        """
        if not output_path:
            output_path = file_path + '.encrypted'
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            encrypted_data = self.fernet.encrypt(file_data)
            
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            return output_path
            
        except Exception as e:
            raise Exception(f"File encryption failed: {e}")
    
    def decrypt_file(self, encrypted_file_path, output_path=None):
        """
        Decrypt a file
        
        Args:
            encrypted_file_path (str): Path to encrypted file
            output_path (str, optional): Path for decrypted file
            
        Returns:
            str: Path to decrypted file
        """
        if not output_path:
            output_path = encrypted_file_path.replace('.encrypted', '')
        
        try:
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.fernet.decrypt(encrypted_data)
            
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            return output_path
            
        except Exception as e:
            raise Exception(f"File decryption failed: {e}")
    
    def generate_secure_token(self, length=32):
        """
        Generate secure random token
        
        Args:
            length (int): Token length in bytes
            
        Returns:
            str: Base64 encoded secure token
        """
        token_bytes = os.urandom(length)
        return base64.urlsafe_b64encode(token_bytes).decode('utf-8')
    
    def validate_encrypted_data(self, encrypted_data: str) -> bool:
        """
        Check if ciphertext can be successfully decrypted (integrity probe).
        """
        try:
            self.decrypt_data(encrypted_data)
            return True
        except (EncryptionError, DecryptionError):
            return False

    def validate_round_trip(self, sample: str = "SSRBC_HEALTH_CHECK") -> bool:
        """
        Encrypt then immediately decrypt a sample string.
        Returns True if round-trip succeeds — used in health checks.
        """
        try:
            ciphertext = self.encrypt_data(sample)
            plaintext  = self.decrypt_data(ciphertext)
            return plaintext == sample
        except (EncryptionError, DecryptionError):
            return False
    
    @staticmethod
    def generate_new_key():
        """
        Generate a new Fernet key
        
        Returns:
            str: Base64 encoded Fernet key
        """
        key = Fernet.generate_key()
        return key.decode('utf-8')
    
    def get_encryption_info(self):
        """
        Get information about encryption configuration
        
        Returns:
            dict: Encryption configuration info
        """
        return {
            'algorithm': 'Fernet (AES 128)',
            'key_derivation': 'PBKDF2-HMAC-SHA256',
            'iterations': 100000,
            'salt_length': len(self.salt),
            'has_custom_password': 'ENCRYPTION_MASTER_PASSWORD' in os.environ
        }

# Utility functions for direct use
def quick_encrypt(data, password=None):
    """
    Quick encryption function
    
    Args:
        data (str): Data to encrypt
        password (str, optional): Password for encryption
        
    Returns:
        str: Encrypted data
    """
    encryption_utils = EncryptionUtils(password)
    return encryption_utils.encrypt_data(data)

def quick_decrypt(encrypted_data, password=None):
    """
    Quick decryption function
    
    Args:
        encrypted_data (str): Encrypted data
        password (str, optional): Password for decryption
        
    Returns:
        str: Decrypted data
    """
    encryption_utils = EncryptionUtils(password)
    return encryption_utils.decrypt_data(encrypted_data)