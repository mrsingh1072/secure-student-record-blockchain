"""
Hashing utilities for data integrity and blockchain operations using SHA256
"""

import hashlib
import hmac
import json
import os
from datetime import datetime

class HashingUtils:
    """
    Handles SHA256 hashing operations for data integrity and blockchain
    """
    
    def __init__(self, salt=None):
        """
        Initialize hashing utilities
        
        Args:
            salt (str, optional): Salt for HMAC operations
        """
        self.salt = salt or self._get_default_salt()
    
    def _get_default_salt(self):
        """
        Get default salt for HMAC operations
        
        Returns:
            str: Default salt
        """
        default_salt = os.getenv('HASHING_SALT', 'SecureStudentRecordsSalt2024')
        return default_salt
    
    def generate_sha256(self, data):
        """
        Generate SHA256 hash of data
        
        Args:
            data (str or bytes): Data to hash
            
        Returns:
            str: Hexadecimal SHA256 hash
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        return hashlib.sha256(data).hexdigest()
    
    def generate_sha256_file(self, file_path):
        """
        Generate SHA256 hash of a file
        
        Args:
            file_path (str): Path to file
            
        Returns:
            str: Hexadecimal SHA256 hash of file
        """
        sha256_hash = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            
            return sha256_hash.hexdigest()
            
        except Exception as e:
            raise Exception(f"File hashing failed: {e}")
    
    def generate_hmac_sha256(self, data, key=None):
        """
        Generate HMAC-SHA256 hash with key
        
        Args:
            data (str or bytes): Data to hash
            key (str, optional): HMAC key (uses salt if not provided)
            
        Returns:
            str: Hexadecimal HMAC-SHA256 hash
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        hmac_key = (key or self.salt).encode('utf-8')
        return hmac.new(hmac_key, data, hashlib.sha256).hexdigest()
    
    def hash_student_record(self, record_data):
        """
        Generate standardized hash for student record data
        
        Args:
            record_data (dict): Student record data
            
        Returns:
            str: SHA256 hash of normalized record data
        """
        try:
            # Normalize data by sorting keys and converting to JSON
            normalized_data = json.dumps(record_data, sort_keys=True, separators=(',', ':'))
            
            # Add timestamp to ensure uniqueness
            timestamp = datetime.now().isoformat()
            data_with_timestamp = f"{normalized_data}|timestamp:{timestamp}"
            
            return self.generate_sha256(data_with_timestamp)
            
        except Exception as e:
            raise Exception(f"Record hashing failed: {e}")
    
    def hash_password_with_salt(self, password, salt=None):
        """
        Hash password with salt using SHA256
        
        Args:
            password (str): Plain text password
            salt (str, optional): Salt for hashing
            
        Returns:
            tuple: (hashed_password, salt_used)
        """
        if not salt:
            salt = os.urandom(32).hex()  # Generate random salt
        
        # Combine password and salt
        salted_password = f"{password}{salt}"
        hashed_password = self.generate_sha256(salted_password)
        
        return hashed_password, salt
    
    def verify_password_hash(self, password, stored_hash, salt):
        """
        Verify password against stored hash
        
        Args:
            password (str): Plain text password
            stored_hash (str): Stored password hash
            salt (str): Salt used for hashing
            
        Returns:
            bool: True if password matches, False otherwise
        """
        try:
            salted_password = f"{password}{salt}"
            calculated_hash = self.generate_sha256(salted_password)
            return calculated_hash == stored_hash
        except:
            return False
    
    def hash_blockchain_block(self, index, timestamp, data_hash, previous_hash, nonce):
        """
        Generate hash for blockchain block
        
        Args:
            index (int): Block index
            timestamp (float): Block timestamp
            data_hash (str): Hash of block data
            previous_hash (str): Hash of previous block
            nonce (int): Nonce for proof of work
            
        Returns:
            str: SHA256 hash of block
        """
        block_string = f"{index}{timestamp}{data_hash}{previous_hash}{nonce}"
        return self.generate_sha256(block_string)
    
    def generate_merkle_root(self, data_hashes):
        """
        Generate Merkle root from list of data hashes
        
        Args:
            data_hashes (list): List of data hashes
            
        Returns:
            str: Merkle root hash
        """
        if not data_hashes:
            return self.generate_sha256("")
        
        if len(data_hashes) == 1:
            return data_hashes[0]
        
        # Build Merkle tree
        current_level = data_hashes[:]
        
        while len(current_level) > 1:
            next_level = []
            
            # Process pairs of hashes
            for i in range(0, len(current_level), 2):
                left_hash = current_level[i]
                
                # Handle odd number of hashes by duplicating last hash
                if i + 1 < len(current_level):
                    right_hash = current_level[i + 1]
                else:
                    right_hash = left_hash
                
                # Combine and hash the pair
                combined = f"{left_hash}{right_hash}"
                next_level.append(self.generate_sha256(combined))
            
            current_level = next_level
        
        return current_level[0]
    
    def validate_hash_format(self, hash_string, expected_length=64):
        """
        Validate if string is a valid SHA256 hash
        
        Args:
            hash_string (str): Hash string to validate
            expected_length (int): Expected length (64 for SHA256)
            
        Returns:
            bool: True if valid hash format, False otherwise
        """
        if not hash_string or not isinstance(hash_string, str):
            return False
        
        # Check length
        if len(hash_string) != expected_length:
            return False
        
        # Check if all characters are valid hexadecimal
        try:
            int(hash_string, 16)
            return True
        except ValueError:
            return False
    
    def compare_hashes(self, hash1, hash2):
        """
        Securely compare two hashes to prevent timing attacks
        
        Args:
            hash1 (str): First hash
            hash2 (str): Second hash
            
        Returns:
            bool: True if hashes match, False otherwise
        """
        return hmac.compare_digest(hash1, hash2)
    
    def generate_integrity_hash(self, *args):
        """
        Generate integrity hash from multiple arguments
        
        Args:
            *args: Multiple arguments to include in hash
            
        Returns:
            str: SHA256 hash of combined arguments
        """
        combined_data = "|".join(str(arg) for arg in args)
        return self.generate_sha256(combined_data)
    
    def get_hashing_info(self):
        """
        Get information about hashing configuration
        
        Returns:
            dict: Hashing configuration info
        """
        return {
            'primary_algorithm': 'SHA-256',
            'hmac_algorithm': 'HMAC-SHA-256',
            'salt_configured': bool(self.salt),
            'hash_length': 64,
            'supported_formats': ['hexadecimal']
        }

# Utility functions for direct use
def quick_hash(data):
    """
    Quick hash function using SHA256
    
    Args:
        data (str): Data to hash
        
    Returns:
        str: SHA256 hash
    """
    hashing_utils = HashingUtils()
    return hashing_utils.generate_sha256(data)

def quick_file_hash(file_path):
    """
    Quick file hash function
    
    Args:
        file_path (str): Path to file
        
    Returns:
        str: SHA256 hash of file
    """
    hashing_utils = HashingUtils()
    return hashing_utils.generate_sha256_file(file_path)

def verify_data_integrity(data, expected_hash):
    """
    Verify data integrity against expected hash
    
    Args:
        data (str): Data to verify
        expected_hash (str): Expected hash value
        
    Returns:
        bool: True if data matches hash, False otherwise
    """
    hashing_utils = HashingUtils()
    actual_hash = hashing_utils.generate_sha256(data)
    return hashing_utils.compare_hashes(actual_hash, expected_hash)