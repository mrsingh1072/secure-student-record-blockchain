"""
Student Record model for managing encrypted academic records
"""

import json
import hashlib
from datetime import datetime
from database.db import DatabaseManager
from utils.encryption import EncryptionUtils
from utils.hashing import HashingUtils
from utils.masking import DataMasking

class StudentRecord:
    """
    Model for managing encrypted student academic records
    """
    
    VALID_RECORD_TYPES = [
        'transcript', 'certificate', 'diploma', 'grade_card', 
        'achievement', 'enrollment', 'completion'
    ]
    
    def __init__(self, student_id=None, record_type=None, raw_data=None, record_id=None):
        """
        Initialize StudentRecord object
        
        Args:
            student_id (str): Student identifier
            record_type (str): Type of academic record
            raw_data (dict): Original record data
            record_id (int, optional): Database record ID
        """
        self.record_id = record_id
        self.student_id = student_id
        self.record_type = record_type
        self.raw_data = raw_data
        self.masked_data = None
        self.encrypted_data = None
        self.data_hash = None
        self.blockchain_hash = None
        self.created_by = None
        self.created_at = None
        self.updated_at = None
        self.is_verified = False
        
        self.db_manager = DatabaseManager()
        self.encryption_utils = EncryptionUtils()
        self.hash_utils = HashingUtils()
        self.data_masking = DataMasking()
    
    def validate_data(self):
        """
        Validate student record data
        
        Returns:
            tuple: (is_valid, errors)
        """
        errors = []
        
        # Validate student_id
        if not self.student_id or len(self.student_id) < 5:
            errors.append("Student ID must be at least 5 characters long")
        
        # Validate record_type
        if self.record_type not in self.VALID_RECORD_TYPES:
            errors.append(f"Record type must be one of: {', '.join(self.VALID_RECORD_TYPES)}")
        
        # Validate raw_data
        if not self.raw_data:
            errors.append("Record data is required")
        elif not isinstance(self.raw_data, dict):
            errors.append("Record data must be a dictionary")
        else:
            # Check required fields based on record type
            required_fields = self._get_required_fields()
            for field in required_fields:
                if field not in self.raw_data:
                    errors.append(f"Required field missing: {field}")
        
        return len(errors) == 0, errors
    
    def _get_required_fields(self):
        """
        Get required fields based on record type
        
        Returns:
            list: List of required fields
        """
        common_fields = ['student_name', 'student_id', 'institution']
        
        type_specific_fields = {
            'transcript': ['courses', 'grades', 'gpa', 'semester'],
            'certificate': ['certificate_name', 'issued_date', 'issuing_authority'],
            'diploma': ['degree_name', 'graduation_date', 'honors'],
            'grade_card': ['courses', 'grades', 'semester', 'academic_year'],
            'achievement': ['achievement_name', 'date_achieved', 'description'],
            'enrollment': ['program_name', 'enrollment_date', 'status'],
            'completion': ['program_name', 'completion_date', 'result']
        }
        
        specific_fields = type_specific_fields.get(self.record_type, [])
        return common_fields + specific_fields
    
    def process_data(self, created_by):
        """
        Process record data: mask -> encrypt -> hash
        
        Args:
            created_by (str): Username of creator
            
        Returns:
            bool: True if processing successful
        """
        try:
            self.created_by = created_by
            
            # Step 1: Validate data
            is_valid, errors = self.validate_data()
            if not is_valid:
                raise ValueError(f"Validation failed: {', '.join(errors)}")
            
            # Step 2: Create masked version for logging/display
            self.masked_data = self.data_masking.mask_sensitive_data(
                self.raw_data, 
                self.record_type
            )
            
            # Step 3: Encrypt the full data
            raw_data_json = json.dumps(self.raw_data, sort_keys=True)
            self.encrypted_data = self.encryption_utils.encrypt_data(raw_data_json)
            
            # Step 4: Generate hash of original data
            self.data_hash = self.hash_utils.generate_sha256(raw_data_json)
            
            print(f"✓ Record processed successfully")
            print(f"  - Data masked: {len(self.masked_data)} fields")
            print(f"  - Data encrypted: {len(self.encrypted_data)} bytes")
            print(f"  - Hash generated: {self.data_hash[:32]}...")
            
            return True
            
        except Exception as e:
            print(f"Error processing record data: {e}")
            return False
    
    def save_to_database(self):
        """
        Save encrypted record to database
        
        Returns:
            bool: True if saved successfully
        """
        if not self.encrypted_data or not self.data_hash:
            raise ValueError("Record must be processed before saving")
        
        try:
            self.record_id = self.db_manager.create_student_record(
                self.student_id,
                self.record_type,
                self.encrypted_data,
                self.data_hash,
                self.created_by
            )
            
            print(f"✓ Record saved to database with ID: {self.record_id}")
            return True
            
        except Exception as e:
            print(f"Error saving record to database: {e}")
            return False
    
    def add_to_blockchain(self, blockchain, pbft_consensus):
        """
        Add record hash to blockchain after PBFT validation
        
        Args:
            blockchain: Blockchain instance
            pbft_consensus: PBFT consensus instance
            
        Returns:
            bool: True if added to blockchain successfully
        """
        if not self.data_hash:
            raise ValueError("Record must be processed before adding to blockchain")
        
        try:
            # Step 1: PBFT Consensus validation
            consensus_result = pbft_consensus.validate_block_addition(
                self.data_hash,
                self.student_id,
                self.record_type
            )
            
            if not consensus_result['consensus_reached']:
                print(f"✗ PBFT consensus failed - block not added to blockchain")
                return False
            
            # Step 2: Add to blockchain
            block = blockchain.add_block(self.data_hash)
            self.blockchain_hash = block.hash
            
            # Step 3: Update database with blockchain hash
            if self.record_id:
                self.db_manager.update_blockchain_hash(self.record_id, self.blockchain_hash)
                self.is_verified = True
            
            print(f"✓ Record added to blockchain - Block #{block.index}")
            return True
            
        except Exception as e:
            print(f"Error adding record to blockchain: {e}")
            return False
    
    def decrypt_data(self):
        """
        Decrypt record data (for authorized access only)
        
        Returns:
            dict: Decrypted record data or None if decryption fails
        """
        if not self.encrypted_data:
            return None
        
        try:
            decrypted_json = self.encryption_utils.decrypt_data(self.encrypted_data)
            return json.loads(decrypted_json)
        except Exception as e:
            print(f"Error decrypting record data: {e}")
            return None
    
    def verify_integrity(self):
        """
        Verify record integrity by comparing hashes
        
        Returns:
            bool: True if record integrity is intact
        """
        if not self.encrypted_data or not self.data_hash:
            return False
        
        try:
            # Decrypt data and recalculate hash
            decrypted_data = self.decrypt_data()
            if not decrypted_data:
                return False
            
            recalculated_hash = self.hash_utils.generate_sha256(
                json.dumps(decrypted_data, sort_keys=True)
            )
            
            return recalculated_hash == self.data_hash
            
        except Exception as e:
            print(f"Error verifying integrity: {e}")
            return False
    
    @classmethod
    def get_by_student_id(cls, student_id, record_type=None):
        """
        Get records by student ID
        
        Args:
            student_id (str): Student identifier
            record_type (str, optional): Filter by record type
            
        Returns:
            list: List of StudentRecord objects
        """
        try:
            db_manager = DatabaseManager()
            records_data = db_manager.get_student_records(student_id, record_type)
            
            records = []
            for record_data in records_data:
                record = cls()
                record.record_id = record_data['id']
                record.student_id = record_data['student_id']
                record.record_type = record_data['record_type']
                record.encrypted_data = record_data['encrypted_data']
                record.data_hash = record_data['data_hash']
                record.blockchain_hash = record_data['blockchain_hash']
                record.created_by = record_data['created_by']
                record.created_at = record_data['created_at']
                record.updated_at = record_data['updated_at']
                record.is_verified = record_data['is_verified']
                records.append(record)
            
            return records
            
        except Exception as e:
            print(f"Error getting records: {e}")
            return []
    
    @classmethod
    def get_by_hash(cls, data_hash):
        """
        Get record by data hash
        
        Args:
            data_hash (str): Data hash to search for
            
        Returns:
            StudentRecord or None: Record if found
        """
        # This would require a new database method - simplified for now
        return None
    
    def get_masked_view(self):
        """
        Get masked version of record for display
        
        Returns:
            dict: Masked record data
        """
        if self.masked_data:
            return {
                'record_id': self.record_id,
                'student_id': self.student_id,
                'record_type': self.record_type,
                'data': self.masked_data,
                'is_verified': self.is_verified,
                'created_at': self.created_at,
                'created_by': self.created_by
            }
        return None
    
    def to_dict(self, include_encrypted=False, include_decrypted=False):
        """
        Convert record to dictionary
        
        Args:
            include_encrypted (bool): Include encrypted data
            include_decrypted (bool): Include decrypted data (for authorized access)
            
        Returns:
            dict: Record data as dictionary
        """
        data = {
            'record_id': self.record_id,
            'student_id': self.student_id,
            'record_type': self.record_type,
            'data_hash': self.data_hash,
            'blockchain_hash': self.blockchain_hash,
            'is_verified': self.is_verified,
            'created_by': self.created_by,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }
        
        if include_encrypted and self.encrypted_data:
            data['encrypted_data'] = self.encrypted_data
        
        if include_decrypted:
            decrypted = self.decrypt_data()
            if decrypted:
                data['decrypted_data'] = decrypted
            elif self.masked_data:
                data['masked_data'] = self.masked_data
        
        # Remove None values
        return {k: v for k, v in data.items() if v is not None}
    
    def __str__(self):
        return f"StudentRecord({self.student_id}, {self.record_type}, verified={self.is_verified})"
    
    def __repr__(self):
        return f"StudentRecord(id={self.record_id}, student_id='{self.student_id}', type='{self.record_type}')"