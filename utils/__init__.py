"""
Security utilities module for secure student record management
"""

from .encryption import EncryptionUtils, quick_encrypt, quick_decrypt
from .hashing import HashingUtils, quick_hash, quick_file_hash, verify_data_integrity
from .masking import DataMasking, quick_mask, mask_student_id, mask_email
from .logger import get_logger
from .exceptions import (
    BlockchainIntegrityError, PermissionDeniedError, EncryptionError, DecryptionError,
    ValidationError, DatabaseError, PBFTConsensusError
)

__all__ = [
    'EncryptionUtils', 'quick_encrypt', 'quick_decrypt',
    'HashingUtils', 'quick_hash', 'quick_file_hash', 'verify_data_integrity',
    'DataMasking', 'quick_mask', 'mask_student_id', 'mask_email',
    'get_logger',
    'BlockchainIntegrityError', 'PermissionDeniedError', 'EncryptionError', 
    'DecryptionError', 'ValidationError', 'DatabaseError', 'PBFTConsensusError'
]