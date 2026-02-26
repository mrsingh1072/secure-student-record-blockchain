"""
Custom exception classes for the Secure Student Record Blockchain System

These exceptions provide typed error handling throughout the application
for better error tracking and user experience.
"""

class BlockchainIntegrityError(Exception):
    """
    Raised when blockchain validation fails or chain integrity is compromised
    """
    def __init__(self, message="Blockchain integrity check failed", block_index=None):
        self.block_index = block_index
        super().__init__(message)

class PermissionDeniedError(Exception):
    """
    Raised when a user attempts to access resources they don't have permission for
    """
    def __init__(self, message="Permission denied", required_role=None, user_role=None):
        self.required_role = required_role
        self.user_role = user_role
        super().__init__(message)

class EncryptionError(Exception):
    """
    Raised when encryption operations fail
    """
    pass

class DecryptionError(Exception):
    """
    Raised when decryption operations fail
    """
    pass

class ValidationError(Exception):
    """
    Raised when data validation fails
    """
    def __init__(self, message="Validation failed", errors=None):
        self.errors = errors or []
        super().__init__(message)

class DatabaseError(Exception):
    """
    Raised when database operations fail
    """
    pass

class PBFTConsensusError(Exception):
    """
    Raised when PBFT consensus fails or times out
    """
    def __init__(self, message="PBFT consensus failed", node_failures=None):
        self.node_failures = node_failures or []
        super().__init__(message)