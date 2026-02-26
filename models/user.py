"""
User model for authentication and authorization
"""

import hashlib
from datetime import datetime
from database.db import DatabaseManager
from utils.permissions import PolicyEngine, PermissionDeniedError
from utils.logger import get_logger

logger = get_logger(__name__)

class User:
    """
    User model for managing authentication and role-based access
    """
    
    VALID_ROLES = ['admin', 'student', 'verifier']
    
    def __init__(self, username=None, email=None, role=None, student_id=None, user_id=None):
        """
        Initialize User object
        
        Args:
            username (str): Unique username
            email (str): User email address
            role (str): User role (admin, student, verifier)
            student_id (str, optional): Student ID if role is student
            user_id (int, optional): Database user ID
        """
        self.user_id = user_id
        self.username = username
        self.email = email
        self.role = role
        self.student_id = student_id
        self.created_at = None
        self.updated_at = None
        self.is_active = True
        self.db_manager = DatabaseManager()
        self._policy_engine = PolicyEngine(
            db_check_fn=self.db_manager.check_access_permission
        )
    
    @staticmethod
    def hash_password(password):
        """
        Hash password using SHA256
        
        Args:
            password (str): Plain text password
            
        Returns:
            str: Hashed password
        """
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def verify_password(password, password_hash):
        """
        Verify password against hash
        
        Args:
            password (str): Plain text password
            password_hash (str): Stored password hash
            
        Returns:
            bool: True if password matches, False otherwise
        """
        return User.hash_password(password) == password_hash
    
    def validate_data(self):
        """
        Validate user data
        
        Returns:
            tuple: (is_valid, errors)
        """
        errors = []
        
        # Validate username
        if not self.username or len(self.username) < 3:
            errors.append("Username must be at least 3 characters long")
        
        # Validate email
        if not self.email or '@' not in self.email:
            errors.append("Valid email address is required")
        
        # Validate role
        if self.role not in self.VALID_ROLES:
            errors.append(f"Role must be one of: {', '.join(self.VALID_ROLES)}")
        
        # Validate student_id for student role
        if self.role == 'student' and not self.student_id:
            errors.append("Student ID is required for student role")
        
        return len(errors) == 0, errors
    
    def save(self, password=None):
        """
        Save user to database
        
        Args:
            password (str): Plain text password (required for new users)
            
        Returns:
            bool: True if saved successfully, False otherwise
        """
        is_valid, errors = self.validate_data()
        if not is_valid:
            raise ValueError(f"User validation failed: {', '.join(errors)}")
        
        if not password and not self.user_id:
            raise ValueError("Password is required for new users")
        
        try:
            if self.user_id:
                # Update existing user (not implemented in this basic version)
                return False
            else:
                # Create new user
                password_hash = self.hash_password(password)
                self.user_id = self.db_manager.create_user(
                    self.username,
                    self.email,
                    password_hash,
                    self.role,
                    self.student_id
                )
                return True
        except Exception as e:
            print(f"Error saving user: {e}")
            return False
    
    @classmethod
    def authenticate(cls, username, password):
        """
        Authenticate user with username and password
        
        Args:
            username (str): Username
            password (str): Plain text password
            
        Returns:
            User or None: User object if authentication successful, None otherwise
        """
        try:
            db_manager = DatabaseManager()
            user_data = db_manager.get_user_by_username(username)
            
            if user_data and cls.verify_password(password, user_data['password_hash']):
                user = cls()
                user.user_id = user_data['id']
                user.username = user_data['username']
                user.email = user_data['email']
                user.role = user_data['role']
                user.student_id = user_data['student_id']
                user.created_at = user_data['created_at']
                user.updated_at = user_data['updated_at']
                user.is_active = user_data['is_active']
                return user
            
            return None
        except Exception as e:
            print(f"Authentication error: {e}")
            return None
    
    @classmethod
    def get_by_username(cls, username):
        """
        Get user by username
        
        Args:
            username (str): Username to search for
            
        Returns:
            User or None: User object if found, None otherwise
        """
        try:
            db_manager = DatabaseManager()
            user_data = db_manager.get_user_by_username(username)
            
            if user_data:
                user = cls()
                user.user_id = user_data['id']
                user.username = user_data['username']
                user.email = user_data['email']
                user.role = user_data['role']
                user.student_id = user_data['student_id']
                user.created_at = user_data['created_at']
                user.updated_at = user_data['updated_at']
                user.is_active = user_data['is_active']
                return user
            
            return None
        except Exception as e:
            print(f"Error getting user: {e}")
            return None
    
    def can_access_record(self, target_student_id, record_type=None):
        """
        Check if user can access records for a specific student.
        Delegates to PolicyEngine for policy-based evaluation.
        """
        result = self._policy_engine.check(
            actor_role=self.role,
            actor_username=self.username,
            actor_student_id=self.student_id,
            owner_id=target_student_id,
            resource_type=record_type,
            action="READ",
        )
        return result["allowed"]

    
    def grant_access_to_verifier(self, verifier_username, record_type=None, expires_at=None):
        """
        Grant access permission to a verifier (only students can do this)
        
        Args:
            verifier_username (str): Username of verifier
            record_type (str, optional): Specific record type or None for all
            expires_at (datetime, optional): Expiration time
            
        Returns:
            bool: True if permission granted successfully
        """
        if self.role != 'student':
            return False

        try:
            success = self._policy_engine.grant(
                granting_student_id=self.student_id,
                granting_username=self.username,
                verifier_username=verifier_username,
                resource_type=record_type,
                expires_at=expires_at,
                db_grant_fn=self.db_manager.grant_access_permission,
            )
            return success
        except Exception as e:
            logger.error("Error granting access", extra={"error": str(e)})
            return False

    def revoke_access_from_verifier(self, verifier_username, record_type=None):
        """
        Revoke a verifier's delegated access — calls PolicyEngine.revoke()
        which also records the action in the permission audit log.
        """
        if self.role != 'student':
            return False
        try:
            return self._policy_engine.revoke(
                revoking_student_id=self.student_id,
                revoking_username=self.username,
                verifier_username=verifier_username,
                resource_type=record_type,
                db_revoke_fn=self.db_manager.revoke_access_permission,
            )
        except Exception as e:
            logger.error("Error revoking access", extra={"error": str(e)})
            return False
    
    def log_access(self, target_student_id, record_id, action, access_granted, ip_address=None, user_agent=None):
        """
        Log access attempt for audit purposes
        
        Args:
            target_student_id (str): Student ID accessed
            record_id (int): Record ID accessed
            action (str): Action performed
            access_granted (bool): Whether access was granted
            ip_address (str, optional): IP address
            user_agent (str, optional): User agent
        """
        try:
            self.db_manager.log_access_attempt(
                target_student_id,
                self.username,
                record_id,
                action,
                access_granted,
                ip_address,
                user_agent
            )
        except Exception as e:
            logger.error("Error logging access", extra={"error": str(e)})
    
    def to_dict(self, include_sensitive=False):
        """
        Convert user to dictionary
        
        Args:
            include_sensitive (bool): Whether to include sensitive information
            
        Returns:
            dict: User data as dictionary
        """
        data = {
            'user_id': self.user_id,
            'username': self.username,
            'email': self.email if include_sensitive else None,
            'role': self.role,
            'student_id': self.student_id if self.role == 'student' or include_sensitive else None,
            'created_at': self.created_at,
            'is_active': self.is_active
        }
        
        # Remove None values
        return {k: v for k, v in data.items() if v is not None}
    
    def __str__(self):
        return f"User({self.username}, {self.role})"
    
    def __repr__(self):
        return f"User(username='{self.username}', role='{self.role}', student_id='{self.student_id}')"