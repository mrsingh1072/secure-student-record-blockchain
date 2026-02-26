"""
Database module for managing SQLite database connections and operations
"""

import sqlite3
import os
import hashlib
from datetime import datetime
from contextlib import contextmanager
from utils.logger import get_logger

logger = get_logger(__name__)

class DatabaseManager:
    """
    Manages SQLite database connections and operations for student records
    """
    
    def __init__(self, db_path='secure_student_records.db'):
        """
        Initialize database manager
        
        Args:
            db_path (str): Path to SQLite database file
        """
        self.db_path = db_path
        self.init_database()
    
    @contextmanager
    def get_db_connection(self):
        """
        Context manager for database connections
        
        Yields:
            sqlite3.Connection: Database connection
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable dict-like access to rows
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def init_database(self):
        """Initialize database with required tables"""
        with self.get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('admin', 'student', 'verifier')),
                    student_id TEXT,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Student records table (stores encrypted data)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS student_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_id TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    encrypted_data TEXT NOT NULL,
                    data_hash TEXT UNIQUE NOT NULL,
                    blockchain_hash TEXT,
                    created_by TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_verified BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (created_by) REFERENCES users (username)
                )
            ''')
            
            # Access permissions table (smart contract simulation)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS access_permissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_id TEXT NOT NULL,
                    verifier_username TEXT NOT NULL,
                    record_type TEXT,
                    is_granted BOOLEAN DEFAULT FALSE,
                    granted_at TIMESTAMP,
                    expires_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (verifier_username) REFERENCES users (username)
                )
            ''')
            
            # Access log table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS access_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_id TEXT NOT NULL,
                    accessor_username TEXT NOT NULL,
                    record_id INTEGER,
                    action TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    access_granted BOOLEAN,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (accessor_username) REFERENCES users (username),
                    FOREIGN KEY (record_id) REFERENCES student_records (id)
                )
            ''')
            
            # Blockchain sync table (tracks which records are on blockchain)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blockchain_sync (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_id INTEGER NOT NULL,
                    block_index INTEGER NOT NULL,
                    block_hash TEXT NOT NULL,
                    sync_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (record_id) REFERENCES student_records (id)
                )
            ''')
            
            logger.info("Database initialized successfully")
    
    def create_user(self, username, email, password_hash, role, student_id=None):
        """
        Create a new user in the database
        
        Args:
            username (str): Unique username
            email (str): User email address
            password_hash (str): Hashed password
            role (str): User role (admin, student, verifier)
            student_id (str, optional): Student ID if role is student
            
        Returns:
            int: User ID of created user
        """
        with self.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, role, student_id)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, email, password_hash, role, student_id))
            return cursor.lastrowid
    
    def get_user_by_username(self, username):
        """
        Get user information by username
        
        Args:
            username (str): Username to search for
            
        Returns:
            dict or None: User information or None if not found
        """
        with self.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ? AND is_active = TRUE', (username,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def create_student_record(self, student_id, record_type, encrypted_data, data_hash, created_by):
        """
        Create a new student record
        
        Args:
            student_id (str): Student identifier
            record_type (str): Type of record
            encrypted_data (str): Encrypted record data
            data_hash (str): Hash of the original data
            created_by (str): Username of creator
            
        Returns:
            int: Record ID of created record
        """
        with self.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO student_records 
                (student_id, record_type, encrypted_data, data_hash, created_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (student_id, record_type, encrypted_data, data_hash, created_by))
            return cursor.lastrowid
    
    def get_student_records(self, student_id, record_type=None):
        """
        Get student records by student ID
        
        Args:
            student_id (str): Student identifier
            record_type (str, optional): Filter by record type
            
        Returns:
            list: List of student records
        """
        with self.get_db_connection() as conn:
            cursor = conn.cursor()
            if record_type:
                cursor.execute('''
                    SELECT * FROM student_records 
                    WHERE student_id = ? AND record_type = ?
                    ORDER BY created_at DESC
                ''', (student_id, record_type))
            else:
                cursor.execute('''
                    SELECT * FROM student_records 
                    WHERE student_id = ?
                    ORDER BY created_at DESC
                ''', (student_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    def update_blockchain_hash(self, record_id, blockchain_hash):
        """
        Update record with blockchain hash after adding to blockchain
        
        Args:
            record_id (int): Database record ID
            blockchain_hash (str): Hash of block in blockchain
        """
        with self.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE student_records 
                SET blockchain_hash = ?, is_verified = TRUE, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (blockchain_hash, record_id))
    
    def log_access_attempt(self, student_id, accessor_username, record_id, action, access_granted, ip_address=None, user_agent=None):
        """
        Log access attempt for audit trail
        
        Args:
            student_id (str): Student ID accessed
            accessor_username (str): Username attempting access
            record_id (int): Record ID accessed
            action (str): Action performed
            access_granted (bool): Whether access was granted
            ip_address (str, optional): IP address of accessor
            user_agent (str, optional): User agent of accessor
        """
        with self.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO access_logs 
                (student_id, accessor_username, record_id, action, access_granted, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (student_id, accessor_username, record_id, action, access_granted, ip_address, user_agent))
    
    def grant_access_permission(self, student_id, verifier_username, record_type=None, expires_at=None):
        """
        Grant access permission to a verifier
        
        Args:
            student_id (str): Student ID
            verifier_username (str): Username of verifier
            record_type (str, optional): Specific record type or None for all
            expires_at (datetime, optional): Expiration time
        """
        with self.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO access_permissions 
                (student_id, verifier_username, record_type, is_granted, granted_at, expires_at)
                VALUES (?, ?, ?, TRUE, CURRENT_TIMESTAMP, ?)
            ''', (student_id, verifier_username, record_type, expires_at))

    def revoke_access_permission(self, student_id, verifier_username, record_type=None):
        """
        Revoke access permission from a verifier.

        Sets is_granted = FALSE for all matching rows (by student_id + verifier).
        If record_type is specified, only that type's grant is revoked.
        """
        with self.get_db_connection() as conn:
            cursor = conn.cursor()
            if record_type:
                cursor.execute('''
                    UPDATE access_permissions
                    SET is_granted = FALSE, expires_at = CURRENT_TIMESTAMP
                    WHERE student_id = ? AND verifier_username = ? AND record_type = ?
                ''', (student_id, verifier_username, record_type))
            else:
                cursor.execute('''
                    UPDATE access_permissions
                    SET is_granted = FALSE, expires_at = CURRENT_TIMESTAMP
                    WHERE student_id = ? AND verifier_username = ?
                ''', (student_id, verifier_username))
            logger.info("Access revoked",
                        extra={"student_id": student_id, "verifier": verifier_username,
                               "record_type": record_type})
    
    def check_access_permission(self, student_id, verifier_username, record_type=None):
        """
        Check if verifier has permission to access student records
        
        Args:
            student_id (str): Student ID
            verifier_username (str): Username of verifier
            record_type (str, optional): Specific record type
            
        Returns:
            bool: True if access is permitted, False otherwise
        """
        with self.get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check for specific record type permission or general permission
            cursor.execute('''
                SELECT COUNT(*) as count FROM access_permissions 
                WHERE student_id = ? AND verifier_username = ? 
                AND is_granted = TRUE
                AND (record_type = ? OR record_type IS NULL)
                AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
            ''', (student_id, verifier_username, record_type))
            
            result = cursor.fetchone()
            return result['count'] > 0
    
    def get_database_stats(self):
        """
        Get database statistics
        
        Returns:
            dict: Database statistics
        """
        with self.get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Count users by role
            cursor.execute('SELECT role, COUNT(*) as count FROM users WHERE is_active = TRUE GROUP BY role')
            user_stats = {row['role']: row['count'] for row in cursor.fetchall()}
            
            # Count records
            cursor.execute('SELECT COUNT(*) as total_records FROM student_records')
            total_records = cursor.fetchone()['total_records']
            
            # Count verified records
            cursor.execute('SELECT COUNT(*) as verified_records FROM student_records WHERE is_verified = TRUE')
            verified_records = cursor.fetchone()['verified_records']
            
            # Count access logs
            cursor.execute('SELECT COUNT(*) as total_access_logs FROM access_logs')
            total_access_logs = cursor.fetchone()['total_access_logs']
            
            return {
                'users': user_stats,
                'total_records': total_records,
                'verified_records': verified_records,
                'unverified_records': total_records - verified_records,
                'total_access_logs': total_access_logs
            }
    
    def close_connection(self):
        """Close database connection (if needed for cleanup)"""
        pass  # Context manager handles this automatically