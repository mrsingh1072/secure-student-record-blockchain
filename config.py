"""
Configuration settings for Secure Student Record Blockchain System

This module contains all configuration settings for different environments
including development, testing, and production configurations.
"""

import os
from datetime import timedelta

class Config:
    """
    Base configuration class with common settings
    """
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'secure-student-record-blockchain-2024-secret-key-change-in-production'
    
    # Session Configuration
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    
    # Database Configuration  (MySQL via PyMySQL)
    DB_HOST     = os.environ.get('DB_HOST', 'localhost')
    DB_PORT     = int(os.environ.get('DB_PORT', 3306))
    DB_USER     = os.environ.get('DB_USER', 'root')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', '')   # set DB_PASSWORD env var in production
    DB_NAME     = os.environ.get('DB_NAME', 'ssrbc')
    DATABASE_BACKUP_ENABLED  = True
    DATABASE_BACKUP_INTERVAL = 3600  # seconds (1 hour)
    
    # Blockchain Configuration
    BLOCKCHAIN_DATA_FILE = os.environ.get('BLOCKCHAIN_DATA_FILE') or 'blockchain_data.json'
    BLOCKCHAIN_DIFFICULTY = int(os.environ.get('BLOCKCHAIN_DIFFICULTY', 4))
    BLOCKCHAIN_BACKUP_ENABLED = True
    
    # PBFT Consensus Configuration
    PBFT_NODE_COUNT = 3
    PBFT_CONSENSUS_THRESHOLD = 2  # Majority of nodes
    PBFT_VALIDATION_TIMEOUT = 30  # seconds
    
    # Encryption Configuration
    ENCRYPTION_MASTER_PASSWORD = os.environ.get('ENCRYPTION_MASTER_PASSWORD')
    ENCRYPTION_SALT_FILE = 'encryption_salt.key'
    ENCRYPTION_KEY_ROTATION_DAYS = 90  # Rotate encryption keys every 90 days
    
    # Hashing Configuration
    HASHING_SALT = os.environ.get('HASHING_SALT') or 'SecureStudentRecordsSalt2024'
    HASH_ALGORITHM = 'SHA-256'
    
    # Data Masking Configuration
    DEFAULT_MASKING_LEVEL = os.environ.get('MASKING_LEVEL', 'medium')  # low, medium, high
    MASKING_PRESERVE_FORMAT = True
    
    # Security Configuration
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_REQUIRE_SPECIAL_CHARS = True
    PASSWORD_REQUIRE_NUMBERS = True
    SESSION_REGENERATE_ON_AUTH = True
    
    # Rate Limiting Configuration
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_PER_MINUTE = 60
    RATE_LIMIT_PER_HOUR = 1000
    
    # CORS Configuration
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:3000,http://localhost:5000').split(',')
    CORS_SUPPORTS_CREDENTIALS = True
    
    # Logging Configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'secure_student_records.log')
    LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
    LOG_BACKUP_COUNT = 5
    ACCESS_LOG_ENABLED = True
    
    # File Upload Configuration (for future file uploads)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png', 'doc', 'docx'}
    
    # API Configuration
    API_VERSION = '1.0.0'
    API_TITLE = 'Secure Student Record Blockchain API'
    API_DESCRIPTION = 'REST API for secure management of student academic records using blockchain technology'
    
    # Monitoring Configuration
    HEALTH_CHECK_ENABLED = True
    METRICS_ENABLED = False  # Set to True to enable metrics collection
    ERROR_REPORTING_ENABLED = False  # Set to True for error reporting service
    
    # Backup Configuration
    BACKUP_ENABLED = True
    BACKUP_DIRECTORY = os.environ.get('BACKUP_DIR', 'backups')
    BACKUP_RETENTION_DAYS = 30
    BACKUP_ENCRYPTION_ENABLED = True
    
    # Cache Configuration (for future caching implementation)
    CACHE_TYPE = 'simple'
    CACHE_DEFAULT_TIMEOUT = 300  # 5 minutes
    
    @staticmethod
    def init_app(app):
        """
        Initialize application with configuration
        
        Args:
            app: Flask application instance
        """
        # Create required directories
        required_dirs = [
            Config.UPLOAD_FOLDER,
            Config.BACKUP_DIRECTORY,
            'logs'
        ]
        
        for directory in required_dirs:
            if not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
        
        # Set up logging
        import logging
        from logging.handlers import RotatingFileHandler
        
        if not app.debug and not app.testing:
            file_handler = RotatingFileHandler(
                Config.LOG_FILE,
                maxBytes=Config.LOG_MAX_BYTES,
                backupCount=Config.LOG_BACKUP_COUNT
            )
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            file_handler.setLevel(getattr(logging, Config.LOG_LEVEL))
            app.logger.addHandler(file_handler)
            app.logger.setLevel(getattr(logging, Config.LOG_LEVEL))
            app.logger.info('Secure Student Record Blockchain System startup')

class DevelopmentConfig(Config):
    """
    Development environment configuration
    """
    DEBUG = True
    TESTING = False
    
    # Relaxed security for development
    SESSION_COOKIE_SECURE = False
    RATE_LIMIT_ENABLED = False
    
    # Development database
    DATABASE_PATH = 'dev_secure_student_records.db'
    BLOCKCHAIN_DATA_FILE = 'dev_blockchain_data.json'
    
    # More verbose logging
    LOG_LEVEL = 'DEBUG'
    ACCESS_LOG_ENABLED = True
    
    # Development-specific endpoints
    ENABLE_DEBUG_ENDPOINTS = True

class TestingConfig(Config):
    """
    Testing environment configuration
    """
    DEBUG = False
    TESTING = True
    
    # Use in-memory database for testing
    DATABASE_PATH = ':memory:'
    BLOCKCHAIN_DATA_FILE = 'test_blockchain_data.json'
    
    # Disable external services during testing
    RATE_LIMIT_ENABLED = False
    BACKUP_ENABLED = False
    ACCESS_LOG_ENABLED = False
    
    # Fast encryption for testing
    BLOCKCHAIN_DIFFICULTY = 2
    
    # Test-specific settings
    WTF_CSRF_ENABLED = False
    SECRET_KEY = 'test-secret-key-not-for-production'

class ProductionConfig(Config):
    """
    Production environment configuration
    """
    DEBUG = False
    TESTING = False
    
    # Enhanced security for production
    SESSION_COOKIE_SECURE = True  # Requires HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    
    # Production database with full path
    DATABASE_PATH = os.environ.get('PROD_DATABASE_PATH') or '/var/lib/secure_records/secure_student_records.db'
    BLOCKCHAIN_DATA_FILE = os.environ.get('PROD_BLOCKCHAIN_FILE') or '/var/lib/secure_records/blockchain_data.json'
    
    # Enhanced security settings
    PASSWORD_MIN_LENGTH = 12
    BLOCKCHAIN_DIFFICULTY = 6  # More difficult for production security
    
    # Production logging
    LOG_LEVEL = 'WARNING'
    LOG_FILE = '/var/log/secure_records/app.log'
    
    # Rate limiting enabled
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_PER_MINUTE = 30  # More restrictive
    RATE_LIMIT_PER_HOUR = 500
    
    # Monitoring enabled
    METRICS_ENABLED = True
    ERROR_REPORTING_ENABLED = True
    
    # Backup configuration
    BACKUP_DIRECTORY = '/var/backups/secure_records'
    BACKUP_ENCRYPTION_ENABLED = True
    
    @classmethod
    def init_app(cls, app):
        """
        Production-specific initialization
        
        Args:
            app: Flask application instance
        """
        Config.init_app(app)
        
        # Email errors to administrators in production
        import logging
        from logging.handlers import SMTPHandler
        
        credentials = None
        secure = None
        
        if os.environ.get('MAIL_USERNAME'):
            credentials = (os.environ.get('MAIL_USERNAME'),
                          os.environ.get('MAIL_PASSWORD'))
            if os.environ.get('MAIL_USE_TLS'):
                secure = ()
        
        mail_handler = SMTPHandler(
            mailhost=(os.environ.get('MAIL_SERVER', 'localhost'), 
                     os.environ.get('MAIL_PORT', 587)),
            fromaddr=os.environ.get('MAIL_FROM', 'noreply@secure-records.edu'),
            toaddrs=os.environ.get('ADMIN_EMAILS', 'admin@secure-records.edu').split(','),
            subject='Secure Student Records System Error',
            credentials=credentials,
            secure=secure
        )
        
        mail_handler.setLevel(logging.ERROR)
        mail_handler.setFormatter(logging.Formatter('''
Message type:       %(levelname)s
Location:           %(pathname)s:%(lineno)d
Module:             %(module)s
Function:           %(funcName)s
Time:               %(asctime)s

Message:

%(message)s
        '''))
        
        if not app.debug and not app.testing:
            app.logger.addHandler(mail_handler)

# Configuration dictionary for easy access
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

def get_config():
    """
    Get configuration based on environment variable
    
    Returns:
        Configuration class
    """
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])

# Security Configuration Constants
class SecurityConfig:
    """
    Security-specific configuration constants
    """
    
    # Supported encryption algorithms
    SUPPORTED_ENCRYPTION_ALGORITHMS = ['Fernet', 'AES-256-GCM']
    
    # Supported hashing algorithms
    SUPPORTED_HASH_ALGORITHMS = ['SHA-256', 'SHA-512', 'BLAKE2b']
    
    # Password complexity requirements
    PASSWORD_COMPLEXITY = {
        'min_length': 8,
        'require_lowercase': True,
        'require_uppercase': True,
        'require_digits': True,
        'require_special_chars': True,
        'forbidden_patterns': ['password', '123456', 'qwerty']
    }
    
    # Session security settings
    SESSION_SECURITY = {
        'regenerate_on_login': True,
        'invalidate_on_password_change': True,
        'max_concurrent_sessions': 3,
        'track_ip_changes': True
    }
    
    # API security settings
    API_SECURITY = {
        'require_https': True,  # In production
        'rate_limiting': True,
        'request_size_limit': '10MB',
        'timeout_seconds': 30
    }

# Blockchain Configuration Constants
class BlockchainConfig:
    """
    Blockchain-specific configuration constants
    """
    
    # Block structure settings
    BLOCK_SETTINGS = {
        'max_data_size': 1024 * 1024,  # 1MB per block
        'timestamp_tolerance': 600,     # 10 minutes
        'hash_algorithm': 'SHA-256'
    }
    
    # Mining settings
    MINING_SETTINGS = {
        'difficulty_adjustment_blocks': 100,
        'target_block_time': 60,  # seconds
        'max_nonce': 2**32
    }
    
    # Consensus settings
    CONSENSUS_SETTINGS = {
        'pbft_timeout': 30,
        'max_retries': 3,
        'node_failure_threshold': 1  # Can tolerate 1 failed node out of 3
    }

if __name__ == '__main__':
    """
    Display configuration information when run directly
    """
    print("Secure Student Record Blockchain System - Configuration")
    print("=" * 60)
    
    env = os.environ.get('FLASK_ENV', 'development')
    config_class = get_config()
    
    print(f"Environment: {env}")
    print(f"Configuration: {config_class.__name__}")
    print(f"Debug Mode: {config_class.DEBUG}")
    print(f"Database: {config_class.DATABASE_PATH}")
    print(f"Blockchain File: {config_class.BLOCKCHAIN_DATA_FILE}")
    print(f"Log Level: {config_class.LOG_LEVEL}")
    print("=" * 60)