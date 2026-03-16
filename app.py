"""
Main Flask application for Secure Student Record Blockchain System

This application provides a REST API for managing secure student academic records
using blockchain technology with PBFT consensus and advanced encryption.

Features:
- User authentication and role-based access control
- Encrypted data storage with data masking
- Blockchain-based record verification
- PBFT consensus for block validation
- Comprehensive audit logging
"""

from flask import Flask, jsonify, request, session, g, render_template
from flask_cors import CORS
from datetime import datetime, timedelta
import os
import sys
import traceback
import uuid
import json

# Add project root to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import Config
from routes import auth_bp, record_bp
from database.db import DatabaseManager
from models.user import User
from utils.logger import get_logger
from utils.encryption import EncryptionUtils
from utils.hashing import HashingUtils
from utils.masking import DataMasking
from utils.singletons import get_blockchain, get_pbft_consensus, validate_blockchain, get_system_stats
from utils.exceptions import BlockchainIntegrityError, EncryptionError
from oauth_client import init_oauth

logger = get_logger(__name__)

def create_app(config_class=Config):
    """
    Application factory pattern for creating Flask app
    
    Args:
        config_class: Configuration class to use
        
    Returns:
        Flask: Configured Flask application
    """
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize CORS for cross-origin requests
    CORS(app, supports_credentials=True)
    
    # Initialize OAuth providers (Google)
    init_oauth(app)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(record_bp)
    
    # Startup health checks
    startup_checks_passed = perform_startup_checks(app)
    
    if not startup_checks_passed:
        logger.error("Startup checks failed - application may be unstable")
    
    return app

def perform_startup_checks(app):
    """
    Perform comprehensive startup health checks
    
    Returns:
        bool: True if all checks pass, False otherwise
    """
    checks_passed = True
    
    # Database health check
    try:
        with app.app_context():
            db_manager = DatabaseManager()
            db_stats = db_manager.get_database_stats()
            logger.info("Database initialized", extra=db_stats)
    except Exception as e:
        logger.error("Database health check failed", extra={"error": str(e)})
        checks_passed = False
    
    # Blockchain health check
    try:
        blockchain = get_blockchain()
        if validate_blockchain():
            logger.info("Blockchain validation passed", 
                       extra={"blocks": len(blockchain.chain)})
        else:
            logger.error("Blockchain validation failed")
            checks_passed = False
    except BlockchainIntegrityError as e:
        logger.error("Blockchain integrity error", extra={"error": str(e)})
        checks_passed = False
    except Exception as e:
        logger.error("Blockchain health check failed", extra={"error": str(e)})
        checks_passed = False
    
    # PBFT consensus health check
    try:
        pbft_consensus = get_pbft_consensus()
        logger.info("PBFT consensus initialized", 
                   extra={"nodes": len(pbft_consensus.nodes)})
    except Exception as e:
        logger.error("PBFT consensus health check failed", extra={"error": str(e)})
        checks_passed = False
    
    # Encryption health check
    try:
        enc = EncryptionUtils()
        if enc.validate_round_trip():
            logger.info("Encryption validation passed")
        else:
            logger.error("Encryption validation failed")
            checks_passed = False
    except EncryptionError as e:
        logger.error("Encryption error", extra={"error": str(e)})
        checks_passed = False
    except Exception as e:
        logger.error("Encryption health check failed", extra={"error": str(e)})
        checks_passed = False
    
    return checks_passed

def get_system_stats():
    """Get comprehensive system statistics from singleton instances"""
    try:
        blockchain = get_blockchain()
        pbft_consensus = get_pbft_consensus()
        
        blockchain_info = blockchain.get_chain_info()
        consensus_stats = pbft_consensus.get_consensus_stats()
        
        return {
            'blockchain': blockchain_info,
            'consensus': consensus_stats
        }
    except Exception as e:
        logger.error("Error getting system stats", extra={"error": str(e)})
        return {
            'blockchain': {'total_blocks': 0, 'is_valid': False},
            'consensus': {'total_validations': 0}
        }

# Create Flask application
app = create_app()

@app.route('/api', methods=['GET'])
def api_info():
    """
    API endpoint providing system information and API documentation
    """
    return jsonify({
        'system': 'Secure Student Record Blockchain',
        'version': '1.0.0',
        'status': 'operational',
        'timestamp': datetime.now().isoformat(),
        'description': 'Production-quality blockchain-based secure education data management system',
        'features': [
            'Encrypted data storage with Fernet (AES)',
            'SHA256 hashing for data integrity', 
            'Custom blockchain with PBFT consensus',
            'Role-based access control (Admin, Student, Verifier)',
            'Data masking for sensitive information',
            'Smart contract-like permission system',
            'Comprehensive audit logging'
        ],
        'endpoints': {
            'authentication': {
                'POST /auth/register': 'Register new user',
                'POST /auth/login': 'User login',
                'POST /auth/logout': 'User logout',
                'GET /auth/profile': 'Get user profile',
                'GET /auth/check-session': 'Check session validity',
                'POST /auth/grant-access': 'Grant access to verifier (students only)'
            },
            'records': {
                'POST /records/upload': 'Upload student record (admin only)',
                'GET /records/view/<student_id>': 'View student records',
                'GET /records/verify/<student_id>/<record_id>': 'Verify record authenticity',
                'GET /records/blockchain/info': 'Get blockchain information',
                'GET /records/statistics': 'Get system statistics (admin only)',
                'POST /records/search': 'Search records (admin only)'
            },
            'system': {
                'GET /': 'System information',
                'GET /dashboard': 'Blockchain Control Dashboard (HTML)',
                'GET /health': 'Health check',
                'GET /api-docs': 'Detailed API documentation'
            }
        },
        'security': {
            'encryption': 'Fernet (AES 128)',
            'hashing': 'SHA-256',
            'consensus': 'PBFT (3 nodes)',
            'session_timeout': '8 hours'
        }
    }), 200

@app.route('/dashboard', methods=['GET'])
def dashboard():
    """
    Blockchain Control Dashboard for presentation and demonstration
    
    Renders an HTML dashboard page with system status and quick actions
    """
    try:
        # Fetch data from existing internal endpoints
        db_manager = DatabaseManager()
        db_stats = db_manager.get_database_stats()
        
        # Get system stats from singletons
        system_stats = get_system_stats()
        
        # Prepare dashboard data
        dashboard_data = {
            # Blockchain status
            'blockchain_valid': system_stats['blockchain']['is_valid'],
            'total_blocks': system_stats['blockchain']['total_blocks'],
            'latest_block': system_stats['blockchain']['total_blocks'] - 1 if system_stats['blockchain']['total_blocks'] > 0 else 0,
            
            # PBFT Consensus status
            'consensus_online': True,  # Assume online if we can get stats
            'total_validations': system_stats['consensus'].get('total_validations', 0),
            
            # Database status
            'database_online': True,  # If we got here, database is working
            'total_records': db_stats['total_records'],
            'verified_records': db_stats['verified_records'],
            
            # System health
            'system_healthy': (
                system_stats['blockchain']['is_valid'] and 
                db_stats['total_records'] >= 0
            ),
            'last_updated': datetime.now().strftime('%H:%M:%S'),
            'correlation_id': getattr(g, 'correlation_id', 'dashboard-' + str(uuid.uuid4())[:8])
        }
        
        logger.info("Dashboard accessed", 
                   extra={
                       "blockchain_blocks": dashboard_data['total_blocks'],
                       "database_records": dashboard_data['total_records'],
                       "system_health": dashboard_data['system_healthy']
                   })
        
        return render_template('dashboard.html', **dashboard_data)
        
    except Exception as e:
        logger.error("Dashboard error", extra={"error": str(e)})
        # Fallback data in case of errors
        fallback_data = {
            'blockchain_valid': False,
            'total_blocks': 0,
            'latest_block': 0,
            'consensus_online': False,
            'total_validations': 0,
            'database_online': False,
            'total_records': 0,
            'verified_records': 0,
            'system_healthy': False,
            'last_updated': datetime.now().strftime('%H:%M:%S'),
            'correlation_id': 'error-' + str(uuid.uuid4())[:8]
        }
        return render_template('dashboard.html', **fallback_data)

@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint for monitoring system status
    """
    try:
        # Test database connection
        db_manager = DatabaseManager()
        db_stats = db_manager.get_database_stats()
        
        # Get system stats from singletons
        system_stats = get_system_stats()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'components': {
                'database': {
                    'status': 'online',
                    'total_records': db_stats['total_records'],
                    'verified_records': db_stats['verified_records']
                },
                'blockchain': {
                    'status': 'online',
                    'total_blocks': system_stats['blockchain']['total_blocks'],
                    'is_valid': system_stats['blockchain']['is_valid']
                },
                'consensus': {
                    'status': 'online',
                    'total_validations': system_stats['consensus'].get('total_validations', 0)
                }
            },
            'correlation_id': getattr(g, 'correlation_id', 'health-check')
        }), 200
        
    except Exception as e:
        logger.error("Health check failed", extra={"error": str(e)})
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.now().isoformat(),
            'error': str(e),
            'correlation_id': getattr(g, 'correlation_id', 'health-check-error')
        }), 503

@app.route('/api-docs', methods=['GET'])
def api_documentation():
    """
    Comprehensive API documentation
    """
    return jsonify({
        'title': 'Secure Student Record Blockchain API',
        'version': '1.0.0',
        'description': 'REST API for secure management of student academic records using blockchain technology',
        'base_url': request.base_url.replace('/api-docs', ''),
        'authentication': {
            'type': 'session-based',
            'session_timeout': '8 hours',
            'required_headers': {
                'Content-Type': 'application/json',
                'Cookie': 'session cookie (automatic after login)'
            }
        },
        'user_roles': {
            'admin': {
                'description': 'Full system access',
                'permissions': [
                    'Upload student records',
                    'View all records', 
                    'Verify records',
                    'View system statistics',
                    'Search records'
                ]
            },
            'student': {
                'description': 'Access own records',
                'permissions': [
                    'View own records',
                    'Grant access to verifiers',
                    'View own profile'
                ]
            },
            'verifier': {
                'description': 'Verify record authenticity',
                'permissions': [
                    'Verify records (with permission)',
                    'View blockchain information',
                    'Access granted records'
                ]
            }
        },
        'record_types': {
            'supported_types': [
                'transcript', 'certificate', 'diploma', 
                'grade_card', 'achievement', 'enrollment', 'completion'
            ],
            'required_fields': {
                'all_types': ['student_name', 'student_id', 'institution'],
                'transcript': ['courses', 'grades', 'gpa', 'semester'],
                'certificate': ['certificate_name', 'issued_date', 'issuing_authority'],
                'diploma': ['degree_name', 'graduation_date', 'honors']
            }
        },
        'security_features': {
            'data_encryption': 'Fernet (AES 128) with PBKDF2 key derivation',
            'data_masking': 'Sensitive field masking for display',
            'blockchain_consensus': 'PBFT with 3 validation nodes',
            'audit_logging': 'Comprehensive access and action logs',
            'integrity_verification': 'SHA-256 hashing with blockchain verification'
        },
        'error_codes': {
            'AUTH_REQUIRED': 'Authentication required',
            'SESSION_EXPIRED': 'Session has expired',
            'INSUFFICIENT_PERMISSIONS': 'User lacks required permissions',
            'INVALID_CREDENTIALS': 'Username or password incorrect',
            'ACCESS_DENIED': 'Access to resource denied',
            'RECORD_NOT_FOUND': 'Requested record not found',
            'VALIDATION_FAILED': 'Data validation failed',
            'BLOCKCHAIN_ERROR': 'Blockchain operation failed'
        },
        'examples': {
            'register_user': {
                'method': 'POST',
                'url': '/auth/register',
                'body': {
                    'username': 'john_admin',
                    'email': 'john@university.edu',
                    'password': 'securepassword',
                    'role': 'admin'
                }
            },
            'upload_record': {
                'method': 'POST', 
                'url': '/records/upload',
                'body': {
                    'student_id': 'STU123456',
                    'record_type': 'transcript',
                    'record_data': {
                        'student_name': 'Jane Smith',
                        'student_id': 'STU123456',
                        'institution': 'University of Technology',
                        'program': 'Computer Science',
                        'semester': 'Fall 2024',
                        'courses': [
                            {'course': 'CS101', 'grade': 'A', 'credits': 3},
                            {'course': 'MATH201', 'grade': 'B+', 'credits': 4}
                        ],
                        'gpa': 3.75
                    }
                }
            }
        }
    }), 200

@app.route('/demo', methods=['GET'])
def demo_endpoint():
    """
    Demonstration endpoint showcasing the complete secure record workflow
    """
    try:
        # Demo data
        demo_data = {
            'student_id': 'DEMO123',
            'record_type': 'transcript',
            'record_data': {
                'student_name': 'Demo Student',
                'institution': 'Demo University',
                'program': 'Computer Science Demo',
                'semester': 'Spring 2024',
                'courses': [
                    {'course': 'CS101', 'grade': 'A', 'credits': 3},
                    {'course': 'MATH201', 'grade': 'B+', 'credits': 4}
                ],
                'gpa': 3.75
            }
        }
        
        # Get blockchain and PBFT from singletons
        blockchain = get_blockchain()
        pbft_consensus = get_pbft_consensus()
        
        # Database operations
        db_manager = DatabaseManager()
        
        # Encrypt the demo data
        enc = EncryptionUtils()
        encrypted_data = enc.encrypt_data(str(demo_data['record_data']))
        
        # Hash the raw data for integrity
        hasher = HashingUtils()
        data_hash = hasher.generate_sha256(str(demo_data['record_data']))
        
        # Mask sensitive information for display
        masker = DataMasking()
        masked_data = masker.mask_sensitive_data(demo_data['record_data'], 'transcript')
        
        # Create a demo blockchain transaction
        block_data = {
            'student_id': demo_data['student_id'],
            'record_type': demo_data['record_type'],
            'data_hash': data_hash,
            'timestamp': datetime.now().isoformat(),
            'operation': 'demo_upload'
        }
        
        # Add block to blockchain via PBFT consensus
        consensus_result = pbft_consensus.validate_block_addition(
            data_hash, demo_data['student_id'], demo_data['record_type']
        )
        if consensus_result.get('consensus_reached', False):
            new_block = blockchain.add_block(block_data)
            
            logger.info("Demo block added to blockchain", 
                       extra={
                           "block_id": new_block.index,
                           "student_id": demo_data['student_id'],
                           "operation": "demo"
                       })
        
        # Get current blockchain stats
        stats = get_system_stats()
        
        return jsonify({
            'success': True,
            'message': 'Demo workflow completed successfully',
            'demo_data': {
                'original': demo_data,
                'encrypted_size': len(encrypted_data),
                'data_hash': data_hash[:32] + '...',  # Truncate for display
                'masked_display': masked_data
            },
            'blockchain_stats': {
                'total_blocks': stats['blockchain']['total_blocks'],
                'chain_valid': stats['blockchain']['is_valid'],
                'latest_block': new_block.index if 'new_block' in locals() else None
            },
            'security_features': {
                'encryption': 'Fernet (AES-128)',
                'hashing': 'SHA-256',
                'consensus': 'PBFT',
                'data_masking': 'Applied to sensitive fields'
            },
            'correlation_id': getattr(g, 'correlation_id', 'demo-request')
        }), 200
        
    except Exception as e:
        logger.error("Demo endpoint failed", extra={"error": str(e)})
        return jsonify({
            'success': False,
            'error': 'Demo workflow failed',
            'message': str(e),
            'correlation_id': getattr(g, 'correlation_id', 'demo-error')
        }), 500

@app.errorhandler(400)
def bad_request(error):
    """Handle 400 Bad Request errors"""
    return jsonify({
        'success': False,
        'error': 'Bad Request',
        'message': 'The request could not be understood by the server',
        'error_code': 'BAD_REQUEST',
        'timestamp': datetime.now().isoformat()
    }), 400

@app.errorhandler(401)
def unauthorized(error):
    """Handle 401 Unauthorized errors"""
    return jsonify({
        'success': False,
        'error': 'Unauthorized',
        'message': 'Authentication required to access this resource',
        'error_code': 'UNAUTHORIZED',
        'timestamp': datetime.now().isoformat()
    }), 401

@app.errorhandler(403)
def forbidden(error):
    """Handle 403 Forbidden errors"""
    return jsonify({
        'success': False,
        'error': 'Forbidden',
        'message': 'You do not have permission to access this resource',
        'error_code': 'FORBIDDEN',
        'timestamp': datetime.now().isoformat()
    }), 403

@app.errorhandler(404)
def not_found(error):
    """Handle 404 Not Found errors"""
    return jsonify({
        'success': False,
        'error': 'Not Found',
        'message': 'The requested resource was not found',
        'error_code': 'NOT_FOUND',
        'timestamp': datetime.now().isoformat()
    }), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 Internal Server Error"""
    return jsonify({
        'success': False,
        'error': 'Internal Server Error',
        'message': 'An unexpected error occurred on the server',
        'error_code': 'INTERNAL_ERROR',
        'timestamp': datetime.now().isoformat()
    }), 500

@app.before_request
def before_request():
    """
    Execute before each request
    
    - Generate correlation ID for request tracing
    - Log request details with correlation ID
    - Validate JSON for POST/PUT requests
    """
    # Generate correlation ID for request tracing
    g.correlation_id = str(uuid.uuid4())
    g.start_time = datetime.now()
    
    # Skip logging for health checks and static files
    if request.endpoint not in ['health_check', 'index']:
        logger.info("Request started", extra={
            "method": request.method,
            "path": request.path,
            "remote_addr": request.remote_addr,
            "user_agent": request.user_agent.string[:100] if request.user_agent else None,
            "correlation_id": g.correlation_id
        })
    
    # Validate JSON for POST/PUT requests
    if request.method in ['POST', 'PUT'] and request.content_type == 'application/json':
        try:
            request.get_json(force=True)
        except Exception:
            return jsonify({
                'success': False,
                'message': 'Invalid JSON in request body',
                'error_code': 'INVALID_JSON',
                'correlation_id': g.correlation_id
            }), 400

@app.after_request
def after_request(response):
    """
    Execute after each request
    
    - Add security headers
    - Add correlation ID to response
    - Log response status and duration
    """
    # Add correlation ID to response headers
    if hasattr(g, 'correlation_id'):
        response.headers['X-Correlation-ID'] = g.correlation_id
    
    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Log response (skip health checks)
    if request.endpoint not in ['health_check', 'index'] and hasattr(g, 'start_time'):
        duration = (datetime.now() - g.start_time).total_seconds() * 1000
        logger.info("Request completed", extra={
            "status_code": response.status_code,
            "duration_ms": round(duration, 2),
            "correlation_id": getattr(g, 'correlation_id', 'unknown')
        })
    
    return response

# ============================================================================
# FRONTEND TEMPLATE ROUTES
# ============================================================================

@app.route('/login', methods=['GET'])
def login_page():
    """
    Render login page
    """
    # Determine if Google OAuth is configured (used to toggle button visibility)
    google_enabled = bool(
        os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET")
    )
    return render_template('login.html', google_enabled=google_enabled)


@app.route('/register', methods=['GET'])
def register_page():
    """
    Render student registration page
    """
    google_enabled = bool(
        os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET")
    )
    # Pass allowed domains for basic UX hint
    from config import Config as AppConfig

    domains = getattr(AppConfig, "COLLEGE_EMAIL_DOMAINS", None) or getattr(
        AppConfig, "COLLEGE_EMAIL_DOMAIN", None
    )
    if isinstance(domains, (list, tuple, set)):
        allowed_domains = ", ".join(sorted(domains))
    elif domains:
        allowed_domains = str(domains)
    else:
        allowed_domains = "college.edu"

    return render_template(
        'register.html',
        google_enabled=google_enabled,
        allowed_domains=allowed_domains,
    )

@app.route('/admin_dashboard', methods=['GET'])
def admin_dashboard():
    """
    Admin Dashboard - replaces the original dashboard with modern UI
    
    Renders an HTML dashboard page with system status and admin functions
    """
    try:
        # Fetch data from existing internal endpoints
        db_manager = DatabaseManager()
        db_stats = db_manager.get_database_stats()
        
        # Get system stats from singletons
        system_stats = get_system_stats()
        
        # Prepare dashboard data
        dashboard_data = {
            # Blockchain status
            'blockchain_valid': system_stats['blockchain']['is_valid'],
            'total_blocks': system_stats['blockchain']['total_blocks'],
            'latest_block': system_stats['blockchain']['total_blocks'] - 1 if system_stats['blockchain']['total_blocks'] > 0 else 0,
            
            # PBFT Consensus status
            'consensus_online': True,  # Assume online if we can get stats
            'total_validations': system_stats['consensus'].get('total_validations', 0),
            
            # Database status
            'database_online': True,  # If we got here, database is working
            'total_records': db_stats['total_records'],
            'verified_records': db_stats['verified_records'],
            
            # System health
            'system_healthy': (
                system_stats['blockchain']['is_valid'] and 
                db_stats['total_records'] >= 0
            ),
            'last_updated': datetime.now().strftime('%H:%M:%S'),
            'correlation_id': getattr(g, 'correlation_id', 'dashboard-' + str(uuid.uuid4())[:8])
        }
        
        logger.info("Admin dashboard accessed", 
                   extra={
                       "blockchain_blocks": dashboard_data['total_blocks'],
                       "database_records": dashboard_data['total_records'],
                       "system_health": dashboard_data['system_healthy']
                   })
        
        return render_template('admin_dashboard.html', **dashboard_data)
        
    except Exception as e:
        logger.error("Admin dashboard error", extra={"error": str(e)})
        # Fallback data in case of errors
        fallback_data = {
            'blockchain_valid': False,
            'total_blocks': 0,
            'latest_block': 0,
            'consensus_online': False,
            'total_validations': 0,
            'database_online': False,
            'total_records': 0,
            'verified_records': 0,
            'system_healthy': False,
            'last_updated': datetime.now().strftime('%H:%M:%S'),
            'correlation_id': 'error-' + str(uuid.uuid4())[:8]
        }
        return render_template('admin_dashboard.html', **fallback_data)

@app.route('/student_portal', methods=['GET'])
def student_portal():
    """
    Student Portal - view own academic records
    """
    try:
        # In a real implementation, you would:
        # 1. Get the current student user from session
        # 2. Filter records by student_id
        # 3. Return only records belonging to this student
        
        # Mock data for demonstration
        student_data = {
            'student_name': 'John Doe',
            'student_id': 'STU123456',
            'total_records': 3,
            'verified_records': 2,
            'pending_records': 1
        }
        
        logger.info("Student portal accessed", extra=student_data)
        return render_template('student_portal.html', **student_data)
        
    except Exception as e:
        logger.error("Student portal error", extra={"error": str(e)})
        return render_template('student_portal.html', error="Unable to load student records")

@app.route('/verifier_panel', methods=['GET'])
def verifier_panel():
    """
    Verifier Panel - verify student records by ID
    """
    try:
        verifier_data = {
            'verifier_name': 'Jane Smith',
            'verifier_id': 'VER001',
            'total_verifications_today': 12,
            'successful_verifications': 10,
            'failed_verifications': 2
        }
        
        logger.info("Verifier panel accessed", extra=verifier_data)
        return render_template('verifier_panel.html', **verifier_data)
        
    except Exception as e:
        logger.error("Verifier panel error", extra={"error": str(e)})
        return render_template('verifier_panel.html', error="Unable to load verifier panel")

@app.route('/blockchain_explorer', methods=['GET'])
def blockchain_explorer():
    """
    Blockchain Explorer - visualize blocks in the blockchain
    """
    try:
        # Get blockchain data
        blockchain = get_blockchain()
        system_stats = get_system_stats()
        
        explorer_data = {
            'total_blocks': len(blockchain.chain),
            'total_transactions': sum(len(block.transactions) if hasattr(block, 'transactions') else 1 for block in blockchain.chain),
            'blockchain_valid': system_stats['blockchain']['is_valid'],
            'network_hash_rate': '256 SHA',  # Mock data
            'latest_block_hash': blockchain.chain[-1].hash if blockchain.chain else None,
            'genesis_block_hash': blockchain.chain[0].hash if blockchain.chain else None
        }
        
        logger.info("Blockchain explorer accessed", extra=explorer_data)
        return render_template('blockchain_explorer.html', **explorer_data)
        
    except Exception as e:
        logger.error("Blockchain explorer error", extra={"error": str(e)})
        fallback_data = {
            'total_blocks': 0,
            'total_transactions': 0,
            'blockchain_valid': False,
            'network_hash_rate': 'Unknown',
            'latest_block_hash': None,
            'genesis_block_hash': None
        }
        return render_template('blockchain_explorer.html', **fallback_data)

@app.route('/api/blockchain/blocks', methods=['GET'])
def get_blockchain_blocks():
    """
    API endpoint to get blockchain blocks data for the explorer
    """
    try:
        blockchain = get_blockchain()
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        # Convert blocks to JSON-serializable format
        blocks_data = []
        for i, block in enumerate(blockchain.chain):
            block_data = {
                'id': i,
                'hash': getattr(block, 'hash', f'block_{i}_hash'),
                'previous_hash': getattr(block, 'previous_hash', f'block_{i-1}_hash' if i > 0 else '0'),
                'timestamp': getattr(block, 'timestamp', datetime.now()).isoformat(),
                'nonce': getattr(block, 'nonce', 0),
                'merkle_root': getattr(block, 'merkle_root', f'merkle_{i}'),
                'transactions': getattr(block, 'transactions', []),
                'status': 'validated'
            }
            blocks_data.append(block_data)
        
        # Pagination
        start = (page - 1) * per_page
        end = start + per_page
        paginated_blocks = blocks_data[start:end]
        
        return jsonify({
            'success': True,
            'blocks': paginated_blocks,
            'total_blocks': len(blocks_data),
            'page': page,
            'per_page': per_page,
            'total_pages': (len(blocks_data) + per_page - 1) // per_page
        })
        
    except Exception as e:
        logger.error("API blockchain blocks error", extra={"error": str(e)})
        return jsonify({
            'success': False,
            'message': 'Unable to fetch blockchain data',
            'error': str(e)
        }), 500

# Redirect root to appropriate dashboard based on user role
@app.route('/', methods=['GET'])
def root_redirect():
    """
    Root route - redirect to appropriate dashboard or login
    """
    # In a real implementation, check if user is logged in and redirect based on role
    # For now, redirect to login page
    from flask import redirect, url_for
    return redirect(url_for('login_page'))

if __name__ == '__main__':
    """
    Run the application in development mode
    
    For production deployment, use a proper WSGI server like Gunicorn:
    gunicorn --bind 0.0.0.0:8000 --workers 4 app:app
    """
    print("\n" + "="*80)
    print("SECURE STUDENT RECORD BLOCKCHAIN SYSTEM")
    print("="*80)
    print("🔐 Blockchain-based secure education data management")
    print("🛡️  Advanced encryption and PBFT consensus")
    print("👥 Multi-role access control (Admin, Student, Verifier)")
    print("📊 Comprehensive audit logging and verification")
    print("="*80)
    print("🚀 Starting development server...")
    print("📍 Access the API at: http://localhost:5000")
    print("📚 API Documentation: http://localhost:5000/api-docs")
    print("💚 Health Check: http://localhost:5000/health")
    print("="*80)
    
    try:
        app.run(
            host='0.0.0.0',  # Allow external connections
            port=5000,
            debug=True,      # Enable debug mode for development
            threaded=True    # Handle multiple requests concurrently
        )
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"\n❌ Server error: {e}")
        print(traceback.format_exc())