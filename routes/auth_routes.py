"""
Authentication routes for user registration, login, and session management
"""

from flask import Blueprint, request, jsonify, session, g
from functools import wraps
import traceback
from datetime import datetime, timedelta
from models.user import User
from database.db import DatabaseManager
from utils.permissions import PermissionAuditLog
from utils.logger import get_logger

logger = get_logger(__name__)

# Create authentication blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# Session configuration
SESSION_TIMEOUT = timedelta(hours=8)  # 8-hour session timeout

def login_required(f):
    """
    Decorator to require login for protected routes
    
    Args:
        f: Function to decorate
        
    Returns:
        Decorated function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or 'user_role' not in session:
            return jsonify({
                'success': False,
                'message': 'Authentication required',
                'error_code': 'AUTH_REQUIRED'
            }), 401
        
        # Check session timeout
        if 'login_time' in session:
            login_time = datetime.fromisoformat(session['login_time'])
            if datetime.now() - login_time > SESSION_TIMEOUT:
                session.clear()
                return jsonify({
                    'success': False,
                    'message': 'Session expired',
                    'error_code': 'SESSION_EXPIRED'
                }), 401
        
        return f(*args, **kwargs)
    
    return decorated_function

def role_required(required_roles):
    """
    Decorator to require specific roles for protected routes
    
    Args:
        required_roles (list): List of allowed roles
        
    Returns:
        Decorated function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_role' not in session:
                return jsonify({
                    'success': False,
                    'message': 'Authentication required',
                    'error_code': 'AUTH_REQUIRED'
                }), 401
            
            if session['user_role'] not in required_roles:
                return jsonify({
                    'success': False,
                    'message': 'Insufficient permissions',
                    'error_code': 'INSUFFICIENT_PERMISSIONS',
                    'required_roles': required_roles,
                    'user_role': session['user_role']
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Register a new user
    
    Expected JSON:
    {
        "username": "string",
        "email": "string", 
        "password": "string",
        "role": "admin|student|verifier",
        "student_id": "string" (optional, required for students)
    }
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['username', 'email', 'password', 'role']
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            return jsonify({
                'success': False,
                'message': f'Missing required fields: {", ".join(missing_fields)}',
                'error_code': 'MISSING_FIELDS'
            }), 400
        
        username = data['username'].strip()
        email = data['email'].strip()
        password = data['password']
        role = data['role'].lower()
        student_id = data.get('student_id', '').strip() if data.get('student_id') else None
        
        # Validate role
        if role not in ['admin', 'student', 'verifier']:
            return jsonify({
                'success': False,
                'message': 'Invalid role. Must be admin, student, or verifier',
                'error_code': 'INVALID_ROLE'
            }), 400
        
        # Validate student_id for student role
        if role == 'student' and not student_id:
            return jsonify({
                'success': False,
                'message': 'Student ID is required for student role',
                'error_code': 'STUDENT_ID_REQUIRED'
            }), 400
        
        # Check if user already exists
        existing_user = User.get_by_username(username)
        if existing_user:
            return jsonify({
                'success': False,
                'message': 'Username already exists',
                'error_code': 'USERNAME_EXISTS'
            }), 409
        
        # Create new user
        user = User(
            username=username,
            email=email,
            role=role,
            student_id=student_id
        )
        
        if user.save(password=password):
            return jsonify({
                'success': True,
                'message': 'User registered successfully',
                'user': user.to_dict(),
                'timestamp': datetime.now().isoformat()
            }), 201
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to create user',
                'error_code': 'USER_CREATION_FAILED'
            }), 500
            
    except ValueError as ve:
        return jsonify({
            'success': False,
            'message': str(ve),
            'error_code': 'VALIDATION_ERROR'
        }), 400
    except Exception as e:
        logger.error("Registration error", extra={"error": str(e), "traceback": traceback.format_exc()})
        return jsonify({
            'success': False,
            'message': 'Internal server error during registration',
            'error_code': 'REGISTRATION_ERROR'
        }), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Authenticate user and create session
    
    Expected JSON:
    {
        "username": "string",
        "password": "string"
    }
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('username') or not data.get('password'):
            return jsonify({
                'success': False,
                'message': 'Username and password are required',
                'error_code': 'MISSING_CREDENTIALS'
            }), 400
        
        username = data['username'].strip()
        password = data['password']
        
        # Authenticate user
        user = User.authenticate(username, password)
        
        if user:
            # Create session
            session['username'] = user.username
            session['user_role'] = user.role
            session['user_id'] = user.user_id
            session['student_id'] = user.student_id
            session['login_time'] = datetime.now().isoformat()
            
            # Log successful login
            db_manager = DatabaseManager()
            db_manager.log_access_attempt(
                student_id=user.student_id or 'N/A',
                accessor_username=user.username,
                record_id=None,
                action='LOGIN',
                access_granted=True,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'user': user.to_dict(),
                'session_expires_at': (datetime.now() + SESSION_TIMEOUT).isoformat(),
                'timestamp': datetime.now().isoformat()
            }), 200
        else:
            # Log failed login attempt
            db_manager = DatabaseManager()
            db_manager.log_access_attempt(
                student_id='UNKNOWN',
                accessor_username=username,
                record_id=None,
                action='LOGIN_FAILED',
                access_granted=False,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            
            return jsonify({
                'success': False,
                'message': 'Invalid username or password',
                'error_code': 'INVALID_CREDENTIALS'
            }), 401
            
    except Exception as e:
        logger.error("Login error", extra={"error": str(e), "traceback": traceback.format_exc()})
        return jsonify({
            'success': False,
            'message': 'Internal server error during login',
            'error_code': 'LOGIN_ERROR'
        }), 500

@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """
    Logout user and clear session
    """
    try:
        username = session.get('username')
        
        # Log logout
        if username:
            db_manager = DatabaseManager()
            db_manager.log_access_attempt(
                student_id=session.get('student_id', 'N/A'),
                accessor_username=username,
                record_id=None,
                action='LOGOUT',
                access_granted=True,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
        
        # Clear session
        session.clear()
        
        return jsonify({
            'success': True,
            'message': 'Logout successful',
            'timestamp': datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        logger.error("Logout error", extra={"error": str(e)})
        return jsonify({
            'success': False,
            'message': 'Error during logout',
            'error_code': 'LOGOUT_ERROR'
        }), 500

@auth_bp.route('/profile', methods=['GET'])
@login_required
def get_profile():
    """
    Get current user profile information
    """
    try:
        username = session.get('username')
        user = User.get_by_username(username)
        
        if user:
            return jsonify({
                'success': True,
                'user': user.to_dict(include_sensitive=True),
                'session_info': {
                    'login_time': session.get('login_time'),
                    'expires_at': (datetime.fromisoformat(session['login_time']) + SESSION_TIMEOUT).isoformat() if session.get('login_time') else None
                },
                'timestamp': datetime.now().isoformat()
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'User not found',
                'error_code': 'USER_NOT_FOUND'
            }), 404
            
    except Exception as e:
        logger.error("Profile error", extra={"error": str(e)})
        return jsonify({
            'success': False,
            'message': 'Error retrieving profile',
            'error_code': 'PROFILE_ERROR'
        }), 500

@auth_bp.route('/check-session', methods=['GET'])
def check_session():
    """
    Check if current session is valid
    """
    try:
        if 'username' not in session:
            return jsonify({
                'success': False,
                'authenticated': False,
                'message': 'No active session'
            }), 200
        
        # Check session timeout
        if 'login_time' in session:
            login_time = datetime.fromisoformat(session['login_time'])
            if datetime.now() - login_time > SESSION_TIMEOUT:
                session.clear()
                return jsonify({
                    'success': False,
                    'authenticated': False,
                    'message': 'Session expired'
                }), 200
        
        return jsonify({
            'success': True,
            'authenticated': True,
            'username': session['username'],
            'role': session['user_role'],
            'login_time': session.get('login_time'),
            'expires_at': (datetime.fromisoformat(session['login_time']) + SESSION_TIMEOUT).isoformat() if session.get('login_time') else None
        }), 200
        
    except Exception as e:
        logger.error("Session check error", extra={"error": str(e)})
        return jsonify({
            'success': False,
            'authenticated': False,
            'message': 'Error checking session'
        }), 500

@auth_bp.route('/grant-access', methods=['POST'])
@login_required
@role_required(['student'])
def grant_access():
    """
    Grant access permission to a verifier (students only)
    
    Expected JSON:
    {
        "verifier_username": "string",
        "record_type": "string" (optional),
        "expires_in_days": number (optional, default 30)
    }
    """
    try:
        data = request.get_json()
        
        if not data.get('verifier_username'):
            return jsonify({
                'success': False,
                'message': 'Verifier username is required',
                'error_code': 'MISSING_VERIFIER'
            }), 400
        
        verifier_username = data['verifier_username'].strip()
        record_type = data.get('record_type')
        expires_in_days = data.get('expires_in_days', 30)
        
        # Verify verifier exists and has verifier role
        verifier = User.get_by_username(verifier_username)
        if not verifier:
            return jsonify({
                'success': False,
                'message': 'Verifier not found',
                'error_code': 'VERIFIER_NOT_FOUND'
            }), 404
        
        if verifier.role != 'verifier':
            return jsonify({
                'success': False,
                'message': 'User is not a verifier',
                'error_code': 'INVALID_VERIFIER_ROLE'
            }), 400
        
        # Get current user
        username = session.get('username')
        user = User.get_by_username(username)
        
        # Calculate expiration date
        expires_at = datetime.now() + timedelta(days=expires_in_days)
        
        # Grant access
        if user.grant_access_to_verifier(verifier_username, record_type, expires_at):
            # Log the access grant
            db_manager = DatabaseManager()
            db_manager.log_access_attempt(
                student_id=user.student_id,
                accessor_username=username,
                record_id=None,
                action=f'GRANT_ACCESS_TO_{verifier_username}',
                access_granted=True,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            
            return jsonify({
                'success': True,
                'message': 'Access granted successfully',
                'grant_details': {
                    'verifier': verifier_username,
                    'record_type': record_type or 'all',
                    'expires_at': expires_at.isoformat(),
                    'granted_by': username,
                    'granted_at': datetime.now().isoformat()
                }
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to grant access',
                'error_code': 'GRANT_ACCESS_FAILED'
            }), 500
            
    except Exception as e:
        logger.error("Grant access error", extra={"error": str(e)})
        return jsonify({
            'success': False,
            'message': 'Error granting access',
            'error_code': 'GRANT_ACCESS_ERROR'
        }), 500


@auth_bp.route('/revoke-access', methods=['POST'])
@login_required
@role_required(['student'])
def revoke_access():
    """
    Revoke a verifier's delegated access (students only).

    Expected JSON:
    {
        "verifier_username": "string",
        "record_type": "string" (optional)
    }
    """
    try:
        data = request.get_json()
        if not data or not data.get('verifier_username'):
            return jsonify({
                'success': False,
                'message': 'verifier_username is required',
                'error_code': 'MISSING_VERIFIER'
            }), 400

        verifier_username = data['verifier_username'].strip()
        record_type = data.get('record_type')
        username = session.get('username')
        user = User.get_by_username(username)

        if user.revoke_access_from_verifier(verifier_username, record_type):
            logger.info("Access revoked",
                        extra={"actor": username, "verifier": verifier_username,
                               "record_type": record_type,
                               "correlation_id": getattr(g, 'correlation_id', None)})
            return jsonify({
                'success': True,
                'message': 'Access revoked successfully',
                'revoke_details': {
                    'verifier': verifier_username,
                    'record_type': record_type or 'all',
                    'revoked_by': username,
                    'revoked_at': datetime.now().isoformat()
                }
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to revoke access',
                'error_code': 'REVOKE_ACCESS_FAILED'
            }), 500
    except Exception as e:
        logger.error("Revoke access error", extra={"error": str(e)})
        return jsonify({
            'success': False,
            'message': 'Error revoking access',
            'error_code': 'REVOKE_ACCESS_ERROR'
        }), 500


@auth_bp.route('/permissions/audit', methods=['GET'])
@login_required
@role_required(['admin'])
def permissions_audit():
    """
    Return the permission audit trail (admin only).
    Query params:
        limit   — max entries to return (default 50)
        actor   — filter by actor username
        owner   — filter by owner student_id
    """
    try:
        limit = int(request.args.get('limit', 50))
        actor = request.args.get('actor')
        owner = request.args.get('owner')

        entries = PermissionAuditLog.get_entries(limit=limit, actor=actor, owner=owner)
        return jsonify({
            'success': True,
            'audit_entries': entries,
            'total': len(entries),
            'filters': {'actor': actor, 'owner': owner, 'limit': limit}
        }), 200
    except Exception as e:
        logger.error("Audit log error", extra={"error": str(e)})
        return jsonify({
            'success': False,
            'message': 'Error retrieving audit log',
            'error_code': 'AUDIT_LOG_ERROR'
        }), 500

# Helper function to get current user from session
def get_current_user():
    """
    Get current authenticated user from session
    
    Returns:
        User or None: Current user object or None if not authenticated
    """
    if 'username' in session:
        return User.get_by_username(session['username'])
    return None