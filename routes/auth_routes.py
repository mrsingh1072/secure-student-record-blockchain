"""
Authentication routes for user registration, login, and session management
"""

from flask import Blueprint, request, jsonify, session, g
from functools import wraps
import re
import traceback
from datetime import datetime, timedelta

from config import Config
from models.user import User
from database.db import DatabaseManager
from utils.permissions import PermissionAuditLog
from utils.logger import get_logger
from oauth_client import oauth

logger = get_logger(__name__)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

# Session configuration
SESSION_TIMEOUT = timedelta(hours=8)  # 8-hour session timeout


EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _get_allowed_email_domains():
    """
    Get allowed college email domains from config or environment.
    Defaults to a single example domain if not configured.
    """
    domains = []
    raw = getattr(Config, "COLLEGE_EMAIL_DOMAINS", None) or getattr(
        Config, "COLLEGE_EMAIL_DOMAIN", None
    )
    if raw:
        if isinstance(raw, (list, tuple, set)):
            domains = [d.lower().strip() for d in raw if d]
        else:
            domains = [d.lower().strip() for d in str(raw).split(",") if d.strip()]
    return domains


def _is_valid_email(email: str) -> bool:
    if not email or not EMAIL_REGEX.match(email):
        return False

    domains = _get_allowed_email_domains()
    domain = email.split("@")[-1].lower()

    # Allow any *.edu (e.g., .edu, .edu.in) OR explicitly-configured domains
    if domain.endswith(".edu") or domain.endswith(".edu.in"):
        return True
    if domains:
        return domain in domains
    # If nothing is configured, fall back to syntactic validation only
    return True


def _is_valid_username(username: str) -> bool:
    if not username:
        return False
    if len(username) < 3 or len(username) > 50:
        return False
    # Allow alphanumeric and _ . -
    return re.match(r"^[A-Za-z0-9_.-]+$", username) is not None


def _is_valid_password(password: str) -> bool:
    if not password or len(password) < Config.PASSWORD_MIN_LENGTH:
        return False
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    if Config.PASSWORD_REQUIRE_NUMBERS and not has_digit:
        return False
    if Config.PASSWORD_REQUIRE_SPECIAL_CHARS and not has_special:
        return False
    return True


def _hash_aadhaar(aadhaar: str) -> str:
    """
    One-way hash for Aadhaar numbers using SHA-256 from HashingUtils.
    Stored separately from authentication hashes.
    """
    if not aadhaar:
        return None
    from utils.hashing import HashingUtils

    hasher = HashingUtils()
    # Normalize to digits only before hashing
    digits = re.sub(r"\D", "", aadhaar)
    return hasher.generate_sha256(digits)


# Simple in-memory rate limiter for login attempts (per IP)
_login_attempts = {}
LOGIN_MAX_ATTEMPTS_PER_5_MIN = 10
LOGIN_WINDOW_SECONDS = 300

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
        if "username" not in session or "user_role" not in session:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Authentication required",
                        "error_code": "AUTH_REQUIRED",
                    }
                ),
                401,
            )

        # Check session timeout
        if "login_time" in session:
            login_time = datetime.fromisoformat(session["login_time"])
            if datetime.now() - login_time > SESSION_TIMEOUT:
                session.clear()
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "Session expired",
                            "error_code": "SESSION_EXPIRED",
                        }
                    ),
                    401,
                )

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

@auth_bp.route("/register", methods=["POST"])
def register():
    """
    Register a new user
    
    Student self-registration + backward-compatible admin provisioning.

    New student flow (preferred):
    {
        "username": "student_username",
        "email": "student@college.edu",
        "password": "PlainTextPassword",
        "aadhaar": "optional 12-digit Aadhaar"
    }

    Backward-compatible admin flow:
    {
        "username": "string",
        "email": "string",
        "password": "string",
        "role": "admin|student|verifier",
        "student_id": "string" (optional, required for students)
    }
    """
    try:
        data = request.get_json() or {}

        username = (data.get("username") or "").strip()
        email = (data.get("email") or "").strip()
        password = data.get("password") or ""
        aadhaar_raw = (data.get("aadhaar") or "").strip()

        # If role is not provided, default to student self-registration
        role = (data.get("role") or "student").lower()
        student_id = (
            (data.get("student_id") or "").strip()
            if data.get("student_id")
            else None
        )

        # Basic required fields for all flows
        missing = []
        if not username:
            missing.append("username")
        if not email:
            missing.append("email")
        if not password:
            missing.append("password")
        if missing:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": f"Missing required fields: {', '.join(missing)}",
                        "error_code": "MISSING_FIELDS",
                    }
                ),
                400,
            )

        # Validate username
        if not _is_valid_username(username):
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Username must be 3-50 characters and contain only letters, numbers, ., -, _",
                        "error_code": "INVALID_USERNAME",
                    }
                ),
                400,
            )

        # Validate email and domain
        if not _is_valid_email(email):
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Email must be a valid college email address",
                        "error_code": "INVALID_EMAIL",
                    }
                ),
                400,
            )

        # Validate password strength
        if not _is_valid_password(password):
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Password does not meet complexity requirements",
                        "error_code": "WEAK_PASSWORD",
                    }
                ),
                400,
            )

        # Validate role for admin provisioning flow
        if role not in ["admin", "student", "verifier"]:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Invalid role. Must be admin, student, or verifier",
                        "error_code": "INVALID_ROLE",
                    }
                ),
                400,
            )

        # Validate student_id for student role (admin flow)
        if role == "student" and data.get("role") and not student_id:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Student ID is required for student role",
                        "error_code": "STUDENT_ID_REQUIRED",
                    }
                ),
                400,
            )

        # Optional Aadhaar validation (digits only).
        # If value looks invalid, we safely ignore it instead of blocking registration.
        aadhaar_hash = None
        if aadhaar_raw:
            digits_only = re.sub(r"\D", "", aadhaar_raw)
            if digits_only:
                aadhaar_hash = _hash_aadhaar(digits_only)

        # Enforce username and email uniqueness
        db_manager = DatabaseManager()
        if db_manager.get_user_by_username(username):
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Username already exists",
                        "error_code": "USERNAME_EXISTS",
                    }
                ),
                409,
            )

        if db_manager.get_user_by_email(email):
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Email already registered",
                        "error_code": "EMAIL_EXISTS",
                    }
                ),
                409,
            )

        # Create new user (student by default)
        user = User(
            username=username,
            email=email,
            role=role,
            student_id=student_id,
        )

        if user.save(password=password):
            # Persist Aadhaar and Google flags directly via DB if column exists
            if aadhaar_hash or True:
                # Update aadhaar_hash / google_auth_enabled if those columns exist
                try:
                    with db_manager._cursor() as cursor:
                        updates = []
                        params = []
                        if db_manager._table_has_column("users", "aadhaar_hash"):
                            updates.append("aadhaar_hash = %s")
                            params.append(aadhaar_hash)
                        # New students default to google_auth_enabled = 1 if they registered
                        if db_manager._table_has_column(
                            "users", "google_auth_enabled"
                        ):
                            updates.append("google_auth_enabled = %s")
                            params.append(1)
                        if updates:
                            params.append(user.user_id)
                            cursor.execute(
                                f"UPDATE users SET {', '.join(updates)} WHERE id = %s",
                                tuple(params),
                            )
                except Exception as e:
                    logger.error(
                        "Post-registration user update failed",
                        extra={"error": str(e)},
                    )

            return (
                jsonify(
                    {
                        "success": True,
                        "message": "User registered successfully",
                        "user": user.to_dict(),
                        "timestamp": datetime.now().isoformat(),
                    }
                ),
                201,
            )
        else:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Failed to create user",
                        "error_code": "USER_CREATION_FAILED",
                    }
                ),
                500,
            )
            
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

@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Authenticate user and create session
    
    Expected JSON:
    {
        "identifier": "username-or-email",   # preferred
        "password": "string"
    }

    Backward-compatible:
    {
        "username": "string",
        "password": "string"
    }
    """
    try:
        data = request.get_json() or {}

        raw_identifier = data.get("identifier") or data.get("username") or ""
        password = data.get("password") or ""

        # Validate required fields
        if not raw_identifier.strip() or not password:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Username/email and password are required",
                        "error_code": "MISSING_CREDENTIALS",
                    }
                ),
                400,
            )

        identifier = raw_identifier.strip()

        # Rate limiting per IP
        ip = request.remote_addr or "unknown"
        now = datetime.now()
        attempts = _login_attempts.get(ip, [])
        # Drop attempts outside the window
        attempts = [t for t in attempts if (now - t).total_seconds() < LOGIN_WINDOW_SECONDS]
        if len(attempts) >= LOGIN_MAX_ATTEMPTS_PER_5_MIN:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Too many login attempts. Please try again later.",
                        "error_code": "RATE_LIMITED",
                    }
                ),
                429,
            )

        attempts.append(now)
        _login_attempts[ip] = attempts

        # Authenticate user
        user = User.authenticate(identifier, password)
        
        if user:
            # Regenerate session (best-effort) and create server-side session
            session.clear()
            session["username"] = user.username
            session["user_role"] = user.role
            session["user_id"] = user.user_id
            session["student_id"] = user.student_id
            session["login_time"] = datetime.now().isoformat()
            
            # Log successful login
            db_manager = DatabaseManager()
            db_manager.log_access_attempt(
                student_id=user.student_id or "N/A",
                accessor_username=user.username,
                record_id=None,
                action="LOGIN",
                access_granted=True,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string,
            )

            return (
                jsonify(
                    {
                        "success": True,
                        "message": "Login successful",
                        "user": user.to_dict(),
                        "session_expires_at": (
                            datetime.now() + SESSION_TIMEOUT
                        ).isoformat(),
                        "timestamp": datetime.now().isoformat(),
                    }
                ),
                200,
            )
        else:
            # Log failed login attempt
            db_manager = DatabaseManager()
            db_manager.log_access_attempt(
                student_id="UNKNOWN",
                accessor_username=identifier,
                record_id=None,
                action="LOGIN_FAILED",
                access_granted=False,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string,
            )

            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Invalid username/email or password",
                        "error_code": "INVALID_CREDENTIALS",
                    }
                ),
                401,
            )
            
    except Exception as e:
        logger.error("Login error", extra={"error": str(e), "traceback": traceback.format_exc()})
        return jsonify({
            'success': False,
            'message': 'Internal server error during login',
            'error_code': 'LOGIN_ERROR'
        }), 500

@auth_bp.route('/logout', methods=['POST', 'GET'])
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
        
        # For browser convenience, support both API-style JSON and
        # redirect-based logout. If the client expects HTML (GET from
        # address bar or link), redirect to login page instead of JSON.
        from flask import redirect, url_for

        if request.method == 'GET' and 'application/json' not in request.headers.get('Accept', ''):
            return redirect(url_for('login_page'))

        return jsonify(
            {
                'success': True,
                'message': 'Logout successful',
                'timestamp': datetime.now().isoformat()
            }
        ), 200
        
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


@auth_bp.route("/google", methods=["GET"])
def google_login():
    """
    Start Google OAuth login flow.
    """
    from flask import redirect, url_for

    client = oauth.create_client("google")
    if not client or not client.client_id or not client.client_secret:
        return jsonify({
            "success": False,
            "message": "Google authentication is not configured on this server",
            "error_code": "GOOGLE_AUTH_DISABLED"
        }), 404

    redirect_uri = url_for("auth.google_callback", _external=True)
    return client.authorize_redirect(redirect_uri)


@auth_bp.route("/google/callback", methods=["GET"])
def google_callback():
    """
    Handle Google OAuth callback:
    - Exchange code for tokens
    - Fetch user info
    - Enforce college email constraint
    - Create or login student user
    """
    from flask import redirect, url_for

    client = oauth.create_client("google")
    if not client:
        return jsonify({
            "success": False,
            "message": "Google authentication is not configured",
            "error_code": "GOOGLE_AUTH_DISABLED"
        }), 404

    try:
        token = client.authorize_access_token()
        # Prefer standard OpenID Connect userinfo endpoint
        resp = client.get("userinfo")
        userinfo = resp.json()
    except Exception as e:
        logger.error("Google OAuth token exchange failed", extra={"error": str(e)})
        return jsonify({
            "success": False,
            "message": "Google authentication failed",
            "error_code": "GOOGLE_AUTH_ERROR"
        }), 400

    email = userinfo.get("email")
    google_sub = userinfo.get("sub")

    if not email or not google_sub:
        return jsonify({
            "success": False,
            "message": "Unable to retrieve Google account information",
            "error_code": "GOOGLE_NO_EMAIL"
        }), 400

    # Enforce college email policy (must be .edu/.edu.in or configured domain)
    if not _is_valid_email(email):
        return jsonify({
            "success": False,
            "message": "Google account is not a valid college email",
            "error_code": "GOOGLE_EMAIL_NOT_ALLOWED"
        }), 403

    db_manager = DatabaseManager()
    existing_row = db_manager.get_user_by_email(email)

    if existing_row:
        # Existing user: only allow if role is student (admins/verifiers use password login)
        if existing_row.get("role") != "student":
            return jsonify({
                "success": False,
                "message": "Google login is only allowed for student accounts",
                "error_code": "GOOGLE_ROLE_NOT_ALLOWED"
            }), 403

        user = User()
        user.user_id = existing_row["id"]
        user.username = existing_row["username"]
        user.email = existing_row["email"]
        user.role = existing_row["role"]
        user.student_id = existing_row.get("student_id")
    else:
        # Auto-provision a new student user
        base_username = email.split("@")[0]
        username = base_username
        suffix = 1
        while db_manager.get_user_by_username(username):
            username = f"{base_username}{suffix}"
            suffix += 1

        try:
            user_id = db_manager.create_user(
                username=username,
                email=email,
                password_hash=None,
                role="student",
                student_id=None,
                aadhaar_hash=None,
                google_auth_enabled=True,
                google_id=google_sub,
            )
        except Exception as e:
            logger.error("Failed to create Google user", extra={"error": str(e)})
            return jsonify({
                "success": False,
                "message": "Unable to create user for Google account",
                "error_code": "GOOGLE_USER_CREATE_FAILED"
            }), 500

        user = User(
            username=username,
            email=email,
            role="student",
            student_id=None,
            user_id=user_id,
        )

    # Establish session (same semantics as password login)
    session.clear()
    session["username"] = user.username
    session["user_role"] = user.role
    session["user_id"] = user.user_id
    session["student_id"] = user.student_id
    session["login_time"] = datetime.now().isoformat()

    # Log successful login
    db_manager.log_access_attempt(
        student_id=user.student_id or "N/A",
        accessor_username=user.username,
        record_id=None,
        action="LOGIN_GOOGLE",
        access_granted=True,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
    )

    # Redirect students to their portal
    return redirect(url_for("student_portal"))

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