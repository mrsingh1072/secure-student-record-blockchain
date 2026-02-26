"""
Routes module for secure student record management system
"""

from .auth_routes import auth_bp
from .record_routes import record_bp

__all__ = ['auth_bp', 'record_bp']