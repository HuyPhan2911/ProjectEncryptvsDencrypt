"""
OAuth2 Resource Server implementation.
Protects API endpoints and validates JWT access tokens.
"""
from flask import Blueprint, request, jsonify
from functools import wraps
from jwt_utils import verify_jwt
from config import JWT_SECRET

resource_bp = Blueprint('resource', __name__, url_prefix='/api')


def require_auth(f):
    """
    Decorator to protect endpoints with JWT authentication.
    Extracts token from Authorization header and verifies it.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Extract token from Authorization header
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return jsonify({"error": "missing_authorization_header"}), 401
        
        # Check Bearer token format
        parts = auth_header.split(' ')
        if len(parts) != 2 or parts[0] != 'Bearer':
            return jsonify({"error": "invalid_authorization_format"}), 401
        
        token = parts[1]
        
        # Verify JWT token
        payload = verify_jwt(token, JWT_SECRET)
        if not payload:
            return jsonify({"error": "invalid_or_expired_token"}), 401
        
        # Attach user info to request for use in route handlers
        request.user_id = payload.get('sub')
        request.client_id = payload.get('client_id')
        request.scope = payload.get('scope', '')
        
        return f(*args, **kwargs)
    
    return decorated_function


@resource_bp.route('/user/profile', methods=['GET'])
@require_auth
def get_user_profile():
    """
    Protected endpoint: Returns user profile information.
    Requires valid JWT access token.
    """
    # Import from user_db module
    from user_db import get_user_by_id
    
    user = get_user_by_id(request.user_id)
    if not user:
        return jsonify({"error": "user_not_found"}), 404
    
    # Return user data (excluding password)
    return jsonify({
        "id": user['id'],
        "username": user['username'],
        "email": user.get('email', ''),
        "scope": request.scope,
        "client_id": request.client_id
    })


@resource_bp.route('/data', methods=['GET'])
@require_auth
def get_protected_data():
    """
    Protected endpoint: Returns some protected data.
    Requires valid JWT access token.
    """
    return jsonify({
        "message": "This is protected data!",
        "user_id": request.user_id,
        "client_id": request.client_id,
        "scope": request.scope,
        "data": [
            {"id": 1, "name": "Item 1", "value": 100},
            {"id": 2, "name": "Item 2", "value": 200},
            {"id": 3, "name": "Item 3", "value": 300}
        ]
    })


@resource_bp.route('/health', methods=['GET'])
def health_check():
    """
    Public endpoint: Health check (no authentication required).
    """
    return jsonify({"status": "ok", "service": "resource_server"})

