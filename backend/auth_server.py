"""
OAuth2 Authorization Server implementation.
Handles authorization requests, code generation, and token issuance.
"""
from flask import Blueprint, request, redirect, url_for, render_template_string, session
import secrets
import time
from typing import Dict, Optional
from jwt_utils import create_jwt, verify_jwt
from user_db import verify_user_credentials
from config import (
    JWT_SECRET, 
    CLIENT_SECRET,
    ACCESS_TOKEN_EXPIRY,
    REFRESH_TOKEN_EXPIRY,
    AUTHORIZATION_CODE_EXPIRY
)

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# In-memory storage
authorization_codes: Dict[str, Dict] = {}  # code -> {client_id, redirect_uri, user_id, scope, expires_at}
access_tokens: Dict[str, Dict] = {}  # token -> {user_id, client_id, scope, expires_at}
refresh_tokens: Dict[str, Dict] = {}  # refresh_token -> {user_id, client_id, scope}


@auth_bp.route('/authorize', methods=['GET', 'POST'])
def authorize():
    """
    OAuth2 Authorization Endpoint.
    GET: Shows login/consent form
    POST: Processes login/consent and redirects with authorization code
    """
    if request.method == 'GET':
        # Extract OAuth2 parameters
        client_id = request.args.get('client_id')
        redirect_uri = request.args.get('redirect_uri')
        response_type = request.args.get('response_type')
        scope = request.args.get('scope', '')
        state = request.args.get('state')
        
        # Validate parameters
        if not client_id or not redirect_uri or response_type != 'code':
            return "Invalid request parameters", 400
        
        # Store in session for POST request
        session['oauth_client_id'] = client_id
        session['oauth_redirect_uri'] = redirect_uri
        session['oauth_scope'] = scope
        session['oauth_state'] = state
        
        # Render login form
        login_form = """
        <!DOCTYPE html>
        <html>
        <head><title>OAuth2 Login</title></head>
        <body>
            <h2>Login to OAuth2 Demo</h2>
            <form method="POST">
                <label>Username: <input type="text" name="username" required></label><br><br>
                <label>Password: <input type="password" name="password" required></label><br><br>
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
        """
        return render_template_string(login_form)
    
    elif request.method == 'POST':
        # Get OAuth2 parameters from session
        client_id = session.get('oauth_client_id')
        redirect_uri = session.get('oauth_redirect_uri')
        scope = session.get('oauth_scope', '')
        state = session.get('oauth_state')
        
        if not client_id or not redirect_uri:
            return "Session expired. Please try again.", 400
        
        # Authenticate user
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = verify_user_credentials(username, password)
        if not user:
            return "Invalid credentials", 401
        
        # Generate authorization code
        code = secrets.token_urlsafe(32)
        authorization_codes[code] = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'user_id': user['id'],
            'scope': scope,
            'expires_at': time.time() + AUTHORIZATION_CODE_EXPIRY
        }
        
        # Build redirect URI with authorization code
        redirect_url = f"{redirect_uri}?code={code}"
        if state:
            redirect_url += f"&state={state}"
        
        return redirect(redirect_url)


@auth_bp.route('/token', methods=['POST'])
def token():
    """
    OAuth2 Token Endpoint.
    Exchanges authorization code for access token and refresh token.
    """
    grant_type = request.form.get('grant_type')
    
    if grant_type == 'authorization_code':
        # Exchange authorization code for tokens
        code = request.form.get('code')
        client_id = request.form.get('client_id')
        redirect_uri = request.form.get('redirect_uri')
        client_secret = request.form.get('client_secret')
        
        if not code or not client_id:
            return {"error": "invalid_request"}, 400
        
        # Verify client_secret (in production, check against database)
        if client_secret != CLIENT_SECRET:
            return {"error": "invalid_client"}, 400
        
        # Verify authorization code
        code_data = authorization_codes.get(code)
        if not code_data:
            return {"error": "invalid_grant"}, 400
        
        # Check expiration
        if time.time() > code_data['expires_at']:
            del authorization_codes[code]
            return {"error": "invalid_grant"}, 400
        
        # Verify client_id and redirect_uri
        if code_data['client_id'] != client_id:
            return {"error": "invalid_client"}, 400
        
        if code_data['redirect_uri'] != redirect_uri:
            return {"error": "invalid_grant"}, 400
        
        # Generate access token (JWT)
        access_token_payload = {
            'sub': code_data['user_id'],
            'client_id': client_id,
            'scope': code_data['scope'],
            'exp': int(time.time()) + ACCESS_TOKEN_EXPIRY,
            'iat': int(time.time())
        }
        access_token = create_jwt(access_token_payload, JWT_SECRET)
        
        # Generate refresh token
        refresh_token = secrets.token_urlsafe(32)
        refresh_tokens[refresh_token] = {
            'user_id': code_data['user_id'],
            'client_id': client_id,
            'scope': code_data['scope']
        }
        
        # Store access token (for revocation purposes)
        access_tokens[access_token] = {
            'user_id': code_data['user_id'],
            'client_id': client_id,
            'scope': code_data['scope'],
            'expires_at': time.time() + ACCESS_TOKEN_EXPIRY
        }
        
        # Delete used authorization code
        del authorization_codes[code]
        
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_EXPIRY,
            "refresh_token": refresh_token,
            "scope": code_data['scope']
        }
    
    elif grant_type == 'refresh_token':
        # Exchange refresh token for new access token
        refresh_token = request.form.get('refresh_token')
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
        
        if not refresh_token or not client_id:
            return {"error": "invalid_request"}, 400
        
        # Verify client_secret
        if client_secret != CLIENT_SECRET:
            return {"error": "invalid_client"}, 400
        
        # Verify refresh token
        refresh_data = refresh_tokens.get(refresh_token)
        if not refresh_data:
            return {"error": "invalid_grant"}, 400
        
        if refresh_data['client_id'] != client_id:
            return {"error": "invalid_client"}, 400
        
        # Generate new access token
        access_token_payload = {
            'sub': refresh_data['user_id'],
            'client_id': client_id,
            'scope': refresh_data['scope'],
            'exp': int(time.time()) + ACCESS_TOKEN_EXPIRY,
            'iat': int(time.time())
        }
        access_token = create_jwt(access_token_payload, JWT_SECRET)
        
        # Store new access token
        access_tokens[access_token] = {
            'user_id': refresh_data['user_id'],
            'client_id': client_id,
            'scope': refresh_data['scope'],
            'expires_at': time.time() + ACCESS_TOKEN_EXPIRY
        }
        
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_EXPIRY,
            "scope": refresh_data['scope']
        }
    
    else:
        return {"error": "unsupported_grant_type"}, 400
