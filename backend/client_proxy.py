"""
OAuth2 Client Proxy endpoints.
These endpoints help the React frontend exchange authorization codes
and refresh tokens without exposing client_secret to the frontend.
"""
from flask import Blueprint, request, jsonify
import requests
from config import CLIENT_ID, CLIENT_SECRET, AUTH_SERVER_URL, REDIRECT_URI

client_bp = Blueprint('client', __name__, url_prefix='/api')


@client_bp.route('/exchange_code', methods=['POST'])
def exchange_code():
    """
    Exchanges authorization code for access token and refresh token.
    This is a proxy endpoint - the frontend sends the code here,
    and this backend makes the server-to-server request to auth server.
    """
    data = request.get_json()
    code = data.get('code')
    state = data.get('state')
    
    if not code:
        return jsonify({"error": "missing_code"}), 400
    
    # Make server-to-server request to authorization server
    token_url = f"{AUTH_SERVER_URL}/auth/token"
    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI
    }
    
    try:
        response = requests.post(token_url, data=token_data)
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "token_exchange_failed", "details": str(e)}), 500


@client_bp.route('/refresh_token', methods=['POST'])
def refresh_token():
    """
    Exchanges refresh token for new access token.
    This is a proxy endpoint - the frontend sends the refresh token here,
    and this backend makes the server-to-server request to auth server.
    """
    data = request.get_json()
    refresh_token = data.get('refresh_token')
    
    if not refresh_token:
        return jsonify({"error": "missing_refresh_token"}), 400
    
    # Make server-to-server request to authorization server
    token_url = f"{AUTH_SERVER_URL}/auth/token"
    token_data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    
    try:
        response = requests.post(token_url, data=token_data)
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "token_refresh_failed", "details": str(e)}), 500

