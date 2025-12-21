"""
Manual JWT implementation using only Python standard library.
Implements Base64Url encoding/decoding, JSON serialization, and HMAC-SHA256 signing.
"""
import json
import base64
import hmac
import hashlib
import time
from typing import Dict, Optional


def base64url_encode(data: bytes) -> str:
    """Encode bytes to Base64Url string (URL-safe, no padding)."""
    encoded = base64.urlsafe_b64encode(data).decode('utf-8')
    return encoded.rstrip('=')


def base64url_decode(data: str) -> bytes:
    """Decode Base64Url string to bytes."""
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def create_jwt(payload: Dict, secret: str) -> str:
    """
    Create a JWT token.
    
    Args:
        payload: Dictionary containing JWT claims
        secret: Secret key for HMAC-SHA256 signing
    
    Returns:
        JWT token string (header.payload.signature)
    """
    # Header
    header = {
        "alg": "HS256",
        "typ": "JWT"
    }
    
    # Encode header and payload
    header_encoded = base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_encoded = base64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    
    # Create signature
    message = f"{header_encoded}.{payload_encoded}".encode('utf-8')
    signature = hmac.new(
        secret.encode('utf-8'),
        message,
        hashlib.sha256
    ).digest()
    signature_encoded = base64url_encode(signature)
    
    # Combine into JWT
    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"


def verify_jwt(token: str, secret: str) -> Optional[Dict]:
    """
    Verify and decode a JWT token.
    
    Args:
        token: JWT token string
        secret: Secret key for HMAC-SHA256 verification
    
    Returns:
        Decoded payload dictionary if valid, None otherwise
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        header_encoded, payload_encoded, signature_encoded = parts
        
        # Verify signature
        message = f"{header_encoded}.{payload_encoded}".encode('utf-8')
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            message,
            hashlib.sha256
        ).digest()
        expected_signature_encoded = base64url_encode(expected_signature)
        
        if signature_encoded != expected_signature_encoded:
            return None
        
        # Decode payload
        payload_json = base64url_decode(payload_encoded).decode('utf-8')
        payload = json.loads(payload_json)
        
        # Check expiration if present
        if 'exp' in payload:
            if time.time() > payload['exp']:
                return None
        
        return payload
    except Exception:
        return None


def decode_jwt_payload(token: str) -> Optional[Dict]:
    """
    Decode JWT payload without verification (for inspection only).
    
    Args:
        token: JWT token string
    
    Returns:
        Decoded payload dictionary or None if invalid
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        payload_encoded = parts[1]
        payload_json = base64url_decode(payload_encoded).decode('utf-8')
        return json.loads(payload_json)
    except Exception:
        return None

