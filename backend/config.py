"""
Centralized configuration for OAuth2 demo.
All secrets and configuration values are defined here.
"""
# Flask session secret key
FLASK_SECRET_KEY = "oauth2-demo-secret-key-for-sessions-2024"

# JWT signing secret (must be the same across auth server and resource server)
JWT_SECRET = "oauth2-demo-jwt-secret-key-256-bits-minimum-length"

# OAuth2 Client Configuration
CLIENT_ID = "my_client"
CLIENT_SECRET = "my_client_secret"

# Server URLs
AUTH_SERVER_URL = "http://localhost:5001"
REDIRECT_URI = "http://localhost:5173/callback"

# Token expiration times (in seconds)
ACCESS_TOKEN_EXPIRY = 10  # 1 minute
REFRESH_TOKEN_EXPIRY = 86400 * 7  # 7 days
AUTHORIZATION_CODE_EXPIRY = 600  # 10 minutes

