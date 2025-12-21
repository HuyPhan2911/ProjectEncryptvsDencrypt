"""
Main Flask application.
Combines Authorization Server, Resource Server, and Client Proxy.
"""
from flask import Flask
from flask_cors import CORS

from config import FLASK_SECRET_KEY

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# Enable CORS for React frontend
CORS(app, origins=["http://localhost:5173", "http://localhost:3000"])

# Import user database functions
from user_db import verify_user_credentials, get_user_by_id, users


# Import and register blueprints after app is created
from auth_server import auth_bp
from resource_server import resource_bp
from client_proxy import client_bp

app.register_blueprint(auth_bp)
app.register_blueprint(resource_bp)
app.register_blueprint(client_bp)


@app.route('/')
def index():
    """Root endpoint - API information."""
    return {
        "message": "OAuth2 Demo API",
        "endpoints": {
            "authorization": "/auth/authorize",
            "token": "/auth/token",
            "protected_api": "/api/user/profile",
            "client_proxy": "/api/exchange_code"
        }
    }


if __name__ == '__main__':
    from user_db import users
    print("=" * 60)
    print("OAuth2 Demo Server Starting...")
    print("=" * 60)
    print("\nAvailable Users:")
    for user in users:
        print(f"  - {user['username']} / {user['password']}")
    print("\nAuthorization Server: http://localhost:5001/auth/authorize")
    print("Resource Server: http://localhost:5001/api/*")
    print("=" * 60)
    app.run(debug=True, port=5001)

