# OAuth2 Authorization Code Flow - Full Stack Demo

A complete OAuth2 implementation demonstrating the Authorization Code flow using **only standard libraries** - no OAuth/JWT libraries! Built with Flask (Python) backend and React (Vite) frontend.

## 🎯 Project Goals

- **Educational**: Understand OAuth2 by implementing it from scratch
- **No Dependencies**: Manual JWT implementation using only Python/JS standard libraries
- **Complete Flow**: Authorization Server, Resource Server, and Client all implemented
- **Learning First**: Code is well-commented to explain each step

## 📚 Learning Resources

**Start here**: Read [`OAUTH2_GUIDE.md`](./OAUTH2_GUIDE.md) for a complete explanation of:
- What OAuth2 is and why it exists
- Step-by-step flow walkthrough
- How JWT tokens work
- Security considerations
- Backend and frontend architecture

## 🏗️ Project Structure

```
Oauth2/
├── backend/
│   ├── app.py              # Main Flask app (combines all components)
│   ├── jwt_utils.py        # Manual JWT implementation (Base64Url + HMAC-SHA256)
│   ├── auth_server.py      # Authorization Server (issues codes & tokens)
│   ├── resource_server.py  # Resource Server (protects API endpoints)
│   ├── client_proxy.py     # Client proxy (exchanges codes, refreshes tokens)
│   └── requirements.txt    # Python dependencies
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx         # Main React component (OAuth2 flow)
│   │   ├── main.jsx        # React entry point
│   │   └── index.css       # Styles
│   ├── index.html
│   ├── package.json        # Node dependencies
│   └── vite.config.js      # Vite configuration
│
├── README.md               # This file
└── OAUTH2_GUIDE.md         # Detailed OAuth2 explanation
```

## 🚀 Quick Start

### Prerequisites

- Python 3.8+ 
- Node.js 18+ and pnpm
- Two terminal windows

### Step 1: Setup Backend

```bash
cd backend

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the Flask server
python app.py
```

The backend will start on `http://localhost:5001`

**Available Users:**
- Username: `alice` / Password: `password123`
- Username: `bob` / Password: `password123`

### Step 2: Setup Frontend

In a **new terminal window**:

```bash
cd frontend

# Install dependencies
pnpm install

# Start the development server
pnpm dev
```

The frontend will start on `http://localhost:5173`

### Step 3: Test the Flow

1. Open `http://localhost:5173` in your browser
2. Click **"Login with OAuth2"**
3. You'll be redirected to the authorization server
4. Login with `alice` / `password123`
5. You'll be redirected back with an authorization code
6. The frontend automatically exchanges the code for tokens
7. Use the buttons to fetch protected resources!

## 🔄 OAuth2 Flow Overview

```
1. User clicks "Login" 
   → Frontend redirects to /auth/authorize

2. User enters credentials
   → Authorization Server validates and generates code

3. Browser redirected back to frontend
   → URL contains: ?code=abc123&state=xyz

4. Frontend sends code to backend proxy
   → POST /api/exchange_code

5. Backend exchanges code for tokens
   → POST /auth/token (server-to-server)

6. Frontend receives access_token & refresh_token
   → Stores tokens, makes API calls

7. API calls include Bearer token
   → GET /api/user/profile (Authorization: Bearer <token>)

8. Resource Server validates JWT
   → Returns protected data
```

## 🧩 Components Explained

### 1. Authorization Server (`auth_server.py`)

**Endpoints:**
- `GET /auth/authorize` - Shows login form, generates authorization code
- `POST /auth/authorize` - Processes login, redirects with code
- `POST /auth/token` - Exchanges code for tokens, handles refresh

**Key Features:**
- Generates short-lived authorization codes (10 min)
- Issues JWT access tokens (1 hour) and refresh tokens (7 days)
- Validates client_id, redirect_uri, and code expiration

### 2. Resource Server (`resource_server.py`)

**Endpoints:**
- `GET /api/user/profile` - Protected: Returns user profile
- `GET /api/data` - Protected: Returns protected data
- `GET /api/health` - Public: Health check

**Key Features:**
- `@require_auth` decorator validates JWT tokens
- Extracts user info from token payload
- Returns 401 if token is invalid/expired

### 3. Client Proxy (`client_proxy.py`)

**Endpoints:**
- `POST /api/exchange_code` - Exchanges authorization code for tokens
- `POST /api/refresh_token` - Exchanges refresh token for new access token

**Why a proxy?**
- Keeps `client_secret` on backend (never exposed to frontend)
- Handles CORS and server-to-server communication
- Frontend never directly calls authorization server

### 4. JWT Utilities (`jwt_utils.py`)

**Manual Implementation:**
- `base64url_encode/decode` - URL-safe Base64 encoding
- `create_jwt` - Creates JWT with HMAC-SHA256 signature
- `verify_jwt` - Verifies signature and expiration

**No libraries used!** Just Python standard library:
- `base64`, `json`, `hmac`, `hashlib`, `time`

### 5. React Frontend (`src/App.jsx`)

**Features:**
- Initiates OAuth2 flow with state parameter (CSRF protection)
- Handles callback with authorization code
- Exchanges code for tokens via backend proxy
- Stores tokens and makes authenticated API calls
- Automatic token refresh on 401 responses
- Clean UI showing tokens and protected data

## 🔐 Security Features

✅ **Authorization Code**: Short-lived (10 min), one-time use  
✅ **Access Token**: JWT with expiration (1 hour), HMAC-SHA256 signed  
✅ **Refresh Token**: Long-lived (7 days), stored securely  
✅ **State Parameter**: CSRF protection  
✅ **Client Secret**: Never exposed to frontend  
✅ **Token Validation**: Signature verification + expiration checks  

## 🧪 Testing the Flow

### Test Authorization Code Flow

1. **Start both servers** (backend on :5001, frontend on :5173)
2. **Open browser console** to see network requests
3. **Click "Login with OAuth2"**
4. **Observe**:
   - Redirect to `/auth/authorize?client_id=...&redirect_uri=...`
   - Login form appears
   - After login, redirect to `/callback?code=...&state=...`
   - POST to `/api/exchange_code`
   - Tokens received and stored

### Test Protected Endpoints

1. **After login**, click "Fetch User Profile"
2. **Observe**:
   - GET request to `/api/user/profile`
   - `Authorization: Bearer <jwt_token>` header
   - User data returned

### Test Token Refresh

1. **Wait 1 hour** (or modify `ACCESS_TOKEN_EXPIRY` in `auth_server.py`)
2. **Make API call** - should get 401
3. **Frontend automatically** calls `/api/refresh_token`
4. **New access token** issued
5. **Original request retried** successfully

### Inspect JWT Token

The access token is a JWT. You can decode it (without verification) at [jwt.io](https://jwt.io) to see:
- Header: `{"alg": "HS256", "typ": "JWT"}`
- Payload: `{"sub": "user1", "client_id": "my_client", "exp": 1234567890, ...}`
- Signature: HMAC-SHA256 signature

## 📝 Code Highlights

### Manual JWT Creation (Python)

```python
# jwt_utils.py
def create_jwt(payload: Dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_encoded = base64url_encode(json.dumps(header).encode())
    payload_encoded = base64url_encode(json.dumps(payload).encode())
    
    message = f"{header_encoded}.{payload_encoded}".encode()
    signature = hmac.new(secret.encode(), message, hashlib.sha256).digest()
    signature_encoded = base64url_encode(signature)
    
    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"
```

### Protected Endpoint (Python)

```python
# resource_server.py
@resource_bp.route('/api/user/profile', methods=['GET'])
@require_auth
def get_user_profile():
    user = get_user_by_id(request.user_id)  # From JWT payload
    return jsonify({"id": user['id'], "username": user['username']})
```

### OAuth2 Flow Initiation (React)

```javascript
// App.jsx
const initiateLogin = () => {
  const state = generateState()  // CSRF protection
  const authUrl = `${AUTH_SERVER_URL}/auth/authorize?` +
    `client_id=${CLIENT_ID}&` +
    `redirect_uri=${REDIRECT_URI}&` +
    `response_type=code&` +
    `state=${state}`
  window.location.href = authUrl  // Redirect browser
}
```

## 🐛 Troubleshooting

### Backend won't start
- Check Python version: `python3 --version` (need 3.8+)
- Activate virtual environment: `source venv/bin/activate`
- Install dependencies: `pip install -r requirements.txt`

### Frontend won't start
- Check Node version: `node --version` (need 18+)
- Install dependencies: `pnpm install`
- Check if port 5173 is available

### CORS errors
- Backend CORS is configured for `http://localhost:5173`
- If using different port, update `app.py` CORS origins

### Token exchange fails
- Check backend is running on port 5001
- Check browser console for error messages
- Verify authorization code hasn't expired (10 minutes)

### 401 Unauthorized
- Token may have expired (1 hour lifetime)
- Frontend should auto-refresh, but check refresh token is valid
- Verify JWT secret matches between auth server and resource server

## 🎓 What You'll Learn

By studying this code, you'll understand:

1. **OAuth2 Authorization Code Flow** - Complete flow from start to finish
2. **JWT Structure** - Header, payload, signature components
3. **JWT Signing** - HMAC-SHA256 signature creation and verification
4. **Base64Url Encoding** - URL-safe encoding for tokens
5. **Token Lifecycle** - Access tokens, refresh tokens, expiration
6. **Security Best Practices** - State parameter, client secret protection
7. **Frontend-Backend Communication** - Proxy pattern for OAuth2

## 📖 Further Reading

- [OAuth2 RFC 6749](https://tools.ietf.org/html/rfc6749) - Official OAuth2 specification
- [JWT RFC 7519](https://tools.ietf.org/html/rfc7519) - JSON Web Token specification
- [OAUTH2_GUIDE.md](./OAUTH2_GUIDE.md) - Detailed explanation in this repo

## ⚠️ Important Notes

**This is a learning/demo project!** For production:

- ❌ Don't use in-memory storage (use databases)
- ❌ Don't store passwords in plain text (use bcrypt/argon2)
- ❌ Don't use HTTP (always use HTTPS)
- ❌ Don't store tokens in localStorage (use httpOnly cookies)
- ❌ Don't hardcode secrets (use environment variables)
- ❌ Don't use short secrets (use 256+ bit secrets)

## 📄 License

This is an educational project. Feel free to use and modify for learning purposes.

---

**Happy Learning! 🚀**

For questions or issues, refer to `OAUTH2_GUIDE.md` for detailed explanations.

