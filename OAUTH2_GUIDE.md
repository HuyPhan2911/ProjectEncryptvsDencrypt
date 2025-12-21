# OAuth2 Authorization Code Flow - Complete Guide

## What is OAuth2?

OAuth2 is an authorization framework that allows applications to obtain **limited access** to user accounts on an HTTP service. It enables a third-party application to access user resources without getting the user's password.

**Key Concept**: OAuth2 is about **authorization** (what you can do), not **authentication** (who you are).

## The Four Main Components

1. **Resource Owner (User)**: The person who owns the data/resources
2. **Client Application**: The app that wants to access user resources (our React app)
3. **Authorization Server**: Issues access tokens after authenticating the user (our Flask `/auth` endpoints)
4. **Resource Server**: The API that holds the protected resources (our Flask `/api` endpoints)

## Authorization Code Flow - Step by Step

This is the most secure flow for web applications. Here's how it works:

### Step 1: User Initiates Login
```
User clicks "Login" button in React app
↓
React app redirects browser to:
http://localhost:5000/auth/authorize?
  client_id=my_client&
  redirect_uri=http://localhost:5173/callback&
  response_type=code&
  scope=read&
  state=random_string
```


**Why `state`?** Security! It prevents CSRF attacks. The client generates a random string, sends it, and verifies it comes back unchanged.

### Step 2: Authorization Server Shows Login Form
```
Authorization Server receives the request
↓
Checks if user is logged in (not in our demo)
↓
Shows login form to user
```

**Backend Code** (`auth_server.py`):
- `/auth/authorize` endpoint receives GET request
- Validates `client_id`, `redirect_uri`, `response_type=code`
- Shows HTML login form

### Step 3: User Enters Credentials
```
User enters username/password
↓
POST to /auth/authorize
↓
Authorization Server verifies credentials
```

**Backend Code**:
- Receives POST with username/password
- Verifies against user database
- If valid, generates **authorization code**

### Step 4: Authorization Code Generated
```
Authorization Server creates:
- Random authorization code (e.g., "abc123xyz")
- Stores it in memory with:
  * client_id
  * redirect_uri
  * user_id
  * scope
  * expiration (10 minutes)
↓
Redirects browser back to client:
http://localhost:5173/callback?code=abc123xyz&state=random_string
```

**Important**: The code is **short-lived** (10 minutes) and can only be used **once**.

### Step 5: Client Exchanges Code for Tokens
```
React app receives code in URL
↓
Makes POST request to backend proxy endpoint:
POST /api/exchange_code
Body: { code: "abc123xyz", state: "random_string" }
↓
Backend proxy makes server-to-server request:
POST http://localhost:5000/auth/token
Content-Type: application/x-www-form-urlencoded
Body:
  grant_type=authorization_code&
  code=abc123xyz&
  client_id=my_client&
  redirect_uri=http://localhost:5173/callback
```

**Why a proxy?** 
- The token endpoint requires `client_secret` (should never be in frontend)
- CORS issues (authorization server might not allow browser requests)
- Security: secrets stay on backend

### Step 6: Authorization Server Issues Tokens
```
Authorization Server:
1. Validates authorization code
2. Checks expiration
3. Verifies client_id and redirect_uri match
4. Deletes the code (one-time use)
5. Generates:
   - Access Token (JWT, expires in 1 hour)
   - Refresh Token (random string, stored in memory)
↓
Returns JSON:
{
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "xyz789abc",
  "scope": "read"
}
```

**Backend Code** (`auth_server.py`):
- `/auth/token` endpoint
- Validates code from `authorization_codes` dictionary
- Creates JWT access token using `jwt_utils.create_jwt()`
- Creates refresh token (random string)
- Returns both tokens

### Step 7: Client Stores Tokens
```
React app receives tokens
↓
Stores in memory (or localStorage/sessionStorage)
↓
Uses access_token for API requests
```

**Frontend Code**:
- Stores `access_token` and `refresh_token`
- Adds `Authorization: Bearer <token>` header to API requests

### Step 8: Accessing Protected Resources
```
React app makes API request:
GET http://localhost:5000/api/user/profile
Headers:
  Authorization: Bearer eyJhbGc...
↓
Resource Server:
1. Extracts token from Authorization header
2. Verifies JWT signature
3. Checks expiration
4. Extracts user_id from token payload
5. Returns user data
```

**Backend Code** (`resource_server.py`):
- `/api/*` endpoints
- Middleware extracts `Authorization` header
- Verifies JWT using `jwt_utils.verify_jwt()`
- If valid, allows request; if invalid, returns 401

### Step 9: Token Refresh (When Access Token Expires)
```
Access token expires after 1 hour
↓
React app detects 401 response
↓
Makes refresh request:
POST /api/refresh_token
Body: { refresh_token: "xyz789abc" }
↓
Backend exchanges refresh token for new access token
```

**Backend Code**:
- `/auth/token` with `grant_type=refresh_token`
- Validates refresh token
- Issues new access token (same user, same scope)

## JWT Token Structure

A JWT has three parts separated by dots: `header.payload.signature`

### Example:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### 1. Header (Base64Url encoded)
```json
{
  "alg": "HS256",  // Algorithm: HMAC SHA256
  "typ": "JWT"     // Type: JSON Web Token
}
```

### 2. Payload (Base64Url encoded)
```json
{
  "sub": "user123",           // Subject (user ID)
  "client_id": "my_client",   // Which app requested this
  "scope": "read",            // What permissions
  "exp": 1704067200,          // Expiration timestamp
  "iat": 1704063600           // Issued at timestamp
}
```

### 3. Signature
```
HMAC-SHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret_key
)
```

**Why JWT?**
- **Stateless**: Resource server doesn't need to check database
- **Self-contained**: User info is in the token
- **Tamper-proof**: Signature prevents modification
- **Verifiable**: Anyone with secret can verify it's valid

## Security Considerations

### 1. Authorization Code
- ✅ Short-lived (10 minutes)
- ✅ One-time use (deleted after exchange)
- ✅ Tied to specific `client_id` and `redirect_uri`

### 2. Access Token
- ✅ Short-lived (1 hour)
- ✅ Signed with HMAC-SHA256 (can't be tampered)
- ✅ Contains expiration (`exp` claim)

### 3. Refresh Token
- ✅ Long-lived (7 days)
- ✅ Stored securely (not in frontend if possible)
- ✅ Can be revoked

### 4. State Parameter
- ✅ Prevents CSRF attacks
- ✅ Client generates random string, verifies it matches

### 5. HTTPS in Production
- ⚠️ Always use HTTPS! Tokens in URLs/headers are visible over HTTP

## Backend Architecture

```
Flask App (app.py)
├── Authorization Server (auth_server.py)
│   ├── /auth/authorize  → Login form, generates code
│   └── /auth/token      → Exchanges code for tokens
│
├── Resource Server (resource_server.py)
│   ├── /api/user/profile  → Protected endpoint
│   └── /api/data          → Protected endpoint
│
└── OAuth2 Client Proxy (client_proxy.py)
    ├── /api/exchange_code  → Frontend → Backend → Auth Server
    └── /api/refresh_token  → Frontend → Backend → Auth Server
```

**Why separate blueprints?**
- Clear separation of concerns
- Easy to understand each component's role
- Can be split into separate services later

## Frontend Architecture

```
React App
├── Login Component
│   └── Redirects to /auth/authorize
│
├── Callback Component
│   ├── Extracts code from URL
│   ├── Sends to /api/exchange_code
│   └── Stores tokens
│
├── Protected Component
│   ├── Makes API calls with Bearer token
│   └── Handles 401 (token expired)
│
└── API Service
    ├── Adds Authorization header
    ├── Handles token refresh
    └── Retries failed requests
```

## Data Flow Diagram

```
┌─────────┐         ┌──────────────┐         ┌─────────────┐         ┌──────────────┐
│  User   │────────▶│ React Client │────────▶│ Auth Server │────────▶│User Database │
│ Browser │         │  (Frontend)  │         │  (Backend)  │         │  (In-Memory) │
└─────────┘         └──────────────┘         └─────────────┘         └──────────────┘
     │                     │                          │
     │ 1. Click Login      │                          │
     │◀────────────────────│                          │
     │                     │                          │
     │ 2. Redirect to      │                          │
     │    /auth/authorize  │                          │
     │────────────────────▶│                          │
     │                     │─────────────────────────▶│
     │                     │                          │
     │ 3. Show Login Form  │                          │
     │◀────────────────────│                          │
     │                     │                          │
     │ 4. Enter Credentials│                          │
     │────────────────────▶│                          │
     │                     │─────────────────────────▶│
     │                     │                          │
     │ 5. Redirect with    │                          │
     │    code=abc123      │                          │
     │◀────────────────────│                          │
     │                     │                          │
     │ 6. Exchange Code    │                          │
     │────────────────────▶│                          │
     │                     │─────────────────────────▶│
     │                     │                          │
     │ 7. Receive Tokens   │                          │
     │◀────────────────────│                          │
     │                     │                          │
     │ 8. API Request      │                          │
     │    with Bearer token│                          │
     │────────────────────▶│                          │
     │                     │─────────────────────────▶│
     │                     │                          │
     │ 9. Protected Data   │                          │
     │◀────────────────────│                          │
     │                     │                          │
```

## Key Takeaways

1. **Authorization Code** = Temporary, one-time code (like a ticket)
2. **Access Token** = JWT that proves you're authorized (like a badge)
3. **Refresh Token** = Long-lived token to get new access tokens (like a renewal card)
4. **State Parameter** = CSRF protection (like a receipt number)
5. **Client Secret** = Never in frontend! Always on backend (like a password)

## Why This Flow is Secure

1. ✅ User never shares password with client app
2. ✅ Authorization code is short-lived and one-time use
3. ✅ Access tokens are signed (can't be forged)
4. ✅ Tokens expire automatically
5. ✅ Client secret stays on backend
6. ✅ State parameter prevents CSRF

## Common Mistakes to Avoid

1. ❌ Storing client_secret in frontend code
2. ❌ Using authorization code more than once
3. ❌ Not validating state parameter
4. ❌ Not checking token expiration
5. ❌ Using HTTP instead of HTTPS
6. ❌ Storing tokens in localStorage (XSS risk) - use httpOnly cookies in production

## Next Steps

Now that you understand the flow, let's implement it! The code will make much more sense now.

