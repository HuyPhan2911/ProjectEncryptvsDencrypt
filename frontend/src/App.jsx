import { useState, useEffect } from 'react'
import './App.css'

// OAuth2 Configuration
const AUTH_SERVER_URL = 'http://localhost:5001'
const CLIENT_ID = 'my_client'
const REDIRECT_URI = 'http://localhost:5173/callback'
const SCOPE = 'read'

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [accessToken, setAccessToken] = useState(null)
  const [refreshToken, setRefreshToken] = useState(null)
  const [userData, setUserData] = useState(null)
  const [protectedData, setProtectedData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)

  // Check if we're returning from OAuth callback
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search)
    const code = urlParams.get('code')
    const state = urlParams.get('state')
    const error = urlParams.get('error')

    if (error) {
      setError(`OAuth error: ${error}`)
      // Clean URL
      window.history.replaceState({}, document.title, '/')
      return
    }

    if (code) {
      // We have an authorization code, exchange it for tokens
      exchangeCodeForTokens(code, state)
      // Clean URL
      window.history.replaceState({}, document.title, '/')
    } else {
      // Check if we have stored tokens
      const storedAccessToken = localStorage.getItem('access_token')
      const storedRefreshToken = localStorage.getItem('refresh_token')
      
      if (storedAccessToken && storedRefreshToken) {
        setAccessToken(storedAccessToken)
        setRefreshToken(storedRefreshToken)
        setIsAuthenticated(true)
        // Verify token is still valid by fetching user data
        fetchUserData(storedAccessToken)
      }
    }
  }, [])

  const generateState = () => {
    // Generate random state for CSRF protection
    return Math.random().toString(36).substring(2, 15) + 
           Math.random().toString(36).substring(2, 15)
  }

  const initiateLogin = () => {
    setError(null)
    const state = generateState()
    localStorage.setItem('oauth_state', state)
    
    // Build authorization URL
    const authUrl = new URL(`${AUTH_SERVER_URL}/auth/authorize`)
    authUrl.searchParams.set('client_id', CLIENT_ID)
    authUrl.searchParams.set('redirect_uri', REDIRECT_URI)
    authUrl.searchParams.set('response_type', 'code')
    authUrl.searchParams.set('scope', SCOPE)
    authUrl.searchParams.set('state', state)
    
    // Redirect browser to authorization server
    window.location.href = authUrl.toString()
  }

  const exchangeCodeForTokens = async (code, state) => {
    setLoading(true)
    setError(null)

    try {
      // Verify state matches (CSRF protection)
      const storedState = localStorage.getItem('oauth_state')
      if (state !== storedState) {
        throw new Error('State mismatch - possible CSRF attack')
      }
      localStorage.removeItem('oauth_state')

      // Exchange code for tokens via our backend proxy
      const response = await fetch('/api/exchange_code', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ code, state }),
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.error || 'Token exchange failed')
      }

      const tokenData = await response.json()
      
      // Store tokens
      setAccessToken(tokenData.access_token)
      setRefreshToken(tokenData.refresh_token)
      setIsAuthenticated(true)
      
      // Store in localStorage (in production, consider httpOnly cookies)
      localStorage.setItem('access_token', tokenData.access_token)
      if (tokenData.refresh_token) {
        localStorage.setItem('refresh_token', tokenData.refresh_token)
      }

      // Fetch user data
      await fetchUserData(tokenData.access_token)
    } catch (err) {
      setError(err.message)
      setIsAuthenticated(false)
    } finally {
      setLoading(false)
    }
  }

  const fetchUserData = async (token) => {
    setLoading(true)
    setError(null)

    try {
      const response = await fetch(`${AUTH_SERVER_URL}/api/user/profile`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      })

      if (response.status === 401) {
        // Token expired, try to refresh
        await refreshAccessToken()
        return
      }

      if (!response.ok) {
        throw new Error('Failed to fetch user data')
      }

      const data = await response.json()
      setUserData(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const fetchProtectedData = async () => {
    setLoading(true)
    setError(null)

    try {
      const response = await fetch(`${AUTH_SERVER_URL}/api/data`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
      })

      if (response.status === 401) {
        // Token expired, try to refresh
        await refreshAccessToken()
        // Retry the request
        return fetchProtectedData()
      }

      if (!response.ok) {
        throw new Error('Failed to fetch protected data')
      }

      const data = await response.json()
      setProtectedData(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const refreshAccessToken = async () => {
    if (!refreshToken) {
      throw new Error('No refresh token available')
    }

    try {
      const response = await fetch('/api/refresh_token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ refresh_token: refreshToken }),
      })

      if (!response.ok) {
        throw new Error('Token refresh failed')
      }

      const tokenData = await response.json()
      setAccessToken(tokenData.access_token)
      localStorage.setItem('access_token', tokenData.access_token)

      // If new refresh token provided, update it
      if (tokenData.refresh_token) {
        setRefreshToken(tokenData.refresh_token)
        localStorage.setItem('refresh_token', tokenData.refresh_token)
      }
    } catch (err) {
      // Refresh failed, user needs to login again
      logout()
      throw err
    }
  }

  const logout = () => {
    setAccessToken(null)
    setRefreshToken(null)
    setIsAuthenticated(false)
    setUserData(null)
    setProtectedData(null)
    setError(null)
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
    localStorage.removeItem('oauth_state')
  }

  return (
    <div className="container">
      <h1>🔐 OAuth2 Authorization Code Flow Demo</h1>
      
      {error && (
        <div className="status error">
          <strong>Error:</strong> {error}
        </div>
      )}

      {loading && (
        <div className="status info">
          <span className="loading">Loading...</span>
        </div>
      )}

      {!isAuthenticated ? (
        <div>
          <h2>Welcome!</h2>
          <p>This is an OAuth2 demo application. Click the button below to start the authorization flow.</p>
          <button onClick={initiateLogin} disabled={loading}>
            Login with OAuth2
          </button>
          <div className="status info" style={{ marginTop: '20px' }}>
            <strong>Test Users:</strong><br />
            Username: <code>alice</code> / Password: <code>password123</code><br />
            Username: <code>bob</code> / Password: <code>password123</code>
          </div>
        </div>
      ) : (
        <div>
          <div className="status success">
            ✅ <strong>Authenticated!</strong> You have successfully completed the OAuth2 flow.
          </div>

          <div style={{ display: 'flex', gap: '10px', marginTop: '20px' }}>
            <button onClick={() => fetchUserData(accessToken)} disabled={loading}>
              Fetch User Profile
            </button>
            <button onClick={fetchProtectedData} disabled={loading}>
              Fetch Protected Data
            </button>
            <button onClick={logout} style={{ background: '#dc3545' }}>
              Logout
            </button>
          </div>

          {accessToken && (
            <div>
              <h2>Access Token (JWT)</h2>
              <div className="token-display">{accessToken}</div>
            </div>
          )}

          {refreshToken && (
            <div>
              <h2>Refresh Token</h2>
              <div className="token-display">{refreshToken}</div>
            </div>
          )}

          {userData && (
            <div>
              <h2>User Profile Data</h2>
              <div className="data-display">{JSON.stringify(userData, null, 2)}</div>
            </div>
          )}

          {protectedData && (
            <div>
              <h2>Protected Resource Data</h2>
              <div className="data-display">{JSON.stringify(protectedData, null, 2)}</div>
            </div>
          )}
        </div>
      )}

      <div style={{ marginTop: '40px', paddingTop: '20px', borderTop: '1px solid #dee2e6' }}>
        <h2>How This Works</h2>
        <ol style={{ lineHeight: '1.8', marginLeft: '20px' }}>
          <li>Click "Login with OAuth2" → Redirects to authorization server</li>
          <li>Enter credentials → Authorization server validates and generates code</li>
          <li>Redirected back with code → Frontend exchanges code for tokens</li>
          <li>Tokens stored → Use access token to call protected APIs</li>
          <li>When token expires → Use refresh token to get new access token</li>
        </ol>
        <p style={{ marginTop: '15px', color: '#666' }}>
          See <code>OAUTH2_GUIDE.md</code> for detailed explanation of the flow.
        </p>
      </div>
    </div>
  )
}

export default App

