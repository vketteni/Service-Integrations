# OAuth 2.0 Primer

## Overview
OAuth 2.0 is an authorization framework that enables applications to obtain limited access to user accounts on HTTP services. It allows third-party applications to access user data without exposing user credentials, providing a secure and standardized way to handle authorization across different platforms.

## Key Concepts

### Roles
- **Resource Owner**: The user who authorizes access to their account
- **Client**: The application requesting access (your app)
- **Resource Server**: The server hosting protected resources (API)
- **Authorization Server**: Issues access tokens after authenticating the resource owner

### Grant Types
OAuth 2.0 defines several grant types for different use cases:

1. **Authorization Code Grant** - Most secure, used for server-side apps
2. **Implicit Grant** - For client-side apps (deprecated, use PKCE instead)
3. **Resource Owner Password Credentials** - Direct username/password (not recommended)
4. **Client Credentials** - For server-to-server communication
5. **Refresh Token** - To obtain new access tokens
6. **PKCE** - Extension for public clients (mobile/SPA apps)

## Authorization Code Flow (Most Common)

### Step-by-Step Process

```
1. Client redirects user to authorization server
2. User authenticates and authorizes the client
3. Authorization server redirects back with authorization code
4. Client exchanges code for access token
5. Client uses access token to access protected resources
```

### Implementation Example

```javascript
// Step 1: Build authorization URL
const buildAuthUrl = (clientId, redirectUri, scopes, state) => {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: scopes.join(' '),
    state: state // CSRF protection
  });
  
  return `https://auth-server.com/oauth/authorize?${params}`;
};

// Usage
const authUrl = buildAuthUrl(
  'your-client-id',
  'https://yourapp.com/callback',
  ['read', 'write'],
  'random-state-string'
);

// Redirect user to authUrl
window.location.href = authUrl;

// Step 2: Handle callback (on your server)
const handleCallback = async (req, res) => {
  const { code, state } = req.query;
  
  // Verify state parameter
  if (state !== expectedState) {
    return res.status(400).json({ error: 'Invalid state parameter' });
  }
  
  // Step 3: Exchange code for access token
  const tokenResponse = await fetch('https://auth-server.com/oauth/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64')}`
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: REDIRECT_URI
    })
  });
  
  const tokens = await tokenResponse.json();
  
  // Store tokens securely
  // tokens.access_token, tokens.refresh_token, tokens.expires_in
  
  res.redirect('/success');
};
```

## PKCE Flow (For Public Clients)

PKCE (Proof Key for Code Exchange) adds security for public clients that can't store client secrets.

```javascript
// Generate code verifier and challenge
const generateCodeChallenge = () => {
  const codeVerifier = base64URLEncode(crypto.randomBytes(32));
  const codeChallenge = base64URLEncode(
    crypto.createHash('sha256').update(codeVerifier).digest()
  );
  
  return { codeVerifier, codeChallenge };
};

// Step 1: Build authorization URL with PKCE
const buildPKCEAuthUrl = (clientId, redirectUri, scopes, codeChallenge) => {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: scopes.join(' '),
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  });
  
  return `https://auth-server.com/oauth/authorize?${params}`;
};

// Step 2: Exchange code with code verifier
const exchangeCodePKCE = async (code, codeVerifier, clientId, redirectUri) => {
  const response = await fetch('https://auth-server.com/oauth/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      client_id: clientId,
      code_verifier: codeVerifier,
      redirect_uri: redirectUri
    })
  });
  
  return response.json();
};
```

## Client Credentials Flow

For server-to-server authentication without user involvement:

```javascript
const getClientCredentialsToken = async (clientId, clientSecret, scopes) => {
  const response = await fetch('https://auth-server.com/oauth/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`
    },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      scope: scopes.join(' ')
    })
  });
  
  return response.json();
};

// Usage
const tokens = await getClientCredentialsToken(
  'your-client-id',
  'your-client-secret',
  ['api:read', 'api:write']
);
```

## Token Management

### Access Token Usage
```javascript
// Using access token in API requests
const makeAuthenticatedRequest = async (accessToken, url) => {
  const response = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    }
  });
  
  if (response.status === 401) {
    // Token expired, need to refresh
    throw new Error('Token expired');
  }
  
  return response.json();
};
```

### Refresh Token Flow
```javascript
const refreshAccessToken = async (refreshToken, clientId, clientSecret) => {
  const response = await fetch('https://auth-server.com/oauth/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`
    },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken
    })
  });
  
  const tokens = await response.json();
  
  // Update stored tokens
  return tokens;
};

// Automatic token refresh wrapper
class OAuth2Client {
  constructor(clientId, clientSecret, accessToken, refreshToken) {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
  }
  
  async makeRequest(url, options = {}) {
    try {
      return await this._makeAuthenticatedRequest(url, options);
    } catch (error) {
      if (error.message === 'Token expired') {
        // Refresh token and retry
        await this._refreshToken();
        return await this._makeAuthenticatedRequest(url, options);
      }
      throw error;
    }
  }
  
  async _makeAuthenticatedRequest(url, options) {
    const response = await fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${this.accessToken}`
      }
    });
    
    if (response.status === 401) {
      throw new Error('Token expired');
    }
    
    return response.json();
  }
  
  async _refreshToken() {
    const tokens = await refreshAccessToken(
      this.refreshToken,
      this.clientId,
      this.clientSecret
    );
    
    this.accessToken = tokens.access_token;
    if (tokens.refresh_token) {
      this.refreshToken = tokens.refresh_token;
    }
    
    // Save updated tokens to storage
    this._saveTokens();
  }
  
  _saveTokens() {
    // Implement secure token storage
    // Database, encrypted cookies, etc.
  }
}
```

## Platform-Specific Examples

### Google OAuth 2.0
```javascript
const GOOGLE_OAUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';

const getGoogleAuthUrl = (clientId, redirectUri, scopes) => {
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: scopes.join(' '),
    response_type: 'code',
    access_type: 'offline', // For refresh token
    prompt: 'consent'
  });
  
  return `${GOOGLE_OAUTH_URL}?${params}`;
};

// Exchange Google auth code
const exchangeGoogleCode = async (code, clientId, clientSecret, redirectUri) => {
  const response = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code'
    })
  });
  
  return response.json();
};
```

### GitHub OAuth 2.0
```javascript
const GITHUB_OAUTH_URL = 'https://github.com/login/oauth/authorize';
const GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token';

const getGitHubAuthUrl = (clientId, scopes, state) => {
  const params = new URLSearchParams({
    client_id: clientId,
    scope: scopes.join(' '),
    state: state
  });
  
  return `${GITHUB_OAUTH_URL}?${params}`;
};

const exchangeGitHubCode = async (code, clientId, clientSecret) => {
  const response = await fetch(GITHUB_TOKEN_URL, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      code: code
    })
  });
  
  return response.json();
};
```

### Microsoft Azure AD
```javascript
const AZURE_OAUTH_URL = 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize';
const AZURE_TOKEN_URL = 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token';

const getAzureAuthUrl = (tenantId, clientId, redirectUri, scopes) => {
  const params = new URLSearchParams({
    client_id: clientId,
    response_type: 'code',
    redirect_uri: redirectUri,
    response_mode: 'query',
    scope: scopes.join(' ')
  });
  
  return `${AZURE_OAUTH_URL.replace('{tenant}', tenantId)}?${params}`;
};
```

## Security Best Practices

### State Parameter
Always use a state parameter to prevent CSRF attacks:

```javascript
// Generate random state
const generateState = () => {
  return crypto.randomBytes(16).toString('hex');
};

// Store state in session/database
const state = generateState();
req.session.oauthState = state;

// Include in auth URL
const authUrl = buildAuthUrl(clientId, redirectUri, scopes, state);

// Verify on callback
if (req.query.state !== req.session.oauthState) {
  throw new Error('Invalid state parameter');
}
```

### Secure Token Storage
```javascript
// Server-side: Use secure, httpOnly cookies or encrypted database storage
const storeTokens = (tokens, userId) => {
  // Encrypt tokens before storage
  const encryptedTokens = encrypt(JSON.stringify(tokens));
  
  // Store in database
  db.tokens.update(userId, {
    access_token: encryptedTokens,
    expires_at: new Date(Date.now() + tokens.expires_in * 1000),
    updated_at: new Date()
  });
};

// Client-side: Never store sensitive tokens in localStorage
// Use secure httpOnly cookies or memory storage
```

### HTTPS Only
```javascript
// Always use HTTPS for OAuth flows
const REDIRECT_URI = 'https://yourapp.com/oauth/callback'; // Not HTTP!

// Check for secure connection
if (req.protocol !== 'https' && process.env.NODE_ENV === 'production') {
  return res.status(400).json({ error: 'HTTPS required' });
}
```

## Error Handling

### Common OAuth Errors
```javascript
const handleOAuthError = (error) => {
  switch (error.error) {
    case 'invalid_request':
      return 'The request is missing a required parameter';
    case 'invalid_client':
      return 'Client authentication failed';
    case 'invalid_grant':
      return 'The authorization code is invalid or expired';
    case 'unauthorized_client':
      return 'The client is not authorized to use this grant type';
    case 'unsupported_grant_type':
      return 'The grant type is not supported';
    case 'invalid_scope':
      return 'The requested scope is invalid or unknown';
    case 'access_denied':
      return 'The user denied the authorization request';
    default:
      return 'An unknown OAuth error occurred';
  }
};

// Usage in callback handler
const handleCallback = async (req, res) => {
  const { code, error, error_description, state } = req.query;
  
  if (error) {
    const errorMessage = handleOAuthError({ error, error_description });
    return res.status(400).json({ error: errorMessage });
  }
  
  // Continue with code exchange...
};
```

### Token Expiration Handling
```javascript
class TokenManager {
  constructor(tokens) {
    this.tokens = tokens;
    this.refreshInProgress = false;
  }
  
  async getValidToken() {
    // Check if token is expired (with 5-minute buffer)
    const expirationTime = this.tokens.expires_at - (5 * 60 * 1000);
    
    if (Date.now() > expirationTime) {
      return await this.refreshToken();
    }
    
    return this.tokens.access_token;
  }
  
  async refreshToken() {
    if (this.refreshInProgress) {
      // Wait for existing refresh to complete
      await this.waitForRefresh();
      return this.tokens.access_token;
    }
    
    this.refreshInProgress = true;
    
    try {
      const newTokens = await this.performTokenRefresh();
      this.tokens = { ...this.tokens, ...newTokens };
      return this.tokens.access_token;
    } finally {
      this.refreshInProgress = false;
    }
  }
}
```

## Testing OAuth Flows

### Mock Authorization Server
```javascript
// For testing purposes - mock OAuth server
const express = require('express');
const app = express();

// Mock authorization endpoint
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, state, scope } = req.query;
  
  // In real testing, you'd validate these parameters
  const authCode = 'mock-auth-code-123';
  const redirectUrl = `${redirect_uri}?code=${authCode}&state=${state}`;
  
  res.redirect(redirectUrl);
});

// Mock token endpoint
app.post('/oauth/token', (req, res) => {
  const { grant_type, code, client_id, client_secret } = req.body;
  
  // Validate grant type and credentials
  if (grant_type === 'authorization_code' && code === 'mock-auth-code-123') {
    res.json({
      access_token: 'mock-access-token',
      refresh_token: 'mock-refresh-token',
      expires_in: 3600,
      token_type: 'Bearer'
    });
  } else {
    res.status(400).json({ error: 'invalid_grant' });
  }
});
```

### Unit Testing OAuth Client
```javascript
// Jest test example
describe('OAuth Client', () => {
  test('should build correct authorization URL', () => {
    const authUrl = buildAuthUrl(
      'test-client-id',
      'https://test.com/callback',
      ['read', 'write'],
      'test-state'
    );
    
    expect(authUrl).toContain('client_id=test-client-id');
    expect(authUrl).toContain('scope=read%20write');
    expect(authUrl).toContain('state=test-state');
  });
  
  test('should handle token refresh', async () => {
    const mockFetch = jest.fn().mockResolvedValue({
      json: () => Promise.resolve({
        access_token: 'new-token',
        expires_in: 3600
      })
    });
    
    global.fetch = mockFetch;
    
    const client = new OAuth2Client('id', 'secret', 'old-token', 'refresh');
    const token = await client._refreshToken();
    
    expect(mockFetch).toHaveBeenCalled();
    expect(client.accessToken).toBe('new-token');
  });
});
```

## Common Integration Patterns

### Express.js Middleware
```javascript
const createOAuthMiddleware = (config) => {
  return async (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
      // Validate token with OAuth provider
      const userInfo = await validateToken(token, config);
      req.user = userInfo;
      next();
    } catch (error) {
      res.status(401).json({ error: 'Invalid token' });
    }
  };
};

// Usage
app.use('/api', createOAuthMiddleware(oauthConfig));
```

### React Hook for OAuth
```javascript
import { useState, useEffect } from 'react';

const useOAuth = (config) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    // Check for existing token
    const token = localStorage.getItem('access_token');
    if (token) {
      validateAndSetUser(token);
    } else {
      setLoading(false);
    }
  }, []);
  
  const login = () => {
    const authUrl = buildAuthUrl(
      config.clientId,
      config.redirectUri,
      config.scopes,
      generateState()
    );
    window.location.href = authUrl;
  };
  
  const logout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    setIsAuthenticated(false);
    setUser(null);
  };
  
  const validateAndSetUser = async (token) => {
    try {
      const userInfo = await fetchUserInfo(token);
      setUser(userInfo);
      setIsAuthenticated(true);
    } catch (error) {
      logout();
    } finally {
      setLoading(false);
    }
  };
  
  return { isAuthenticated, user, loading, login, logout };
};
```

## Resources

### Specifications
- [RFC 6749 - OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 7636 - PKCE Extension](https://tools.ietf.org/html/rfc7636)
- [RFC 6750 - Bearer Token Usage](https://tools.ietf.org/html/rfc6750)

### Security Guidelines
- [OAuth 2.0 Security Best Practices](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)
- [OAuth 2.0 for Browser-Based Apps](https://tools.ietf.org/html/draft-ietf-oauth-browser-based-apps)

### Libraries and Tools
- **Node.js**: `passport-oauth2`, `simple-oauth2`, `node-oauth2-server`
- **Python**: `authlib`, `requests-oauthlib`, `django-oauth-toolkit`
- **Java**: `Spring Security OAuth`, `Apache Oltu`
- **PHP**: `league/oauth2-client`, `thephpleague/oauth2-server`

### Testing Tools
- [OAuth 2.0 Debugger](https://oauthdebugger.com/)
- [JWT.io](https://jwt.io/) - For JWT token inspection
- [Postman OAuth 2.0](https://learning.postman.com/docs/sending-requests/authorization/#oauth-20) - For API testing