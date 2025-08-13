# API Key Management Primer

## Overview
API keys are secret tokens used to authenticate applications when accessing third-party services. Proper API key management is critical for security, preventing unauthorized access, rate limiting, and maintaining system integrity. This primer covers best practices for generating, storing, rotating, and securing API keys throughout their lifecycle.

## Key Concepts

### What are API Keys?
API keys are unique identifiers passed with API requests to:
- **Authenticate** the calling application
- **Authorize** access to specific resources
- **Track** usage and enforce rate limits
- **Audit** API usage patterns

### Types of API Keys
1. **Public Keys** - Safe to expose in client-side code (limited permissions)
2. **Secret Keys** - Must be kept secure on servers only
3. **Restricted Keys** - Limited to specific domains, IPs, or API endpoints
4. **Temporary Keys** - Short-lived tokens with automatic expiration

## Security Best Practices

### 1. Never Hardcode API Keys
```javascript
// ❌ BAD: Hardcoded in source code
const apiKey = 'sk_live_abcd1234...';

// ❌ BAD: Committed to version control
const config = {
  stripeKey: 'sk_live_abcd1234...'
};

// ✅ GOOD: Use environment variables
const apiKey = process.env.STRIPE_SECRET_KEY;

// ✅ GOOD: Load from secure configuration
const config = await loadSecureConfig();
const apiKey = config.stripe.secretKey;
```

### 2. Use Environment Variables
```bash
# .env file (never commit this)
STRIPE_SECRET_KEY=sk_live_abcd1234...
GOOGLE_ANALYTICS_API_KEY=AIza...
HUBSPOT_API_KEY=pat-na1-abcd...

# Production environment
export STRIPE_SECRET_KEY="sk_live_abcd1234..."
export NODE_ENV="production"
```

```javascript
// Node.js with dotenv
require('dotenv').config();

const stripeKey = process.env.STRIPE_SECRET_KEY;
if (!stripeKey) {
  throw new Error('STRIPE_SECRET_KEY environment variable is required');
}

// Validate environment
if (process.env.NODE_ENV === 'production') {
  if (stripeKey.startsWith('sk_test_')) {
    throw new Error('Cannot use test keys in production');
  }
}
```

### 3. Implement Key Rotation
```javascript
class APIKeyManager {
  constructor(primary, secondary = null) {
    this.primaryKey = primary;
    this.secondaryKey = secondary;
    this.currentKey = 'primary';
  }

  getCurrentKey() {
    return this.currentKey === 'primary' ? this.primaryKey : this.secondaryKey;
  }

  // Graceful key rotation
  async rotateKey(newKey) {
    // Step 1: Set new key as secondary
    this.secondaryKey = newKey;
    
    // Step 2: Test the new key
    const isValid = await this.validateKey(newKey);
    if (!isValid) {
      throw new Error('New key validation failed');
    }
    
    // Step 3: Switch to new key
    this.currentKey = 'secondary';
    
    // Step 4: Wait for propagation period
    setTimeout(() => {
      this.primaryKey = this.secondaryKey;
      this.secondaryKey = null;
      this.currentKey = 'primary';
    }, 300000); // 5 minutes
  }

  async validateKey(key) {
    try {
      // Make a test API call
      const response = await fetch('https://api.service.com/test', {
        headers: { 'Authorization': `Bearer ${key}` }
      });
      return response.ok;
    } catch (error) {
      return false;
    }
  }

  // Fallback mechanism
  async makeRequest(url, options = {}) {
    let key = this.getCurrentKey();
    
    try {
      return await this._makeRequestWithKey(url, key, options);
    } catch (error) {
      if (error.status === 401 && this.secondaryKey) {
        // Try with fallback key
        console.warn('Primary key failed, trying fallback');
        return await this._makeRequestWithKey(url, this.secondaryKey, options);
      }
      throw error;
    }
  }

  async _makeRequestWithKey(url, key, options) {
    const response = await fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${key}`
      }
    });

    if (!response.ok) {
      const error = new Error(`API request failed: ${response.statusText}`);
      error.status = response.status;
      throw error;
    }

    return response.json();
  }
}
```

### 4. Secure Storage Solutions

#### Server-Side Storage
```javascript
// Using encrypted storage
const crypto = require('crypto');

class SecureKeyStorage {
  constructor(encryptionKey) {
    this.algorithm = 'aes-256-gcm';
    this.encryptionKey = crypto.scryptSync(encryptionKey, 'salt', 32);
  }

  encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher(this.algorithm, this.encryptionKey);
    cipher.setAAD(Buffer.from('api-key'));
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    };
  }

  decrypt(encryptedData) {
    const decipher = crypto.createDecipher(
      this.algorithm, 
      this.encryptionKey
    );
    
    decipher.setAAD(Buffer.from('api-key'));
    decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  // Store in database with encryption
  async storeKey(keyId, apiKey) {
    const encryptedData = this.encrypt(apiKey);
    
    await db.apiKeys.insert({
      keyId,
      encrypted: encryptedData.encrypted,
      iv: encryptedData.iv,
      authTag: encryptedData.authTag,
      createdAt: new Date()
    });
  }

  async retrieveKey(keyId) {
    const record = await db.apiKeys.findOne({ keyId });
    if (!record) return null;
    
    return this.decrypt({
      encrypted: record.encrypted,
      iv: record.iv,
      authTag: record.authTag
    });
  }
}
```

#### Using Cloud Secret Managers
```javascript
// AWS Secrets Manager
const AWS = require('aws-sdk');
const secretsManager = new AWS.SecretsManager();

class AWSSecretManager {
  async getSecret(secretName) {
    try {
      const result = await secretsManager.getSecretValue({
        SecretId: secretName
      }).promise();
      
      return JSON.parse(result.SecretString);
    } catch (error) {
      console.error('Error retrieving secret:', error);
      throw error;
    }
  }

  async updateSecret(secretName, secretValue) {
    try {
      await secretsManager.updateSecret({
        SecretId: secretName,
        SecretString: JSON.stringify(secretValue)
      }).promise();
    } catch (error) {
      console.error('Error updating secret:', error);
      throw error;
    }
  }
}

// Azure Key Vault
const { SecretClient } = require('@azure/keyvault-secrets');
const { DefaultAzureCredential } = require('@azure/identity');

class AzureKeyVaultManager {
  constructor(vaultUrl) {
    const credential = new DefaultAzureCredential();
    this.client = new SecretClient(vaultUrl, credential);
  }

  async getSecret(secretName) {
    try {
      const secret = await this.client.getSecret(secretName);
      return secret.value;
    } catch (error) {
      console.error('Error retrieving secret:', error);
      throw error;
    }
  }

  async setSecret(secretName, secretValue) {
    try {
      await this.client.setSecret(secretName, secretValue);
    } catch (error) {
      console.error('Error setting secret:', error);
      throw error;
    }
  }
}
```

### 5. Key Validation and Monitoring
```javascript
class APIKeyValidator {
  constructor() {
    this.keyFormats = {
      stripe: /^sk_(test|live)_[a-zA-Z0-9]{24,}$/,
      google: /^AIza[0-9A-Za-z-_]{35}$/,
      github: /^ghp_[a-zA-Z0-9]{36}$/,
      hubspot: /^pat-na1-[a-f0-9-]{36}$/
    };
  }

  validateFormat(service, key) {
    const pattern = this.keyFormats[service];
    if (!pattern) {
      throw new Error(`Unknown service: ${service}`);
    }
    
    return pattern.test(key);
  }

  validateEnvironment(service, key) {
    // Ensure production keys aren't used in development
    if (process.env.NODE_ENV !== 'production') {
      if (service === 'stripe' && key.includes('_live_')) {
        throw new Error('Cannot use live Stripe key in non-production environment');
      }
    }
    
    // Ensure test keys aren't used in production
    if (process.env.NODE_ENV === 'production') {
      if (service === 'stripe' && key.includes('_test_')) {
        throw new Error('Cannot use test Stripe key in production environment');
      }
    }
    
    return true;
  }

  async validateKeyHealth(service, key) {
    const healthChecks = {
      stripe: async (key) => {
        const stripe = require('stripe')(key);
        try {
          await stripe.accounts.retrieve();
          return true;
        } catch (error) {
          return false;
        }
      },
      
      google: async (key) => {
        try {
          const response = await fetch(`https://www.googleapis.com/analytics/v3/management/accounts?key=${key}`);
          return response.status !== 401;
        } catch (error) {
          return false;
        }
      }
    };
    
    const healthCheck = healthChecks[service];
    if (healthCheck) {
      return await healthCheck(key);
    }
    
    return true; // Assume valid if no health check available
  }
}

// Monitoring and alerting
class APIKeyMonitor {
  constructor() {
    this.usageStats = new Map();
    this.alerts = [];
  }

  trackUsage(keyId, endpoint, success) {
    const key = `${keyId}:${endpoint}`;
    const stats = this.usageStats.get(key) || {
      requests: 0,
      failures: 0,
      lastUsed: null
    };
    
    stats.requests++;
    if (!success) stats.failures++;
    stats.lastUsed = new Date();
    
    this.usageStats.set(key, stats);
    
    // Check for unusual patterns
    this.checkForAnomalies(keyId, stats);
  }

  checkForAnomalies(keyId, stats) {
    const failureRate = stats.failures / stats.requests;
    
    // High failure rate alert
    if (stats.requests > 100 && failureRate > 0.5) {
      this.raiseAlert('HIGH_FAILURE_RATE', keyId, {
        failureRate: failureRate.toFixed(2),
        totalRequests: stats.requests
      });
    }
    
    // Unused key alert
    const daysSinceLastUse = (Date.now() - stats.lastUsed) / (1000 * 60 * 60 * 24);
    if (daysSinceLastUse > 30) {
      this.raiseAlert('UNUSED_KEY', keyId, {
        daysSinceLastUse: Math.floor(daysSinceLastUse)
      });
    }
  }

  raiseAlert(type, keyId, details) {
    const alert = {
      type,
      keyId,
      details,
      timestamp: new Date(),
      resolved: false
    };
    
    this.alerts.push(alert);
    console.warn(`API Key Alert [${type}] for key ${keyId}:`, details);
    
    // Send to monitoring system
    this.sendToMonitoring(alert);
  }

  sendToMonitoring(alert) {
    // Integrate with monitoring services
    // Datadog, New Relic, Sentry, etc.
  }
}
```

## Environment-Specific Management

### Development Environment
```javascript
// dev-config.js
const config = {
  stripe: {
    publishableKey: process.env.STRIPE_TEST_PUBLISHABLE_KEY,
    secretKey: process.env.STRIPE_TEST_SECRET_KEY
  },
  google: {
    analyticsKey: process.env.GOOGLE_ANALYTICS_DEV_KEY
  },
  // Always use test/sandbox keys in development
  validateEnvironment: () => {
    const keys = [
      process.env.STRIPE_TEST_SECRET_KEY,
      process.env.GOOGLE_ANALYTICS_DEV_KEY
    ];
    
    keys.forEach(key => {
      if (key && (key.includes('live') || key.includes('prod'))) {
        throw new Error('Production keys detected in development environment');
      }
    });
  }
};

module.exports = config;
```

### Production Environment
```javascript
// prod-config.js
const config = {
  stripe: {
    publishableKey: process.env.STRIPE_LIVE_PUBLISHABLE_KEY,
    secretKey: process.env.STRIPE_LIVE_SECRET_KEY
  },
  google: {
    analyticsKey: process.env.GOOGLE_ANALYTICS_PROD_KEY
  },
  // Validate production keys
  validateEnvironment: () => {
    const requiredKeys = [
      'STRIPE_LIVE_SECRET_KEY',
      'GOOGLE_ANALYTICS_PROD_KEY'
    ];
    
    requiredKeys.forEach(keyName => {
      const key = process.env[keyName];
      if (!key) {
        throw new Error(`Required production key ${keyName} is missing`);
      }
      
      if (key.includes('test') || key.includes('dev')) {
        throw new Error(`Test key found in production: ${keyName}`);
      }
    });
  }
};

module.exports = config;
```

## Access Control and Permissions

### Key Scoping
```javascript
class ScopedAPIKeyManager {
  constructor() {
    this.keyScopes = new Map();
  }

  createScopedKey(baseKey, scopes, restrictions = {}) {
    const scopedKey = {
      baseKey,
      scopes, // ['read:users', 'write:orders']
      restrictions: {
        ipWhitelist: restrictions.ipWhitelist || [],
        domainWhitelist: restrictions.domainWhitelist || [],
        rateLimit: restrictions.rateLimit || 1000,
        expiresAt: restrictions.expiresAt
      },
      createdAt: new Date()
    };
    
    const keyId = this.generateKeyId();
    this.keyScopes.set(keyId, scopedKey);
    
    return keyId;
  }

  validateKeyAccess(keyId, requiredScope, request) {
    const keyData = this.keyScopes.get(keyId);
    if (!keyData) {
      throw new Error('Invalid API key');
    }

    // Check expiration
    if (keyData.restrictions.expiresAt && new Date() > keyData.restrictions.expiresAt) {
      throw new Error('API key has expired');
    }

    // Check scope
    if (!keyData.scopes.includes(requiredScope)) {
      throw new Error(`Insufficient scope. Required: ${requiredScope}`);
    }

    // Check IP whitelist
    if (keyData.restrictions.ipWhitelist.length > 0) {
      const clientIP = request.ip;
      if (!keyData.restrictions.ipWhitelist.includes(clientIP)) {
        throw new Error('IP address not whitelisted');
      }
    }

    // Check domain whitelist
    if (keyData.restrictions.domainWhitelist.length > 0) {
      const origin = request.headers.origin;
      if (!keyData.restrictions.domainWhitelist.includes(origin)) {
        throw new Error('Domain not whitelisted');
      }
    }

    return keyData.baseKey;
  }

  generateKeyId() {
    return `ak_${crypto.randomBytes(16).toString('hex')}`;
  }
}
```

### Rate Limiting by Key
```javascript
class RateLimitedKeyManager {
  constructor() {
    this.rateLimits = new Map();
    this.usageCounters = new Map();
  }

  setRateLimit(keyId, limit, windowMs = 60000) {
    this.rateLimits.set(keyId, { limit, windowMs, resetTime: Date.now() + windowMs });
  }

  checkRateLimit(keyId) {
    const rateLimit = this.rateLimits.get(keyId);
    if (!rateLimit) return true; // No limit set

    const now = Date.now();
    const usage = this.usageCounters.get(keyId) || { count: 0, resetTime: now + rateLimit.windowMs };

    // Reset counter if window expired
    if (now >= usage.resetTime) {
      usage.count = 0;
      usage.resetTime = now + rateLimit.windowMs;
    }

    // Check if limit exceeded
    if (usage.count >= rateLimit.limit) {
      const resetIn = Math.ceil((usage.resetTime - now) / 1000);
      throw new Error(`Rate limit exceeded. Resets in ${resetIn} seconds`);
    }

    // Increment counter
    usage.count++;
    this.usageCounters.set(keyId, usage);

    return true;
  }
}
```

## Key Lifecycle Management

### Automated Key Rotation
```javascript
class AutomatedKeyRotation {
  constructor(keyManager, rotationIntervalDays = 90) {
    this.keyManager = keyManager;
    this.rotationInterval = rotationIntervalDays * 24 * 60 * 60 * 1000;
    this.scheduledRotations = new Map();
  }

  scheduleRotation(keyId, service) {
    const rotationTime = Date.now() + this.rotationInterval;
    
    const timeout = setTimeout(async () => {
      await this.rotateKey(keyId, service);
    }, this.rotationInterval);

    this.scheduledRotations.set(keyId, {
      timeout,
      service,
      scheduledFor: new Date(rotationTime)
    });

    console.log(`Key rotation scheduled for ${keyId} at ${new Date(rotationTime)}`);
  }

  async rotateKey(keyId, service) {
    try {
      console.log(`Starting rotation for key ${keyId}`);
      
      // Generate new key (service-specific)
      const newKey = await this.generateNewKey(service);
      
      // Update key manager
      await this.keyManager.rotateKey(newKey);
      
      // Schedule next rotation
      this.scheduleRotation(keyId, service);
      
      // Notify administrators
      await this.notifyRotation(keyId, service, 'success');
      
    } catch (error) {
      console.error(`Key rotation failed for ${keyId}:`, error);
      await this.notifyRotation(keyId, service, 'failed', error.message);
      
      // Retry in 1 hour
      setTimeout(() => this.rotateKey(keyId, service), 3600000);
    }
  }

  async generateNewKey(service) {
    // Service-specific key generation logic
    const generators = {
      internal: () => crypto.randomBytes(32).toString('hex'),
      // For external services, this would trigger their key generation API
      stripe: async () => {
        // Call Stripe API to generate new restricted key
        throw new Error('Manual rotation required for Stripe keys');
      }
    };

    const generator = generators[service];
    if (!generator) {
      throw new Error(`No key generator for service: ${service}`);
    }

    return await generator();
  }

  async notifyRotation(keyId, service, status, error = null) {
    const notification = {
      keyId,
      service,
      status,
      timestamp: new Date(),
      error
    };

    // Send notification (email, Slack, etc.)
    console.log('Key rotation notification:', notification);
  }
}
```

### Key Deprecation and Cleanup
```javascript
class KeyDeprecationManager {
  constructor() {
    this.deprecatedKeys = new Map();
    this.gracePeriodMs = 30 * 24 * 60 * 60 * 1000; // 30 days
  }

  deprecateKey(keyId, reason, replacementKeyId = null) {
    const deprecationInfo = {
      keyId,
      reason,
      replacementKeyId,
      deprecatedAt: new Date(),
      gracePeriodEnds: new Date(Date.now() + this.gracePeriodMs),
      notificationsSent: []
    };

    this.deprecatedKeys.set(keyId, deprecationInfo);

    // Schedule notifications
    this.scheduleDeprecationNotifications(deprecationInfo);
  }

  scheduleDeprecationNotifications(deprecationInfo) {
    // Immediate notification
    this.sendDeprecationNotification(deprecationInfo, 'immediate');

    // 7 days before expiration
    const sevenDaysNotice = deprecationInfo.gracePeriodEnds.getTime() - (7 * 24 * 60 * 60 * 1000);
    if (sevenDaysNotice > Date.now()) {
      setTimeout(() => {
        this.sendDeprecationNotification(deprecationInfo, '7-days');
      }, sevenDaysNotice - Date.now());
    }

    // 1 day before expiration
    const oneDayNotice = deprecationInfo.gracePeriodEnds.getTime() - (24 * 60 * 60 * 1000);
    if (oneDayNotice > Date.now()) {
      setTimeout(() => {
        this.sendDeprecationNotification(deprecationInfo, '1-day');
      }, oneDayNotice - Date.now());
    }

    // Cleanup after grace period
    setTimeout(() => {
      this.cleanupDeprecatedKey(deprecationInfo.keyId);
    }, this.gracePeriodMs);
  }

  sendDeprecationNotification(deprecationInfo, type) {
    if (deprecationInfo.notificationsSent.includes(type)) {
      return; // Already sent this type of notification
    }

    const message = this.buildDeprecationMessage(deprecationInfo, type);
    
    // Send notification
    console.log('Deprecation notification:', message);
    
    // Mark as sent
    deprecationInfo.notificationsSent.push(type);
  }

  buildDeprecationMessage(deprecationInfo, type) {
    const messages = {
      immediate: `API Key ${deprecationInfo.keyId} has been deprecated. Reason: ${deprecationInfo.reason}. Grace period ends: ${deprecationInfo.gracePeriodEnds}`,
      '7-days': `API Key ${deprecationInfo.keyId} will be disabled in 7 days. Please update to replacement key: ${deprecationInfo.replacementKeyId}`,
      '1-day': `URGENT: API Key ${deprecationInfo.keyId} will be disabled in 24 hours. Update immediately.`
    };

    return messages[type];
  }

  async cleanupDeprecatedKey(keyId) {
    try {
      // Remove from active keys
      await this.keyManager.revokeKey(keyId);
      
      // Archive deprecation info
      const deprecationInfo = this.deprecatedKeys.get(keyId);
      await this.archiveDeprecationInfo(deprecationInfo);
      
      // Remove from memory
      this.deprecatedKeys.delete(keyId);
      
      console.log(`Deprecated key ${keyId} has been cleaned up`);
    } catch (error) {
      console.error(`Failed to cleanup deprecated key ${keyId}:`, error);
    }
  }

  async archiveDeprecationInfo(deprecationInfo) {
    // Store in database for audit purposes
    await db.deprecatedKeys.insert({
      ...deprecationInfo,
      cleanedUpAt: new Date()
    });
  }
}
```

## Testing and Validation

### Key Testing Framework
```javascript
class APIKeyTester {
  constructor() {
    this.testSuites = new Map();
  }

  registerTestSuite(service, tests) {
    this.testSuites.set(service, tests);
  }

  async testKey(service, key, environment = 'test') {
    const testSuite = this.testSuites.get(service);
    if (!testSuite) {
      throw new Error(`No test suite registered for service: ${service}`);
    }

    const results = [];

    for (const test of testSuite) {
      try {
        const result = await test.run(key, environment);
        results.push({
          name: test.name,
          passed: true,
          result
        });
      } catch (error) {
        results.push({
          name: test.name,
          passed: false,
          error: error.message
        });
      }
    }

    return {
      service,
      key: this.maskKey(key),
      environment,
      timestamp: new Date(),
      passed: results.every(r => r.passed),
      results
    };
  }

  maskKey(key) {
    if (key.length <= 8) return '***';
    return key.slice(0, 4) + '***' + key.slice(-4);
  }
}

// Example test suites
const stripeTestSuite = [
  {
    name: 'Authentication Test',
    run: async (key, env) => {
      const stripe = require('stripe')(key);
      const account = await stripe.accounts.retrieve();
      return { accountId: account.id, environment: env };
    }
  },
  {
    name: 'Read Permission Test',
    run: async (key, env) => {
      const stripe = require('stripe')(key);
      const customers = await stripe.customers.list({ limit: 1 });
      return { canRead: true, customerCount: customers.data.length };
    }
  }
];

const googleAnalyticsTestSuite = [
  {
    name: 'API Access Test',
    run: async (key, env) => {
      const response = await fetch(`https://www.googleapis.com/analytics/v3/management/accounts?key=${key}`);
      if (!response.ok) throw new Error('API access failed');
      const data = await response.json();
      return { accountCount: data.items?.length || 0 };
    }
  }
];

// Register test suites
const tester = new APIKeyTester();
tester.registerTestSuite('stripe', stripeTestSuite);
tester.registerTestSuite('google-analytics', googleAnalyticsTestSuite);
```

## Compliance and Auditing

### Audit Trail
```javascript
class APIKeyAuditLogger {
  constructor() {
    this.auditLog = [];
  }

  logKeyEvent(event, keyId, userId, details = {}) {
    const logEntry = {
      timestamp: new Date(),
      event,
      keyId: this.maskKey(keyId),
      userId,
      details,
      sessionId: this.getCurrentSessionId(),
      ipAddress: this.getCurrentIP()
    };

    this.auditLog.push(logEntry);
    this.persistAuditLog(logEntry);
  }

  async persistAuditLog(entry) {
    // Store in secure audit database
    await db.auditLog.insert(entry);
    
    // Also send to external audit service if required
    if (process.env.AUDIT_SERVICE_ENABLED === 'true') {
      await this.sendToExternalAuditService(entry);
    }
  }

  generateAuditReport(startDate, endDate, keyId = null) {
    let filteredLogs = this.auditLog.filter(log => {
      return log.timestamp >= startDate && log.timestamp <= endDate;
    });

    if (keyId) {
      const maskedKeyId = this.maskKey(keyId);
      filteredLogs = filteredLogs.filter(log => log.keyId === maskedKeyId);
    }

    return {
      period: { startDate, endDate },
      totalEvents: filteredLogs.length,
      eventsByType: this.groupByEventType(filteredLogs),
      keyActivity: this.groupByKey(filteredLogs),
      userActivity: this.groupByUser(filteredLogs)
    };
  }

  groupByEventType(logs) {
    const grouped = {};
    logs.forEach(log => {
      grouped[log.event] = (grouped[log.event] || 0) + 1;
    });
    return grouped;
  }

  maskKey(key) {
    return key.slice(0, 4) + '***' + key.slice(-4);
  }
}

// Usage
const auditLogger = new APIKeyAuditLogger();

// Log key events
auditLogger.logKeyEvent('KEY_CREATED', keyId, userId, { service: 'stripe' });
auditLogger.logKeyEvent('KEY_USED', keyId, userId, { endpoint: '/api/customers' });
auditLogger.logKeyEvent('KEY_ROTATED', keyId, userId, { reason: 'scheduled' });
auditLogger.logKeyEvent('KEY_REVOKED', keyId, userId, { reason: 'security_breach' });
```

## Emergency Procedures

### Key Compromise Response
```javascript
class KeyCompromiseHandler {
  constructor(keyManager, auditLogger, notificationService) {
    this.keyManager = keyManager;
    this.auditLogger = auditLogger;
    this.notificationService = notificationService;
  }

  async handleKeyCompromise(keyId, compromiseReason, reportedBy) {
    console.log(`SECURITY ALERT: Key compromise detected for ${keyId}`);
    
    try {
      // Step 1: Immediate key revocation
      await this.keyManager.revokeKey(keyId);
      
      // Step 2: Log the incident
      this.auditLogger.logKeyEvent('KEY_COMPROMISED', keyId, reportedBy, {
        reason: compromiseReason,
        responseTime: new Date()
      });
      
      // Step 3: Generate replacement key
      const newKeyId = await this.keyManager.generateReplacementKey(keyId);
      
      // Step 4: Notify stakeholders
      await this.notifyKeyCompromise(keyId, newKeyId, compromiseReason);
      
      // Step 5: Update dependent systems
      await this.updateDependentSystems(keyId, newKeyId);
      
      return {
        oldKeyId: keyId,
        newKeyId: newKeyId,
        revokedAt: new Date(),
        status: 'handled'
      };
      
    } catch (error) {
      console.error('Error handling key compromise:', error);
      await this.escalateIncident(keyId, error);
      throw error;
    }
  }

  async notifyKeyCompromise(oldKeyId, newKeyId, reason) {
    const message = {
      type: 'SECURITY_INCIDENT',
      title: 'API Key Compromise Detected',
      details: {
        compromisedKey: this.maskKey(oldKeyId),
        replacementKey: this.maskKey(newKeyId),
        reason: reason,
        timestamp: new Date()
      },
      urgency: 'HIGH'
    };

    await this.notificationService.sendEmergencyAlert(message);
  }

  async escalateIncident(keyId, error) {
    const escalationMessage = {
      type: 'ESCALATION',
      title: 'Key Compromise Response Failed',
      details: {
        keyId: this.maskKey(keyId),
        error: error.message,
        timestamp: new Date()
      },
      urgency: 'CRITICAL'
    };

    await this.notificationService.escalate(escalationMessage);
  }

  maskKey(key) {
    return key.slice(0, 4) + '***' + key.slice(-4);
  }
}
```

### Disaster Recovery
```javascript
class KeyDisasterRecovery {
  constructor() {
    this.backupStrategies = new Map();
    this.recoveryProcedures = new Map();
  }

  registerBackupStrategy(service, strategy) {
    this.backupStrategies.set(service, strategy);
  }

  async createKeyBackup(service, keys) {
    const strategy = this.backupStrategies.get(service);
    if (!strategy) {
      throw new Error(`No backup strategy for service: ${service}`);
    }

    const backup = {
      service,
      timestamp: new Date(),
      keyCount: keys.length,
      checksum: this.generateChecksum(keys),
      encrypted: await strategy.encrypt(keys)
    };

    await this.storeBackup(backup);
    return backup;
  }

  async recoverKeys(service, backupId) {
    const backup = await this.retrieveBackup(backupId);
    const strategy = this.backupStrategies.get(service);
    
    if (!strategy) {
      throw new Error(`No recovery strategy for service: ${service}`);
    }

    const keys = await strategy.decrypt(backup.encrypted);
    
    // Validate checksum
    if (this.generateChecksum(keys) !== backup.checksum) {
      throw new Error('Backup integrity check failed');
    }

    return keys;
  }

  generateChecksum(keys) {
    const crypto = require('crypto');
    const combined = keys.map(k => k.keyId + k.value).join('');
    return crypto.createHash('sha256').update(combined).digest('hex');
  }
}
```

## Resources and Tools

### Popular Key Management Services
- **AWS Secrets Manager** - Cloud-native secret management
- **Azure Key Vault** - Microsoft's key and secret management service
- **HashiCorp Vault** - Multi-cloud secret management platform
- **Google Secret Manager** - Google Cloud's secret management service

### Security Scanning Tools
- **GitLeaks** - Scan git repos for secrets
- **TruffleHog** - Search for high entropy strings and secrets
- **SecretScanner** - Generic secret detection in code

### Monitoring and Alerting
- **Datadog** - APM with API key monitoring capabilities
- **New Relic** - Application monitoring with custom alerts
- **Sentry** - Error tracking with security event monitoring

### Best Practices Checklist
- [ ] Never hardcode API keys in source code
- [ ] Use environment variables or secure vaults
- [ ] Implement key rotation schedules
- [ ] Monitor key usage and set up alerts
- [ ] Use least privilege principles for key scopes
- [ ] Maintain audit logs for all key operations
- [ ] Test keys regularly with automated validation
- [ ] Have emergency revocation procedures ready
- [ ] Encrypt keys at rest and in transit
- [ ] Separate keys by environment (dev/staging/prod)

### Code Review Guidelines
```javascript
// Code review checklist for API key security
const codeReviewChecklist = {
  antiPatterns: [
    'Hardcoded keys in source files',
    'API keys in git history',
    'Production keys in development',
    'Keys in client-side JavaScript',
    'Unencrypted key storage',
    'No key rotation mechanism',
    'Missing key validation',
    'No usage monitoring'
  ],
  
  bestPractices: [
    'Environment variable usage',
    'Secure key storage implementation',
    'Proper error handling for auth failures',
    'Key masking in logs',
    'Rate limiting implementation',
    'Key validation before use',
    'Monitoring and alerting setup',
    'Documentation of key management procedures'
  ]
};
```