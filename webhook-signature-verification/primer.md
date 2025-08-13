# Webhook Signature Verification Primer

## Overview
Webhook signature verification is a security mechanism that ensures webhook payloads are authentic and haven't been tampered with during transmission. By verifying cryptographic signatures, you can confirm that webhooks actually come from the claimed sender and reject potentially malicious requests.

## Why Webhook Verification Matters

### Security Risks Without Verification
- **Spoofing**: Attackers can send fake webhooks to your endpoints
- **Data Tampering**: Malicious actors can modify webhook payloads
- **Replay Attacks**: Old webhook payloads can be resent maliciously
- **Unauthorized Access**: Unverified webhooks can trigger unwanted actions

### Benefits of Signature Verification
- **Authenticity**: Confirm webhooks come from the expected sender
- **Integrity**: Ensure payload hasn't been modified in transit
- **Non-repudiation**: Proof that the sender actually sent the webhook
- **Protection**: Guard against malicious webhook injection attacks

## Common Signature Methods

### HMAC (Hash-based Message Authentication Code)
Most popular method using shared secrets:

```javascript
const crypto = require('crypto');

// Generate HMAC signature
function generateHMAC(payload, secret, algorithm = 'sha256') {
  return crypto
    .createHmac(algorithm, secret)
    .update(payload, 'utf8')
    .digest('hex');
}

// Verify HMAC signature
function verifyHMAC(payload, signature, secret, algorithm = 'sha256') {
  const expectedSignature = generateHMAC(payload, secret, algorithm);
  return crypto.timingSafeEqual(
    Buffer.from(signature, 'hex'),
    Buffer.from(expectedSignature, 'hex')
  );
}
```

### Digital Signatures (RSA/ECDSA)
Using public-key cryptography:

```javascript
const crypto = require('crypto');

// Verify RSA signature
function verifyRSASignature(payload, signature, publicKey) {
  const verifier = crypto.createVerify('sha256');
  verifier.update(payload, 'utf8');
  verifier.end();
  
  return verifier.verify(publicKey, signature, 'base64');
}

// Verify ECDSA signature
function verifyECDSASignature(payload, signature, publicKey) {
  const verifier = crypto.createVerify('sha256');
  verifier.update(payload, 'utf8');
  verifier.end();
  
  return verifier.verify({
    key: publicKey,
    format: 'pem',
    type: 'spki'
  }, signature, 'base64');
}
```

## Platform-Specific Implementations

### Stripe Webhooks
Stripe uses HMAC-SHA256 with a timestamp for replay protection:

```javascript
const stripe = require('stripe')('sk_test_...');

function verifyStripeWebhook(payload, signature, endpointSecret) {
  try {
    // Stripe's library handles signature verification and replay protection
    const event = stripe.webhooks.constructEvent(
      payload,
      signature,
      endpointSecret
    );
    return event;
  } catch (err) {
    console.error('Stripe webhook signature verification failed:', err.message);
    throw new Error('Invalid signature');
  }
}

// Manual Stripe verification
function verifyStripeWebhookManual(payload, signature, secret) {
  const elements = signature.split(',');
  const signatureElements = {};
  
  elements.forEach(element => {
    const [key, value] = element.split('=');
    signatureElements[key] = value;
  });
  
  const timestamp = signatureElements.t;
  const signatures = [signatureElements.v1]; // v1 is HMAC-SHA256
  
  // Check timestamp (prevent replay attacks)
  const currentTime = Math.floor(Date.now() / 1000);
  const tolerance = 300; // 5 minutes
  
  if (currentTime - timestamp > tolerance) {
    throw new Error('Timestamp outside tolerance');
  }
  
  // Construct signed payload
  const signedPayload = timestamp + '.' + payload;
  
  // Verify signature
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(signedPayload, 'utf8')
    .digest('hex');
  
  const isValid = signatures.some(sig => 
    crypto.timingSafeEqual(
      Buffer.from(sig, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    )
  );
  
  if (!isValid) {
    throw new Error('Invalid signature');
  }
  
  return JSON.parse(payload);
}

// Express middleware
const verifyStripeSignature = (req, res, next) => {
  const signature = req.headers['stripe-signature'];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
  
  try {
    const event = verifyStripeWebhook(req.body, signature, endpointSecret);
    req.stripeEvent = event;
    next();
  } catch (error) {
    return res.status(400).json({ error: 'Webhook signature verification failed' });
  }
};
```

### GitHub Webhooks
GitHub uses HMAC-SHA256 with X-Hub-Signature-256 header:

```javascript
function verifyGitHubWebhook(payload, signature, secret) {
  const hmac = crypto.createHmac('sha256', secret);
  const digest = 'sha256=' + hmac.update(payload, 'utf8').digest('hex');
  
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest))) {
    throw new Error('Invalid GitHub webhook signature');
  }
  
  return JSON.parse(payload);
}

// Express middleware for GitHub webhooks
const verifyGitHubSignature = (req, res, next) => {
  const signature = req.headers['x-hub-signature-256'];
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  
  if (!signature) {
    return res.status(400).json({ error: 'Missing signature header' });
  }
  
  try {
    verifyGitHubWebhook(req.body, signature, secret);
    next();
  } catch (error) {
    return res.status(400).json({ error: 'Invalid signature' });
  }
};
```

### HubSpot Webhooks
HubSpot uses HMAC-SHA256 with source hash:

```javascript
function verifyHubSpotWebhook(requestBody, signature, clientSecret) {
  const sourceString = requestBody + clientSecret;
  const hash = crypto.createHash('sha256').update(sourceString).digest('hex');
  
  if (hash !== signature) {
    throw new Error('Invalid HubSpot webhook signature');
  }
  
  return JSON.parse(requestBody);
}

// HubSpot webhook verification middleware
const verifyHubSpotSignature = (req, res, next) => {
  const signature = req.headers['x-hubspot-signature'];
  const clientSecret = process.env.HUBSPOT_CLIENT_SECRET;
  
  try {
    verifyHubSpotWebhook(req.body, signature, clientSecret);
    next();
  } catch (error) {
    return res.status(400).json({ error: 'Invalid HubSpot signature' });
  }
};
```

### Salesforce Webhooks (Outbound Messages)
Salesforce uses digital certificates for verification:

```javascript
const forge = require('node-forge');

function verifySalesforceWebhook(payload, signature, certificate) {
  try {
    // Parse the certificate
    const cert = forge.pki.certificateFromPem(certificate);
    const publicKey = cert.publicKey;
    
    // Create message digest
    const md = forge.md.sha256.create();
    md.update(payload, 'utf8');
    
    // Verify signature
    const signatureBytes = forge.util.decode64(signature);
    const isValid = publicKey.verify(md.digest().bytes(), signatureBytes);
    
    if (!isValid) {
      throw new Error('Invalid Salesforce signature');
    }
    
    return payload;
  } catch (error) {
    throw new Error('Salesforce webhook verification failed: ' + error.message);
  }
}
```

### PayPal Webhooks
PayPal uses certificate-based verification:

```javascript
function verifyPayPalWebhook(headers, body, webhookId) {
  // PayPal provides an SDK for verification
  const paypal = require('paypal-rest-sdk');
  
  const certId = headers['paypal-cert-id'];
  const signature = headers['paypal-signature'];
  const timestamp = headers['paypal-transmission-time'];
  const authAlgo = headers['paypal-auth-algo'];
  
  return new Promise((resolve, reject) => {
    paypal.notification.webhookEvent.verify({
      auth_algo: authAlgo,
      cert_id: certId,
      signature: signature,
      transmission_id: headers['paypal-transmission-id'],
      transmission_time: timestamp,
      webhook_id: webhookId,
      webhook_event: body
    }, (error, response) => {
      if (error || response.verification_status !== 'SUCCESS') {
        reject(new Error('PayPal webhook verification failed'));
      } else {
        resolve(body);
      }
    });
  });
}
```

## Generic Webhook Verification Framework

### Configurable Verification System
```javascript
class WebhookVerifier {
  constructor() {
    this.verifiers = new Map();
    this.defaultConfig = {
      timestampTolerance: 300, // 5 minutes
      algorithm: 'sha256',
      encoding: 'hex'
    };
  }

  registerVerifier(provider, config) {
    this.verifiers.set(provider, {
      ...this.defaultConfig,
      ...config
    });
  }

  async verify(provider, payload, headers, secret) {
    const config = this.verifiers.get(provider);
    if (!config) {
      throw new Error(`No verifier registered for provider: ${provider}`);
    }

    try {
      return await this.performVerification(config, payload, headers, secret);
    } catch (error) {
      throw new Error(`Webhook verification failed for ${provider}: ${error.message}`);
    }
  }

  async performVerification(config, payload, headers, secret) {
    // Extract signature from headers
    const signature = this.extractSignature(config, headers);
    
    // Check timestamp if required
    if (config.timestampHeader) {
      this.verifyTimestamp(config, headers);
    }
    
    // Perform signature verification
    switch (config.method) {
      case 'hmac':
        return this.verifyHMAC(config, payload, signature, secret);
      case 'rsa':
        return this.verifyRSA(config, payload, signature, secret);
      case 'ecdsa':
        return this.verifyECDSA(config, payload, signature, secret);
      default:
        throw new Error(`Unsupported verification method: ${config.method}`);
    }
  }

  extractSignature(config, headers) {
    const signature = headers[config.signatureHeader.toLowerCase()];
    if (!signature) {
      throw new Error(`Missing signature header: ${config.signatureHeader}`);
    }

    // Handle different signature formats
    if (config.signaturePrefix) {
      if (!signature.startsWith(config.signaturePrefix)) {
        throw new Error('Invalid signature format');
      }
      return signature.slice(config.signaturePrefix.length);
    }

    return signature;
  }

  verifyTimestamp(config, headers) {
    const timestamp = headers[config.timestampHeader.toLowerCase()];
    if (!timestamp) {
      throw new Error('Missing timestamp header');
    }

    const currentTime = Math.floor(Date.now() / 1000);
    const webhookTime = parseInt(timestamp, 10);
    
    if (Math.abs(currentTime - webhookTime) > config.timestampTolerance) {
      throw new Error('Webhook timestamp outside tolerance window');
    }
  }

  verifyHMAC(config, payload, signature, secret) {
    let data = payload;
    
    // Some providers include timestamp in signed data
    if (config.includeTimestamp && config.timestampHeader) {
      const timestamp = headers[config.timestampHeader.toLowerCase()];
      data = timestamp + '.' + payload;
    }
    
    const expectedSignature = crypto
      .createHmac(config.algorithm, secret)
      .update(data, 'utf8')
      .digest(config.encoding);
    
    if (!crypto.timingSafeEqual(
      Buffer.from(signature, config.encoding),
      Buffer.from(expectedSignature, config.encoding)
    )) {
      throw new Error('HMAC signature verification failed');
    }
    
    return JSON.parse(payload);
  }

  verifyRSA(config, payload, signature, publicKey) {
    const verifier = crypto.createVerify(config.algorithm);
    verifier.update(payload, 'utf8');
    verifier.end();
    
    const isValid = verifier.verify(publicKey, signature, 'base64');
    if (!isValid) {
      throw new Error('RSA signature verification failed');
    }
    
    return JSON.parse(payload);
  }

  verifyECDSA(config, payload, signature, publicKey) {
    const verifier = crypto.createVerify(config.algorithm);
    verifier.update(payload, 'utf8');
    verifier.end();
    
    const isValid = verifier.verify({
      key: publicKey,
      format: 'pem',
      type: 'spki'
    }, signature, 'base64');
    
    if (!isValid) {
      throw new Error('ECDSA signature verification failed');
    }
    
    return JSON.parse(payload);
  }
}

// Usage example
const verifier = new WebhookVerifier();

// Register different providers
verifier.registerVerifier('stripe', {
  method: 'hmac',
  algorithm: 'sha256',
  signatureHeader: 'stripe-signature',
  timestampHeader: null, // Stripe handles timestamps in signature
  includeTimestamp: true,
  signaturePrefix: null
});

verifier.registerVerifier('github', {
  method: 'hmac',
  algorithm: 'sha256',
  signatureHeader: 'x-hub-signature-256',
  signaturePrefix: 'sha256=',
  timestampTolerance: 300
});

verifier.registerVerifier('custom-service', {
  method: 'hmac',
  algorithm: 'sha256',
  signatureHeader: 'x-signature',
  timestampHeader: 'x-timestamp',
  timestampTolerance: 600
});
```

## Express.js Middleware Framework

### Universal Webhook Middleware
```javascript
const express = require('express');

function createWebhookMiddleware(options = {}) {
  const {
    provider,
    secret,
    secretHeader = null,
    rawBody = true,
    errorHandler = null
  } = options;

  return (req, res, next) => {
    // Ensure raw body is available
    if (rawBody && !req.rawBody) {
      let data = '';
      req.setEncoding('utf8');
      
      req.on('data', chunk => {
        data += chunk;
      });
      
      req.on('end', () => {
        req.rawBody = data;
        performVerification();
      });
    } else {
      performVerification();
    }

    function performVerification() {
      try {
        const webhookSecret = secretHeader ? 
          req.headers[secretHeader.toLowerCase()] : secret;
        
        if (!webhookSecret) {
          throw new Error('Webhook secret not found');
        }

        const payload = req.rawBody || req.body;
        const verifiedPayload = verifier.verify(
          provider, 
          payload, 
          req.headers, 
          webhookSecret
        );
        
        req.verifiedWebhook = verifiedPayload;
        next();
      } catch (error) {
        if (errorHandler) {
          return errorHandler(error, req, res, next);
        }
        
        res.status(400).json({
          error: 'Webhook verification failed',
          message: error.message
        });
      }
    }
  };
}

// Usage examples
const app = express();

// Stripe webhook endpoint
app.post('/webhooks/stripe',
  express.raw({ type: 'application/json' }),
  createWebhookMiddleware({
    provider: 'stripe',
    secret: process.env.STRIPE_WEBHOOK_SECRET
  }),
  (req, res) => {
    const event = req.verifiedWebhook;
    console.log('Stripe event:', event.type);
    res.json({ received: true });
  }
);

// GitHub webhook endpoint
app.post('/webhooks/github',
  express.json(),
  createWebhookMiddleware({
    provider: 'github',
    secret: process.env.GITHUB_WEBHOOK_SECRET
  }),
  (req, res) => {
    const payload = req.verifiedWebhook;
    console.log('GitHub event:', payload.action);
    res.json({ received: true });
  }
);
```

## Advanced Security Features

### Replay Attack Prevention
```javascript
class ReplayProtection {
  constructor(windowSizeMs = 300000) { // 5 minutes default
    this.processedWebhooks = new Set();
    this.windowSize = windowSizeMs;
    this.cleanup();
  }

  checkReplay(webhookId, timestamp) {
    const now = Date.now();
    const webhookTime = new Date(timestamp).getTime();
    
    // Check if webhook is within time window
    if (now - webhookTime > this.windowSize) {
      throw new Error('Webhook outside of acceptable time window');
    }
    
    // Create unique identifier for this webhook
    const uniqueId = `${webhookId}-${timestamp}`;
    
    if (this.processedWebhooks.has(uniqueId)) {
      throw new Error('Duplicate webhook detected (replay attack)');
    }
    
    this.processedWebhooks.add(uniqueId);
    return true;
  }

  cleanup() {
    // Periodically clean up old webhook IDs
    setInterval(() => {
      const cutoff = Date.now() - this.windowSize;
      for (const id of this.processedWebhooks) {
        const [, timestampStr] = id.split('-');
        const timestamp = new Date(timestampStr).getTime();
        
        if (timestamp < cutoff) {
          this.processedWebhooks.delete(id);
        }
      }
    }, this.windowSize / 2); // Cleanup every half window
  }
}

const replayProtection = new ReplayProtection();

// Integration with webhook verification
function verifyWithReplayProtection(payload, headers, secret) {
  // First verify signature
  const verified = verifyWebhookSignature(payload, headers, secret);
  
  // Then check for replay
  const webhookId = headers['webhook-id'] || headers['x-webhook-id'];
  const timestamp = headers['timestamp'] || headers['x-timestamp'];
  
  if (webhookId && timestamp) {
    replayProtection.checkReplay(webhookId, timestamp);
  }
  
  return verified;
}
```

### Rate Limiting for Webhooks
```javascript
class WebhookRateLimiter {
  constructor(maxRequests = 100, windowMs = 60000) {
    this.requests = new Map();
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
  }

  checkRateLimit(identifier) {
    const now = Date.now();
    const windowStart = now - this.windowMs;
    
    if (!this.requests.has(identifier)) {
      this.requests.set(identifier, []);
    }
    
    const requestTimes = this.requests.get(identifier);
    
    // Remove old requests outside window
    const validRequests = requestTimes.filter(time => time > windowStart);
    
    if (validRequests.length >= this.maxRequests) {
      throw new Error(`Rate limit exceeded for ${identifier}`);
    }
    
    // Add current request
    validRequests.push(now);
    this.requests.set(identifier, validRequests);
    
    return true;
  }
}

const rateLimiter = new WebhookRateLimiter();

// Rate limiting middleware
function webhookRateLimit(req, res, next) {
  const identifier = req.ip; // or extract from headers/auth
  
  try {
    rateLimiter.checkRateLimit(identifier);
    next();
  } catch (error) {
    res.status(429).json({
      error: 'Too many webhook requests',
      retryAfter: 60
    });
  }
}
```

### Webhook Logging and Monitoring
```javascript
class WebhookLogger {
  constructor(options = {}) {
    this.logLevel = options.logLevel || 'info';
    this.logPayloads = options.logPayloads || false;
    this.sensitiveFields = options.sensitiveFields || ['password', 'token', 'key'];
  }

  logWebhook(event, provider, headers, payload, status = 'received') {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      provider,
      status,
      headers: this.sanitizeHeaders(headers),
      payloadSize: payload ? Buffer.byteLength(payload, 'utf8') : 0,
      userAgent: headers['user-agent'],
      sourceIP: headers['x-forwarded-for'] || headers['x-real-ip']
    };

    if (this.logPayloads && payload) {
      logEntry.payload = this.sanitizePayload(payload);
    }

    console.log(`[WEBHOOK] ${JSON.stringify(logEntry)}`);
    
    // Send to monitoring service
    this.sendToMonitoring(logEntry);
  }

  sanitizeHeaders(headers) {
    const sanitized = { ...headers };
    
    // Remove sensitive headers
    delete sanitized['authorization'];
    delete sanitized['x-api-key'];
    
    // Mask signature headers (keep prefix for debugging)
    Object.keys(sanitized).forEach(key => {
      if (key.includes('signature') || key.includes('auth')) {
        const value = sanitized[key];
        sanitized[key] = value.length > 10 ? 
          value.substring(0, 10) + '...' : '***';
      }
    });
    
    return sanitized;
  }

  sanitizePayload(payload) {
    try {
      const parsed = JSON.parse(payload);
      return this.redactSensitiveFields(parsed);
    } catch (error) {
      return '[INVALID_JSON]';
    }
  }

  redactSensitiveFields(obj) {
    if (typeof obj !== 'object' || obj === null) {
      return obj;
    }

    const redacted = Array.isArray(obj) ? [] : {};
    
    for (const [key, value] of Object.entries(obj)) {
      if (this.sensitiveFields.some(field => 
        key.toLowerCase().includes(field.toLowerCase())
      )) {
        redacted[key] = '[REDACTED]';
      } else if (typeof value === 'object') {
        redacted[key] = this.redactSensitiveFields(value);
      } else {
        redacted[key] = value;
      }
    }
    
    return redacted;
  }

  sendToMonitoring(logEntry) {
    // Integration with monitoring services
    // DataDog, New Relic, CloudWatch, etc.
  }
}

// Usage with middleware
const logger = new WebhookLogger({ 
  logPayloads: process.env.NODE_ENV !== 'production',
  logLevel: 'debug'
});

function loggingMiddleware(provider) {
  return (req, res, next) => {
    logger.logWebhook('received', provider, req.headers, req.body);
    
    // Override res.json to log responses
    const originalJson = res.json;
    res.json = function(body) {
      logger.logWebhook('response', provider, req.headers, JSON.stringify(body), 'sent');
      return originalJson.call(this, body);
    };
    
    next();
  };
}
```

## Testing Webhook Verification

### Test Framework
```javascript
const crypto = require('crypto');

class WebhookTester {
  constructor() {
    this.testSecrets = {
      stripe: 'whsec_test_secret',
      github: 'github_test_secret',
      hubspot: 'hubspot_test_secret'
    };
  }

  generateTestWebhook(provider, payload, options = {}) {
    const secret = options.secret || this.testSecrets[provider];
    const timestamp = options.timestamp || Math.floor(Date.now() / 1000);
    
    switch (provider) {
      case 'stripe':
        return this.generateStripeTestWebhook(payload, secret, timestamp);
      case 'github':
        return this.generateGitHubTestWebhook(payload, secret);
      case 'hubspot':
        return this.generateHubSpotTestWebhook(payload, secret);
      default:
        throw new Error(`Unknown provider: ${provider}`);
    }
  }

  generateStripeTestWebhook(payload, secret, timestamp) {
    const signedPayload = timestamp + '.' + payload;
    const signature = crypto
      .createHmac('sha256', secret)
      .update(signedPayload, 'utf8')
      .digest('hex');

    return {
      headers: {
        'stripe-signature': `t=${timestamp},v1=${signature}`
      },
      body: payload
    };
  }

  generateGitHubTestWebhook(payload, secret) {
    const signature = 'sha256=' + crypto
      .createHmac('sha256', secret)
      .update(payload, 'utf8')
      .digest('hex');

    return {
      headers: {
        'x-hub-signature-256': signature,
        'x-github-event': 'push'
      },
      body: payload
    };
  }

  generateHubSpotTestWebhook(payload, secret) {
    const sourceString = payload + secret;
    const signature = crypto
      .createHash('sha256')
      .update(sourceString)
      .digest('hex');

    return {
      headers: {
        'x-hubspot-signature': signature
      },
      body: payload
    };
  }

  testVerification(provider, webhook, options = {}) {
    const secret = options.secret || this.testSecrets[provider];
    
    try {
      const result = verifier.verify(
        provider,
        webhook.body,
        webhook.headers,
        secret
      );
      
      return {
        success: true,
        result: result
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }
}

// Jest test examples
describe('Webhook Verification', () => {
  const tester = new WebhookTester();

  test('should verify valid Stripe webhook', () => {
    const payload = JSON.stringify({ type: 'payment_intent.succeeded' });
    const webhook = tester.generateTestWebhook('stripe', payload);
    const result = tester.testVerification('stripe', webhook);
    
    expect(result.success).toBe(true);
    expect(result.result.type).toBe('payment_intent.succeeded');
  });

  test('should reject invalid signature', () => {
    const payload = JSON.stringify({ type: 'payment_intent.succeeded' });
    const webhook = tester.generateTestWebhook('stripe', payload);
    
    // Tamper with signature
    webhook.headers['stripe-signature'] = 'invalid_signature';
    
    const result = tester.testVerification('stripe', webhook);
    expect(result.success).toBe(false);
    expect(result.error).toContain('signature');
  });

  test('should reject old timestamps', () => {
    const payload = JSON.stringify({ type: 'payment_intent.succeeded' });
    const oldTimestamp = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
    
    const webhook = tester.generateTestWebhook('stripe', payload, {
      timestamp: oldTimestamp
    });
    
    const result = tester.testVerification('stripe', webhook);
    expect(result.success).toBe(false);
    expect(result.error).toContain('timestamp');
  });
});
```

## Best Practices

### Security Checklist
```javascript
const securityChecklist = {
  verification: [
    'Always verify webhook signatures',
    'Use timing-safe comparison functions',
    'Validate timestamp to prevent replay attacks',
    'Use HTTPS for all webhook endpoints',
    'Store webhook secrets securely (environment variables)'
  ],
  
  implementation: [
    'Parse JSON only after signature verification',
    'Implement proper error handling and logging',
    'Use raw body for signature calculation',
    'Set appropriate timeouts for webhook processing',
    'Implement idempotency for webhook handlers'
  ],
  
  monitoring: [
    'Log all webhook verification attempts',
    'Monitor for unusual patterns or failures',
    'Set up alerts for verification failures',
    'Track webhook processing performance',
    'Audit webhook endpoint access'
  ]
};
```

### Common Pitfalls to Avoid
```javascript
// ❌ BAD: Using string comparison for signatures
function badVerify(signature1, signature2) {
  return signature1 === signature2; // Vulnerable to timing attacks
}

// ✅ GOOD: Using timing-safe comparison
function goodVerify(signature1, signature2) {
  return crypto.timingSafeEqual(
    Buffer.from(signature1, 'hex'),
    Buffer.from(signature2, 'hex')
  );
}

// ❌ BAD: Modifying body before verification
app.post('/webhook', express.json(), (req, res) => {
  // Body has been parsed and potentially modified
  const signature = calculateSignature(JSON.stringify(req.body));
  // This will likely fail verification
});

// ✅ GOOD: Using raw body for verification
app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  // Body is still in original form
  const signature = calculateSignature(req.body);
  // Verification will work correctly
});

// ❌ BAD: Not handling verification errors
app.post('/webhook', (req, res) => {
  verifySignature(req.body, req.headers.signature);
  // Process webhook...
  res.json({ status: 'ok' });
});

// ✅ GOOD: Proper error handling
app.post('/webhook', (req, res) => {
  try {
    verifySignature(req.body, req.headers.signature);
    // Process webhook...
    res.json({ status: 'ok' });
  } catch (error) {
    console.error('Webhook verification failed:', error);
    res.status(400).json({ error: 'Invalid signature' });
  }
});
```

## Resources

### Documentation Links
- [Stripe Webhooks](https://stripe.com/docs/webhooks/signatures)
- [GitHub Webhooks](https://docs.github.com/en/developers/webhooks-and-events/webhooks/securing-your-webhooks)
- [PayPal Webhooks](https://developer.paypal.com/docs/api/webhooks/v1/#verify-webhook-signature)
- [Shopify Webhooks](https://shopify.dev/docs/apps/webhooks/configuration/https#step-5-verify-the-webhook)

### Security Resources
- [OWASP Webhook Security](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [RFC 2104 - HMAC Specification](https://tools.ietf.org/html/rfc2104)
- [Timing Attack Prevention](https://en.wikipedia.org/wiki/Timing_attack)

### Libraries and Tools
- **Node.js**: `crypto` (built-in), `node-forge`, `jsonwebtoken`
- **Testing**: `jest`, `supertest`, `nock`
- **Monitoring**: `pino`, `winston`, `datadog-metrics`
- **Rate Limiting**: `express-rate-limit`, `bottleneck`