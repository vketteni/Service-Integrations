# Rate Limiting and Error Handling Primer

## Overview
Rate limiting and error handling are critical components of robust API integrations. Rate limiting prevents overwhelming services with too many requests, while proper error handling ensures graceful degradation and recovery from failures. This primer covers strategies for implementing both defensive and proactive approaches to API reliability.

## Rate Limiting Fundamentals

### Why Rate Limiting Matters
- **Service Protection**: Prevents overwhelming third-party APIs
- **Cost Management**: Avoids unexpected charges from usage-based pricing
- **SLA Compliance**: Ensures you stay within contracted limits
- **Fair Usage**: Prevents one feature from monopolizing API quotas
- **Graceful Degradation**: Maintains service functionality under constraints

### Common Rate Limiting Patterns

#### 1. Token Bucket Algorithm
```javascript
class TokenBucket {
  constructor(capacity, refillRate, refillInterval = 1000) {
    this.capacity = capacity;
    this.tokens = capacity;
    this.refillRate = refillRate;
    this.refillInterval = refillInterval;
    this.lastRefill = Date.now();
    
    this.startRefilling();
  }

  consume(tokens = 1) {
    this.refill();
    
    if (this.tokens >= tokens) {
      this.tokens -= tokens;
      return true;
    }
    
    return false;
  }

  refill() {
    const now = Date.now();
    const timePassed = now - this.lastRefill;
    const tokensToAdd = Math.floor(timePassed / this.refillInterval) * this.refillRate;
    
    this.tokens = Math.min(this.capacity, this.tokens + tokensToAdd);
    this.lastRefill = now;
  }

  startRefilling() {
    setInterval(() => this.refill(), this.refillInterval);
  }

  availableTokens() {
    this.refill();
    return this.tokens;
  }
}

// Usage
const bucket = new TokenBucket(100, 10, 1000); // 100 capacity, 10 tokens/second

async function makeRateLimitedRequest(url) {
  if (!bucket.consume(1)) {
    throw new Error('Rate limit exceeded');
  }
  
  return await fetch(url);
}
```

#### 2. Fixed Window Counter
```javascript
class FixedWindowRateLimiter {
  constructor(maxRequests, windowSizeMs) {
    this.maxRequests = maxRequests;
    this.windowSizeMs = windowSizeMs;
    this.requests = new Map();
  }

  isAllowed(identifier) {
    const now = Date.now();
    const windowStart = Math.floor(now / this.windowSizeMs) * this.windowSizeMs;
    
    const key = `${identifier}:${windowStart}`;
    const requestCount = this.requests.get(key) || 0;
    
    if (requestCount >= this.maxRequests) {
      return {
        allowed: false,
        resetTime: windowStart + this.windowSizeMs,
        remaining: 0
      };
    }
    
    this.requests.set(key, requestCount + 1);
    
    // Cleanup old windows
    this.cleanup(windowStart);
    
    return {
      allowed: true,
      resetTime: windowStart + this.windowSizeMs,
      remaining: this.maxRequests - requestCount - 1
    };
  }

  cleanup(currentWindow) {
    for (const [key] of this.requests) {
      const [, windowStart] = key.split(':');
      if (parseInt(windowStart) < currentWindow) {
        this.requests.delete(key);
      }
    }
  }
}

// Usage
const limiter = new FixedWindowRateLimiter(100, 60000); // 100 requests per minute

function checkRateLimit(userId) {
  const result = limiter.isAllowed(userId);
  
  if (!result.allowed) {
    const resetIn = Math.ceil((result.resetTime - Date.now()) / 1000);
    throw new Error(`Rate limit exceeded. Resets in ${resetIn} seconds`);
  }
  
  return result;
}
```

#### 3. Sliding Window Log
```javascript
class SlidingWindowRateLimiter {
  constructor(maxRequests, windowSizeMs) {
    this.maxRequests = maxRequests;
    this.windowSizeMs = windowSizeMs;
    this.requests = new Map();
  }

  isAllowed(identifier) {
    const now = Date.now();
    const windowStart = now - this.windowSizeMs;
    
    // Get or create request log for identifier
    let requestLog = this.requests.get(identifier) || [];
    
    // Remove old requests outside window
    requestLog = requestLog.filter(timestamp => timestamp > windowStart);
    
    if (requestLog.length >= this.maxRequests) {
      return {
        allowed: false,
        retryAfter: requestLog[0] + this.windowSizeMs - now
      };
    }
    
    // Add current request
    requestLog.push(now);
    this.requests.set(identifier, requestLog);
    
    return {
      allowed: true,
      remaining: this.maxRequests - requestLog.length
    };
  }
}
```

#### 4. Exponential Backoff
```javascript
class ExponentialBackoff {
  constructor(baseDelay = 1000, maxDelay = 30000, maxRetries = 5) {
    this.baseDelay = baseDelay;
    this.maxDelay = maxDelay;
    this.maxRetries = maxRetries;
  }

  async execute(fn, context = '') {
    let attempt = 0;
    
    while (attempt <= this.maxRetries) {
      try {
        return await fn();
      } catch (error) {
        attempt++;
        
        if (attempt > this.maxRetries) {
          throw new Error(`Max retries exceeded for ${context}: ${error.message}`);
        }
        
        if (!this.isRetryableError(error)) {
          throw error;
        }
        
        const delay = this.calculateDelay(attempt);
        console.log(`Attempt ${attempt} failed for ${context}, retrying in ${delay}ms: ${error.message}`);
        
        await this.sleep(delay);
      }
    }
  }

  calculateDelay(attempt) {
    const delay = this.baseDelay * Math.pow(2, attempt - 1);
    const jitter = Math.random() * 0.1 * delay; // 10% jitter
    return Math.min(this.maxDelay, delay + jitter);
  }

  isRetryableError(error) {
    // Common retryable HTTP status codes
    const retryableStatusCodes = [408, 429, 500, 502, 503, 504];
    
    if (error.status && retryableStatusCodes.includes(error.status)) {
      return true;
    }
    
    // Network errors
    if (error.code === 'ECONNRESET' || error.code === 'ETIMEDOUT') {
      return true;
    }
    
    return false;
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Usage
const backoff = new ExponentialBackoff();

async function reliableApiCall() {
  return await backoff.execute(async () => {
    const response = await fetch('https://api.example.com/data');
    
    if (!response.ok) {
      const error = new Error(`HTTP ${response.status}: ${response.statusText}`);
      error.status = response.status;
      throw error;
    }
    
    return response.json();
  }, 'API data fetch');
}
```

## Platform-Specific Rate Limiting

### Stripe Rate Limiting
```javascript
class StripeRateLimiter {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.requestQueue = [];
    this.processing = false;
    this.rateLimit = {
      limit: 100,
      remaining: 100,
      resetTime: Date.now() + 1000
    };
  }

  async makeRequest(url, options = {}) {
    return new Promise((resolve, reject) => {
      this.requestQueue.push({ url, options, resolve, reject });
      this.processQueue();
    });
  }

  async processQueue() {
    if (this.processing || this.requestQueue.length === 0) {
      return;
    }

    this.processing = true;

    while (this.requestQueue.length > 0) {
      // Check if we need to wait for rate limit reset
      if (this.rateLimit.remaining <= 0) {
        const waitTime = this.rateLimit.resetTime - Date.now();
        if (waitTime > 0) {
          console.log(`Rate limit exceeded, waiting ${waitTime}ms`);
          await this.sleep(waitTime);
        }
      }

      const request = this.requestQueue.shift();
      
      try {
        const response = await this.executeRequest(request.url, request.options);
        request.resolve(response);
      } catch (error) {
        request.reject(error);
      }
    }

    this.processing = false;
  }

  async executeRequest(url, options) {
    try {
      const response = await fetch(url, {
        ...options,
        headers: {
          ...options.headers,
          'Authorization': `Bearer ${this.apiKey}`,
          'Stripe-Version': '2023-10-16'
        }
      });

      // Update rate limit info from response headers
      this.updateRateLimitInfo(response);

      if (!response.ok) {
        const errorData = await response.json();
        const error = new Error(errorData.error?.message || 'Stripe API error');
        error.status = response.status;
        error.type = errorData.error?.type;
        throw error;
      }

      return response.json();
    } catch (error) {
      if (error.status === 429) {
        // Rate limited, update our tracking
        this.rateLimit.remaining = 0;
        this.rateLimit.resetTime = Date.now() + 1000; // Wait 1 second
      }
      throw error;
    }
  }

  updateRateLimitInfo(response) {
    const remaining = response.headers.get('x-ratelimit-remaining');
    const resetTime = response.headers.get('x-ratelimit-reset');
    
    if (remaining !== null) {
      this.rateLimit.remaining = parseInt(remaining, 10);
    }
    
    if (resetTime !== null) {
      this.rateLimit.resetTime = parseInt(resetTime, 10) * 1000;
    }
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
```

### Google Analytics Rate Limiting
```javascript
class GoogleAnalyticsRateLimiter {
  constructor() {
    this.quotas = {
      queriesPerDay: { limit: 50000, used: 0, resetTime: this.getNextMidnight() },
      queriesPerSecond: { limit: 10, used: 0, resetTime: Date.now() + 1000 },
      concurrentRequests: { limit: 10, active: 0 }
    };
  }

  async makeAnalyticsRequest(requestFn) {
    // Check daily quota
    if (this.quotas.queriesPerDay.used >= this.quotas.queriesPerDay.limit) {
      const waitTime = this.quotas.queriesPerDay.resetTime - Date.now();
      throw new Error(`Daily quota exceeded. Resets in ${Math.ceil(waitTime / 1000 / 60 / 60)} hours`);
    }

    // Check per-second quota
    if (this.quotas.queriesPerSecond.used >= this.quotas.queriesPerSecond.limit) {
      const waitTime = this.quotas.queriesPerSecond.resetTime - Date.now();
      if (waitTime > 0) {
        await this.sleep(waitTime);
      }
      this.resetPerSecondQuota();
    }

    // Check concurrent requests
    if (this.quotas.concurrentRequests.active >= this.quotas.concurrentRequests.limit) {
      throw new Error('Too many concurrent requests');
    }

    this.quotas.concurrentRequests.active++;
    this.quotas.queriesPerSecond.used++;
    this.quotas.queriesPerDay.used++;

    try {
      const result = await requestFn();
      return result;
    } finally {
      this.quotas.concurrentRequests.active--;
    }
  }

  resetPerSecondQuota() {
    if (Date.now() >= this.quotas.queriesPerSecond.resetTime) {
      this.quotas.queriesPerSecond.used = 0;
      this.quotas.queriesPerSecond.resetTime = Date.now() + 1000;
    }
  }

  getNextMidnight() {
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    tomorrow.setHours(0, 0, 0, 0);
    return tomorrow.getTime();
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
```

### HubSpot Rate Limiting
```javascript
class HubSpotRateLimiter {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.buckets = {
      burst: new TokenBucket(100, 10, 10000), // 100 burst, refill 10 every 10s
      sustained: new TokenBucket(1000, 1000, 60000) // 1000 per minute
    };
  }

  async makeRequest(url, options = {}) {
    // Check both burst and sustained limits
    if (!this.buckets.burst.consume(1)) {
      throw new Error('Burst rate limit exceeded');
    }
    
    if (!this.buckets.sustained.consume(1)) {
      throw new Error('Sustained rate limit exceeded');
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers: {
          ...options.headers,
          'Authorization': `Bearer ${this.apiKey}`
        }
      });

      if (response.status === 429) {
        const retryAfter = response.headers.get('retry-after');
        const waitTime = retryAfter ? parseInt(retryAfter) * 1000 : 1000;
        
        throw new Error(`Rate limited by HubSpot. Retry after ${waitTime}ms`);
      }

      return response.json();
    } catch (error) {
      if (error.message.includes('Rate limited')) {
        // Return tokens since request failed due to rate limiting
        this.buckets.burst.tokens = Math.min(
          this.buckets.burst.capacity, 
          this.buckets.burst.tokens + 1
        );
        this.buckets.sustained.tokens = Math.min(
          this.buckets.sustained.capacity, 
          this.buckets.sustained.tokens + 1
        );
      }
      throw error;
    }
  }
}
```

## Error Handling Strategies

### Error Classification System
```javascript
class APIErrorHandler {
  constructor() {
    this.errorCategories = {
      TEMPORARY: 'temporary',
      PERMANENT: 'permanent',
      CLIENT: 'client',
      SERVER: 'server',
      NETWORK: 'network',
      RATE_LIMIT: 'rate_limit'
    };
    
    this.retryableCategories = [
      this.errorCategories.TEMPORARY,
      this.errorCategories.SERVER,
      this.errorCategories.NETWORK,
      this.errorCategories.RATE_LIMIT
    ];
  }

  categorizeError(error) {
    // HTTP status code based categorization
    if (error.status) {
      if (error.status >= 400 && error.status < 500) {
        if (error.status === 429) return this.errorCategories.RATE_LIMIT;
        if (error.status === 408) return this.errorCategories.TEMPORARY;
        return this.errorCategories.CLIENT;
      }
      
      if (error.status >= 500) {
        return this.errorCategories.SERVER;
      }
    }

    // Network error categorization
    if (error.code) {
      const networkErrors = ['ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND', 'ECONNREFUSED'];
      if (networkErrors.includes(error.code)) {
        return this.errorCategories.NETWORK;
      }
    }

    // Default to temporary for unknown errors
    return this.errorCategories.TEMPORARY;
  }

  isRetryable(error) {
    const category = this.categorizeError(error);
    return this.retryableCategories.includes(category);
  }

  getRetryDelay(error, attempt) {
    const category = this.categorizeError(error);
    
    switch (category) {
      case this.errorCategories.RATE_LIMIT:
        // Extract retry-after header if available
        const retryAfter = error.retryAfter || error.headers?.['retry-after'];
        if (retryAfter) {
          return parseInt(retryAfter) * 1000;
        }
        return Math.min(30000, 1000 * Math.pow(2, attempt)); // Cap at 30s
        
      case this.errorCategories.SERVER:
        return Math.min(60000, 2000 * Math.pow(2, attempt)); // Cap at 1min
        
      case this.errorCategories.NETWORK:
        return Math.min(10000, 500 * Math.pow(2, attempt)); // Cap at 10s
        
      default:
        return Math.min(30000, 1000 * Math.pow(2, attempt));
    }
  }

  formatErrorMessage(error, context) {
    const category = this.categorizeError(error);
    const timestamp = new Date().toISOString();
    
    return {
      timestamp,
      context,
      category,
      message: error.message,
      status: error.status,
      code: error.code,
      retryable: this.isRetryable(error),
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    };
  }
}

// Usage
const errorHandler = new APIErrorHandler();

async function robustApiCall(url, options, context = 'API call') {
  let attempt = 0;
  const maxRetries = 3;
  
  while (attempt <= maxRetries) {
    try {
      const response = await fetch(url, options);
      
      if (!response.ok) {
        const error = new Error(`HTTP ${response.status}: ${response.statusText}`);
        error.status = response.status;
        error.headers = response.headers;
        throw error;
      }
      
      return response.json();
    } catch (error) {
      const errorInfo = errorHandler.formatErrorMessage(error, context);
      console.error('API call failed:', errorInfo);
      
      if (attempt === maxRetries || !errorHandler.isRetryable(error)) {
        throw error;
      }
      
      const delay = errorHandler.getRetryDelay(error, attempt);
      console.log(`Retrying ${context} in ${delay}ms (attempt ${attempt + 1}/${maxRetries})`);
      
      await new Promise(resolve => setTimeout(resolve, delay));
      attempt++;
    }
  }
}
```

### Circuit Breaker Pattern
```javascript
class CircuitBreaker {
  constructor(options = {}) {
    this.failureThreshold = options.failureThreshold || 5;
    this.resetTimeout = options.resetTimeout || 60000;
    this.monitoringPeriod = options.monitoringPeriod || 120000;
    
    this.state = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN
    this.failureCount = 0;
    this.lastFailureTime = null;
    this.successCount = 0;
    this.requestCount = 0;
    
    this.stats = {
      requests: 0,
      successes: 0,
      failures: 0,
      rejections: 0
    };
    
    this.startMonitoring();
  }

  async execute(fn, context = 'function') {
    this.stats.requests++;
    this.requestCount++;
    
    if (this.state === 'OPEN') {
      if (Date.now() - this.lastFailureTime > this.resetTimeout) {
        this.state = 'HALF_OPEN';
        console.log(`Circuit breaker ${context} moving to HALF_OPEN state`);
      } else {
        this.stats.rejections++;
        throw new Error(`Circuit breaker is OPEN for ${context}`);
      }
    }
    
    try {
      const result = await fn();
      this.recordSuccess();
      return result;
    } catch (error) {
      this.recordFailure();
      throw error;
    }
  }

  recordSuccess() {
    this.stats.successes++;
    this.successCount++;
    this.failureCount = 0;
    
    if (this.state === 'HALF_OPEN') {
      this.state = 'CLOSED';
      console.log('Circuit breaker moving to CLOSED state after success');
    }
  }

  recordFailure() {
    this.stats.failures++;
    this.failureCount++;
    this.lastFailureTime = Date.now();
    
    if (this.failureCount >= this.failureThreshold) {
      this.state = 'OPEN';
      console.log(`Circuit breaker moving to OPEN state after ${this.failureCount} failures`);
    }
  }

  getStats() {
    const uptime = this.stats.requests > 0 ? 
      (this.stats.successes / this.stats.requests) * 100 : 100;
    
    return {
      state: this.state,
      uptime: uptime.toFixed(2) + '%',
      ...this.stats
    };
  }

  startMonitoring() {
    setInterval(() => {
      const stats = this.getStats();
      console.log(`Circuit breaker stats: ${JSON.stringify(stats)}`);
      
      // Reset counters for next monitoring period
      this.requestCount = 0;
      this.successCount = 0;
    }, this.monitoringPeriod);
  }

  reset() {
    this.state = 'CLOSED';
    this.failureCount = 0;
    this.successCount = 0;
    this.lastFailureTime = null;
    console.log('Circuit breaker manually reset to CLOSED state');
  }
}

// Usage
const circuitBreaker = new CircuitBreaker({
  failureThreshold: 3,
  resetTimeout: 30000
});

async function protectedApiCall() {
  return await circuitBreaker.execute(async () => {
    const response = await fetch('https://api.unreliable-service.com/data');
    
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }
    
    return response.json();
  }, 'unreliable-service');
}
```

### Comprehensive Request Manager
```javascript
class APIRequestManager {
  constructor(options = {}) {
    this.rateLimiter = options.rateLimiter || new TokenBucket(100, 10);
    this.circuitBreaker = options.circuitBreaker || new CircuitBreaker();
    this.errorHandler = options.errorHandler || new APIErrorHandler();
    this.retryConfig = {
      maxRetries: options.maxRetries || 3,
      baseDelay: options.baseDelay || 1000,
      maxDelay: options.maxDelay || 30000
    };
    
    this.requestQueue = [];
    this.activeRequests = new Map();
    this.processing = false;
  }

  async request(url, options = {}, context = 'API request') {
    const requestId = this.generateRequestId();
    
    return new Promise((resolve, reject) => {
      this.requestQueue.push({
        id: requestId,
        url,
        options,
        context,
        resolve,
        reject,
        timestamp: Date.now()
      });
      
      this.processQueue();
    });
  }

  async processQueue() {
    if (this.processing) return;
    
    this.processing = true;
    
    while (this.requestQueue.length > 0) {
      const request = this.requestQueue.shift();
      
      try {
        // Check if request has timed out in queue
        if (Date.now() - request.timestamp > 30000) {
          request.reject(new Error('Request timed out in queue'));
          continue;
        }
        
        // Rate limiting check
        if (!this.rateLimiter.consume(1)) {
          const waitTime = 1000; // Wait 1 second and retry
          await this.sleep(waitTime);
          this.requestQueue.unshift(request); // Put request back at front
          continue;
        }
        
        const result = await this.executeRequest(request);
        request.resolve(result);
        
      } catch (error) {
        request.reject(error);
      }
    }
    
    this.processing = false;
  }

  async executeRequest(request) {
    const { id, url, options, context } = request;
    
    this.activeRequests.set(id, {
      url,
      context,
      startTime: Date.now()
    });
    
    try {
      const result = await this.circuitBreaker.execute(async () => {
        return await this.retryableRequest(url, options, context);
      }, context);
      
      return result;
    } finally {
      this.activeRequests.delete(id);
    }
  }

  async retryableRequest(url, options, context) {
    let attempt = 0;
    
    while (attempt <= this.retryConfig.maxRetries) {
      try {
        const response = await fetch(url, {
          ...options,
          timeout: options.timeout || 30000
        });
        
        if (!response.ok) {
          const error = new Error(`HTTP ${response.status}: ${response.statusText}`);
          error.status = response.status;
          error.headers = Object.fromEntries(response.headers.entries());
          throw error;
        }
        
        return response.json();
      } catch (error) {
        if (attempt === this.retryConfig.maxRetries || !this.errorHandler.isRetryable(error)) {
          throw error;
        }
        
        const delay = this.errorHandler.getRetryDelay(error, attempt);
        console.log(`${context} failed (attempt ${attempt + 1}), retrying in ${delay}ms:`, error.message);
        
        await this.sleep(delay);
        attempt++;
      }
    }
  }

  generateRequestId() {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  getStats() {
    return {
      queueLength: this.requestQueue.length,
      activeRequests: this.activeRequests.size,
      rateLimiter: {
        tokens: this.rateLimiter.availableTokens(),
        capacity: this.rateLimiter.capacity
      },
      circuitBreaker: this.circuitBreaker.getStats()
    };
  }

  getActiveRequests() {
    const now = Date.now();
    const active = [];
    
    for (const [id, request] of this.activeRequests) {
      active.push({
        id,
        url: request.url,
        context: request.context,
        duration: now - request.startTime
      });
    }
    
    return active;
  }
}

// Usage example
const requestManager = new APIRequestManager({
  rateLimiter: new TokenBucket(50, 5), // 50 tokens, 5 per second
  circuitBreaker: new CircuitBreaker({ failureThreshold: 3 }),
  maxRetries: 3,
  baseDelay: 1000
});

// Make requests through the manager
async function fetchUserData(userId) {
  return await requestManager.request(
    `https://api.example.com/users/${userId}`,
    {
      headers: { 'Authorization': 'Bearer token' }
    },
    `fetch user ${userId}`
  );
}
```

## Monitoring and Alerting

### Request Analytics
```javascript
class RequestAnalytics {
  constructor() {
    this.metrics = {
      requests: new Map(),
      errors: new Map(),
      responseTime: [],
      rateLimits: []
    };
    
    this.startReporting();
  }

  recordRequest(url, duration, status, error = null) {
    const endpoint = this.normalizeUrl(url);
    const minute = Math.floor(Date.now() / 60000);
    
    // Count requests per endpoint per minute
    const requestKey = `${endpoint}:${minute}`;
    const currentCount = this.metrics.requests.get(requestKey) || 0;
    this.metrics.requests.set(requestKey, currentCount + 1);
    
    // Record response time
    this.metrics.responseTime.push({ timestamp: Date.now(), duration, endpoint });
    
    // Record errors
    if (error) {
      const errorKey = `${endpoint}:${status}:${minute}`;
      const errorCount = this.metrics.errors.get(errorKey) || 0;
      this.metrics.errors.set(errorKey, errorCount + 1);
    }
    
    // Keep only recent data (last hour)
    this.cleanupOldData();
  }

  recordRateLimit(endpoint, resetTime, remaining) {
    this.metrics.rateLimits.push({
      timestamp: Date.now(),
      endpoint,
      resetTime,
      remaining
    });
  }

  normalizeUrl(url) {
    try {
      const urlObj = new URL(url);
      // Remove query parameters and normalize path
      const pathParts = urlObj.pathname.split('/');
      
      // Replace IDs with placeholders
      const normalizedParts = pathParts.map(part => {
        if (/^\d+$/.test(part) || /^[a-f0-9-]{36}$/.test(part)) {
          return ':id';
        }
        return part;
      });
      
      return `${urlObj.hostname}${normalizedParts.join('/')}`;
    } catch (error) {
      return 'invalid-url';
    }
  }

  getMetrics(timeRangeMinutes = 60) {
    const cutoff = Date.now() - (timeRangeMinutes * 60000);
    
    // Aggregate request counts
    const requestCounts = {};
    for (const [key, count] of this.metrics.requests) {
      const [endpoint, minute] = key.split(':');
      const timestamp = parseInt(minute) * 60000;
      
      if (timestamp >= cutoff) {
        requestCounts[endpoint] = (requestCounts[endpoint] || 0) + count;
      }
    }
    
    // Aggregate error counts
    const errorCounts = {};
    for (const [key, count] of this.metrics.errors) {
      const [endpoint, status, minute] = key.split(':');
      const timestamp = parseInt(minute) * 60000;
      
      if (timestamp >= cutoff) {
        const errorKey = `${endpoint}:${status}`;
        errorCounts[errorKey] = (errorCounts[errorKey] || 0) + count;
      }
    }
    
    // Calculate average response times
    const responseTimes = {};
    const recentResponseTimes = this.metrics.responseTime.filter(
      rt => rt.timestamp >= cutoff
    );
    
    for (const rt of recentResponseTimes) {
      if (!responseTimes[rt.endpoint]) {
        responseTimes[rt.endpoint] = { sum: 0, count: 0 };
      }
      responseTimes[rt.endpoint].sum += rt.duration;
      responseTimes[rt.endpoint].count += 1;
    }
    
    for (const endpoint in responseTimes) {
      const stats = responseTimes[endpoint];
      responseTimes[endpoint] = Math.round(stats.sum / stats.count);
    }
    
    return {
      timeRange: `${timeRangeMinutes} minutes`,
      requests: requestCounts,
      errors: errorCounts,
      averageResponseTime: responseTimes,
      rateLimits: this.metrics.rateLimits.filter(rl => rl.timestamp >= cutoff)
    };
  }

  cleanupOldData() {
    const cutoff = Date.now() - (60 * 60000); // 1 hour ago
    
    // Cleanup requests
    for (const [key] of this.metrics.requests) {
      const [, minute] = key.split(':');
      if (parseInt(minute) * 60000 < cutoff) {
        this.metrics.requests.delete(key);
      }
    }
    
    // Cleanup errors
    for (const [key] of this.metrics.errors) {
      const [, , minute] = key.split(':');
      if (parseInt(minute) * 60000 < cutoff) {
        this.metrics.errors.delete(key);
      }
    }
    
    // Cleanup response times
    this.metrics.responseTime = this.metrics.responseTime.filter(
      rt => rt.timestamp >= cutoff
    );
    
    // Cleanup rate limits
    this.metrics.rateLimits = this.metrics.rateLimits.filter(
      rl => rl.timestamp >= cutoff
    );
  }

  startReporting() {
    // Report metrics every 5 minutes
    setInterval(() => {
      const metrics = this.getMetrics();
      console.log('API Metrics:', JSON.stringify(metrics, null, 2));
      
      // Send to monitoring service
      this.sendToMonitoring(metrics);
    }, 300000); // 5 minutes
  }

  sendToMonitoring(metrics) {
    // Integration with monitoring services
    // DataDog, New Relic, CloudWatch, etc.
  }
}

// Integration with request manager
const analytics = new RequestAnalytics();

// Wrap fetch to automatically track metrics
const originalFetch = fetch;
global.fetch = async function(url, options = {}) {
  const startTime = Date.now();
  let response;
  let error;
  
  try {
    response = await originalFetch(url, options);
  } catch (err) {
    error = err;
    throw err;
  } finally {
    const duration = Date.now() - startTime;
    analytics.recordRequest(
      url,
      duration,
      response?.status || 0,
      error
    );
  }
  
  return response;
};
```

## Testing Rate Limiting and Error Handling

### Test Framework
```javascript
class RateLimitTester {
  constructor() {
    this.testResults = [];
  }

  async testRateLimit(rateLimiter, requestsPerSecond, durationSeconds) {
    const totalRequests = requestsPerSecond * durationSeconds;
    const interval = 1000 / requestsPerSecond;
    
    console.log(`Testing rate limiter: ${requestsPerSecond} req/s for ${durationSeconds}s`);
    
    const results = {
      totalRequests,
      allowedRequests: 0,
      rejectedRequests: 0,
      timestamps: []
    };
    
    for (let i = 0; i < totalRequests; i++) {
      const startTime = Date.now();
      
      try {
        if (rateLimiter.consume ? rateLimiter.consume(1) : rateLimiter.isAllowed('test').allowed) {
          results.allowedRequests++;
          results.timestamps.push(startTime);
        } else {
          results.rejectedRequests++;
        }
      } catch (error) {
        results.rejectedRequests++;
      }
      
      // Wait for next request
      if (i < totalRequests - 1) {
        await this.sleep(interval);
      }
    }
    
    results.actualRate = results.allowedRequests / durationSeconds;
    results.successRate = (results.allowedRequests / totalRequests) * 100;
    
    this.testResults.push(results);
    return results;
  }

  async testErrorHandling(handler, errorScenarios) {
    const results = [];
    
    for (const scenario of errorScenarios) {
      console.log(`Testing error scenario: ${scenario.name}`);
      
      const mockFunction = async () => {
        throw scenario.error;
      };
      
      const startTime = Date.now();
      let result;
      let finalError;
      
      try {
        result = await handler.execute(mockFunction, scenario.name);
      } catch (error) {
        finalError = error;
      }
      
      const duration = Date.now() - startTime;
      
      results.push({
        scenario: scenario.name,
        expectedRetryable: scenario.expectedRetryable,
        actualRetryable: handler.isRetryableError ? handler.isRetryableError(scenario.error) : false,
        duration,
        succeeded: !!result,
        finalError: finalError?.message
      });
    }
    
    return results;
  }

  async testCircuitBreaker(circuitBreaker, failureCount, recoveryTest = true) {
    const results = {
      initialState: circuitBreaker.state,
      failuresSent: 0,
      stateTransitions: []
    };
    
    // Record state changes
    const originalRecordFailure = circuitBreaker.recordFailure.bind(circuitBreaker);
    const originalRecordSuccess = circuitBreaker.recordSuccess.bind(circuitBreaker);
    
    circuitBreaker.recordFailure = function() {
      const oldState = this.state;
      originalRecordFailure();
      if (oldState !== this.state) {
        results.stateTransitions.push({
          from: oldState,
          to: this.state,
          timestamp: Date.now()
        });
      }
    };
    
    circuitBreaker.recordSuccess = function() {
      const oldState = this.state;
      originalRecordSuccess();
      if (oldState !== this.state) {
        results.stateTransitions.push({
          from: oldState,
          to: this.state,
          timestamp: Date.now()
        });
      }
    };
    
    // Send failures to trigger OPEN state
    for (let i = 0; i < failureCount; i++) {
      try {
        await circuitBreaker.execute(() => {
          throw new Error('Test failure');
        });
      } catch (error) {
        results.failuresSent++;
      }
    }
    
    results.stateAfterFailures = circuitBreaker.state;
    
    // Test recovery if requested
    if (recoveryTest && circuitBreaker.state === 'OPEN') {
      // Wait for reset timeout
      console.log('Waiting for circuit breaker reset...');
      await this.sleep(circuitBreaker.resetTimeout + 100);
      
      // Try a successful request
      try {
        await circuitBreaker.execute(() => Promise.resolve('success'));
        results.recoverySucceeded = true;
      } catch (error) {
        results.recoverySucceeded = false;
        results.recoveryError = error.message;
      }
      
      results.finalState = circuitBreaker.state;
    }
    
    return results;
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  generateReport() {
    return {
      timestamp: new Date().toISOString(),
      rateLimitTests: this.testResults,
      summary: {
        totalTests: this.testResults.length,
        averageSuccessRate: this.testResults.reduce((sum, test) => sum + test.successRate, 0) / this.testResults.length
      }
    };
  }
}

// Jest test examples
describe('Rate Limiting and Error Handling', () => {
  const tester = new RateLimitTester();
  
  test('Token bucket should limit requests correctly', async () => {
    const bucket = new TokenBucket(10, 5, 1000); // 10 capacity, 5 per second
    
    const result = await tester.testRateLimit(bucket, 10, 2);
    
    expect(result.allowedRequests).toBeLessThanOrEqual(20); // 10 initial + 10 refilled
    expect(result.rejectedRequests).toBeGreaterThan(0);
  });
  
  test('Error handler should categorize errors correctly', () => {
    const handler = new APIErrorHandler();
    
    const rateLimitError = { status: 429 };
    const serverError = { status: 500 };
    const clientError = { status: 404 };
    
    expect(handler.categorizeError(rateLimitError)).toBe('rate_limit');
    expect(handler.categorizeError(serverError)).toBe('server');
    expect(handler.categorizeError(clientError)).toBe('client');
    
    expect(handler.isRetryable(rateLimitError)).toBe(true);
    expect(handler.isRetryable(serverError)).toBe(true);
    expect(handler.isRetryable(clientError)).toBe(false);
  });
  
  test('Circuit breaker should open after threshold failures', async () => {
    const circuitBreaker = new CircuitBreaker({ failureThreshold: 3 });
    
    const result = await tester.testCircuitBreaker(circuitBreaker, 5, false);
    
    expect(result.initialState).toBe('CLOSED');
    expect(result.stateAfterFailures).toBe('OPEN');
    expect(result.stateTransitions).toHaveLength(1);
    expect(result.stateTransitions[0].to).toBe('OPEN');
  });
});
```

## Best Practices

### Configuration Management
```javascript
const rateLimitingConfig = {
  // Service-specific configurations
  stripe: {
    requestsPerSecond: 25,
    burstCapacity: 100,
    retryConfig: {
      maxRetries: 3,
      baseDelay: 1000,
      maxDelay: 30000
    }
  },
  
  googleAnalytics: {
    requestsPerSecond: 10,
    requestsPerDay: 50000,
    concurrentRequests: 10,
    retryConfig: {
      maxRetries: 2,
      baseDelay: 2000,
      maxDelay: 60000
    }
  },
  
  hubspot: {
    burstCapacity: 100,
    sustainedRate: 1000, // per minute
    retryConfig: {
      maxRetries: 5,
      baseDelay: 1000,
      maxDelay: 32000
    }
  },
  
  // Global defaults
  default: {
    requestsPerSecond: 10,
    burstCapacity: 50,
    retryConfig: {
      maxRetries: 3,
      baseDelay: 1000,
      maxDelay: 30000
    },
    circuitBreaker: {
      failureThreshold: 5,
      resetTimeout: 60000
    }
  }
};
```

### Common Pitfalls to Avoid
```javascript
// ❌ BAD: Not handling rate limit headers
async function badRequest() {
  const response = await fetch(url);
  return response.json(); // Ignores rate limit info
}

// ✅ GOOD: Reading and respecting rate limit headers
async function goodRequest() {
  const response = await fetch(url);
  
  // Update rate limiter based on headers
  const remaining = response.headers.get('x-ratelimit-remaining');
  const resetTime = response.headers.get('x-ratelimit-reset');
  
  if (remaining !== null && parseInt(remaining) < 5) {
    console.warn('Approaching rate limit');
  }
  
  return response.json();
}

// ❌ BAD: Retrying all errors indefinitely
async function badRetry() {
  let attempts = 0;
  while (attempts < 100) { // Too many attempts
    try {
      return await apiCall();
    } catch (error) {
      attempts++;
      await sleep(1000); // Fixed delay, retries client errors
    }
  }
}

// ✅ GOOD: Smart retry with categorization
async function goodRetry() {
  const errorHandler = new APIErrorHandler();
  let attempt = 0;
  const maxRetries = 3;
  
  while (attempt <= maxRetries) {
    try {
      return await apiCall();
    } catch (error) {
      if (!errorHandler.isRetryable(error) || attempt === maxRetries) {
        throw error;
      }
      
      const delay = errorHandler.getRetryDelay(error, attempt);
      await sleep(delay);
      attempt++;
    }
  }
}
```

## Resources

### Documentation and Standards
- [HTTP Status Codes](https://httpstatuses.com/)
- [RFC 6585 - Additional HTTP Status Codes](https://tools.ietf.org/html/rfc6585)
- [Rate Limiting Patterns](https://cloud.google.com/architecture/rate-limiting-strategies-techniques)

### Libraries and Tools
- **Rate Limiting**: `express-rate-limit`, `bottleneck`, `limiter`
- **Circuit Breakers**: `opossum`, `cockatiel`
- **Retry Logic**: `async-retry`, `retry`, `p-retry`
- **Monitoring**: `prom-client`, `statsd-client`, `datadog-metrics`

### Service-Specific Documentation
- [Stripe Rate Limits](https://stripe.com/docs/rate-limits)
- [Google Analytics Quotas](https://developers.google.com/analytics/devguides/reporting/core/v4/limits-quotas)
- [HubSpot Rate Limits](https://developers.hubspot.com/docs/api/usage-details)
- [Salesforce API Limits](https://developer.salesforce.com/docs/atlas.en-us.salesforce_app_limits_cheatsheet.meta/salesforce_app_limits_cheatsheet/salesforce_app_limits_platform_api.htm)