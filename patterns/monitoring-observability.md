# Monitoring and Observability for Service Integrations

## Overview
Effective monitoring and observability are crucial for maintaining reliable service integrations. This primer covers comprehensive strategies for tracking API health, performance metrics, error patterns, and business KPIs across multiple service integrations.

## The Three Pillars of Observability

### 1. Metrics (What is happening?)
Quantitative measurements over time:
- Request rates, error rates, latencies
- Business metrics (conversions, revenue)
- Resource utilization (CPU, memory, network)

### 2. Logs (What happened?)
Discrete events with context:
- API request/response logs
- Error messages and stack traces
- Business event logs

### 3. Traces (Why did it happen?)
Request flow across distributed systems:
- End-to-end request tracing
- Service dependency mapping
- Performance bottleneck identification

## Metrics Collection Framework

### API Metrics Collector
```javascript
class APIMetricsCollector {
  constructor(options = {}) {
    this.metrics = new Map();
    this.intervals = new Map();
    this.reporters = options.reporters || [];
    this.collectionInterval = options.interval || 60000; // 1 minute
    
    this.startCollection();
  }

  recordAPICall(service, endpoint, duration, statusCode, error = null) {
    const key = `${service}:${endpoint}`;
    
    if (!this.metrics.has(key)) {
      this.metrics.set(key, {
        service,
        endpoint,
        totalRequests: 0,
        successfulRequests: 0,
        failedRequests: 0,
        totalDuration: 0,
        minDuration: Infinity,
        maxDuration: 0,
        statusCodes: new Map(),
        errors: new Map(),
        lastReset: Date.now()
      });
    }
    
    const metric = this.metrics.get(key);
    
    // Update request counts
    metric.totalRequests++;
    if (statusCode >= 200 && statusCode < 300) {
      metric.successfulRequests++;
    } else {
      metric.failedRequests++;
    }
    
    // Update duration metrics
    metric.totalDuration += duration;
    metric.minDuration = Math.min(metric.minDuration, duration);
    metric.maxDuration = Math.max(metric.maxDuration, duration);
    
    // Track status codes
    const statusCount = metric.statusCodes.get(statusCode) || 0;
    metric.statusCodes.set(statusCode, statusCount + 1);
    
    // Track errors
    if (error) {
      const errorCount = metric.errors.get(error.type || 'unknown') || 0;
      metric.errors.set(error.type || 'unknown', errorCount + 1);
    }
  }

  recordBusinessMetric(name, value, tags = {}) {
    const key = `business:${name}`;
    const timestamp = Date.now();
    
    if (!this.metrics.has(key)) {
      this.metrics.set(key, {
        name,
        type: 'business',
        values: [],
        tags: new Map()
      });
    }
    
    const metric = this.metrics.get(key);
    metric.values.push({ value, timestamp, tags });
    
    // Keep only recent values (last hour)
    const cutoff = timestamp - (60 * 60 * 1000);
    metric.values = metric.values.filter(v => v.timestamp >= cutoff);
  }

  calculateDerivedMetrics() {
    const derived = new Map();
    
    for (const [key, metric] of this.metrics) {
      if (metric.endpoint) { // API metrics
        const avgDuration = metric.totalRequests > 0 ? 
          metric.totalDuration / metric.totalRequests : 0;
        
        const errorRate = metric.totalRequests > 0 ? 
          (metric.failedRequests / metric.totalRequests) * 100 : 0;
        
        const requestRate = this.calculateRequestRate(metric);
        
        derived.set(key, {
          ...metric,
          averageDuration: avgDuration,
          errorRate,
          requestRate,
          availability: ((metric.successfulRequests / metric.totalRequests) * 100) || 100
        });
      }
    }
    
    return derived;
  }

  calculateRequestRate(metric) {
    const timeSpan = Date.now() - metric.lastReset;
    const timeSpanMinutes = timeSpan / (1000 * 60);
    return timeSpanMinutes > 0 ? metric.totalRequests / timeSpanMinutes : 0;
  }

  async reportMetrics() {
    const derivedMetrics = this.calculateDerivedMetrics();
    
    for (const reporter of this.reporters) {
      try {
        await reporter.report(derivedMetrics);
      } catch (error) {
        console.error('Failed to report metrics:', error);
      }
    }
    
    // Reset metrics after reporting
    this.resetMetrics();
  }

  resetMetrics() {
    for (const [key, metric] of this.metrics) {
      if (metric.endpoint) {
        metric.totalRequests = 0;
        metric.successfulRequests = 0;
        metric.failedRequests = 0;
        metric.totalDuration = 0;
        metric.minDuration = Infinity;
        metric.maxDuration = 0;
        metric.statusCodes.clear();
        metric.errors.clear();
        metric.lastReset = Date.now();
      }
    }
  }

  startCollection() {
    const interval = setInterval(() => {
      this.reportMetrics();
    }, this.collectionInterval);
    
    this.intervals.set('reporting', interval);
  }

  stop() {
    for (const interval of this.intervals.values()) {
      clearInterval(interval);
    }
    this.intervals.clear();
  }
}
```

### Business Metrics Tracking
```javascript
class BusinessMetricsTracker {
  constructor(services) {
    this.services = services;
    this.metricsCollector = new APIMetricsCollector();
  }

  // E-commerce metrics
  async trackConversion(userId, orderId, value, currency = 'USD') {
    this.metricsCollector.recordBusinessMetric('conversion', value, {
      userId,
      orderId,
      currency,
      timestamp: Date.now()
    });

    // Also send to analytics services
    await this.services.analytics.track('purchase', {
      user_id: userId,
      order_id: orderId,
      revenue: value,
      currency
    });
  }

  // SaaS metrics
  async trackSubscription(userId, planId, mrr, event = 'new') {
    this.metricsCollector.recordBusinessMetric('subscription_mrr', mrr, {
      userId,
      planId,
      event, // new, upgrade, downgrade, churn
      timestamp: Date.now()
    });

    // Update customer success metrics in CRM
    await this.services.hubspot.updateContact(userId, {
      subscription_status: event === 'churn' ? 'Cancelled' : 'Active',
      monthly_recurring_revenue: mrr,
      plan_id: planId
    });
  }

  // Customer health metrics
  async trackCustomerHealth(customerId, healthScore, factors) {
    this.metricsCollector.recordBusinessMetric('customer_health', healthScore, {
      customerId,
      factors: JSON.stringify(factors),
      timestamp: Date.now()
    });

    // Trigger alerts for low health scores
    if (healthScore < 50) {
      await this.triggerCustomerRiskAlert(customerId, healthScore, factors);
    }
  }

  async calculateAggregateMetrics() {
    // Calculate key business metrics
    const metrics = {};
    
    // MRR calculation
    const mrrMetrics = Array.from(this.metricsCollector.metrics.values())
      .filter(m => m.name === 'subscription_mrr')
      .flatMap(m => m.values);
    
    metrics.totalMRR = mrrMetrics
      .filter(v => v.tags.event !== 'churn')
      .reduce((sum, v) => sum + v.value, 0);

    metrics.churnedMRR = mrrMetrics
      .filter(v => v.tags.event === 'churn')
      .reduce((sum, v) => sum + v.value, 0);

    metrics.netMRR = metrics.totalMRR - metrics.churnedMRR;

    // Conversion metrics
    const conversionMetrics = Array.from(this.metricsCollector.metrics.values())
      .filter(m => m.name === 'conversion')
      .flatMap(m => m.values);

    metrics.totalRevenue = conversionMetrics.reduce((sum, v) => sum + v.value, 0);
    metrics.totalOrders = conversionMetrics.length;
    metrics.averageOrderValue = metrics.totalOrders > 0 ? 
      metrics.totalRevenue / metrics.totalOrders : 0;

    return metrics;
  }
}
```

## Distributed Tracing

### Request Tracing Framework
```javascript
class DistributedTracer {
  constructor(options = {}) {
    this.serviceName = options.serviceName || 'unknown-service';
    this.traces = new Map();
    this.spans = new Map();
    this.samplingRate = options.samplingRate || 1.0; // 100% by default
  }

  startTrace(operationName, parentSpanId = null) {
    const traceId = parentSpanId ? this.extractTraceId(parentSpanId) : this.generateTraceId();
    const spanId = this.generateSpanId();
    
    const span = {
      traceId,
      spanId,
      parentSpanId,
      operationName,
      serviceName: this.serviceName,
      startTime: Date.now(),
      endTime: null,
      duration: null,
      tags: new Map(),
      logs: [],
      status: 'active'
    };
    
    this.spans.set(spanId, span);
    
    if (!parentSpanId) {
      this.traces.set(traceId, {
        traceId,
        rootSpanId: spanId,
        spans: [spanId],
        startTime: Date.now(),
        status: 'active'
      });
    } else {
      const trace = this.traces.get(traceId);
      if (trace) {
        trace.spans.push(spanId);
      }
    }
    
    return spanId;
  }

  finishSpan(spanId, error = null) {
    const span = this.spans.get(spanId);
    if (!span) return;
    
    span.endTime = Date.now();
    span.duration = span.endTime - span.startTime;
    span.status = error ? 'error' : 'completed';
    
    if (error) {
      span.tags.set('error', true);
      span.tags.set('error.message', error.message);
      span.logs.push({
        timestamp: Date.now(),
        level: 'error',
        message: error.message,
        stack: error.stack
      });
    }
    
    // Check if this completes the trace
    const traceId = span.traceId;
    const trace = this.traces.get(traceId);
    if (trace && span.spanId === trace.rootSpanId) {
      this.finishTrace(traceId);
    }
  }

  addSpanTag(spanId, key, value) {
    const span = this.spans.get(spanId);
    if (span) {
      span.tags.set(key, value);
    }
  }

  addSpanLog(spanId, logData) {
    const span = this.spans.get(spanId);
    if (span) {
      span.logs.push({
        timestamp: Date.now(),
        ...logData
      });
    }
  }

  finishTrace(traceId) {
    const trace = this.traces.get(traceId);
    if (!trace) return;
    
    trace.endTime = Date.now();
    trace.duration = trace.endTime - trace.startTime;
    trace.status = 'completed';
    
    // Calculate trace statistics
    const traceSpans = trace.spans.map(spanId => this.spans.get(spanId));
    trace.totalSpans = traceSpans.length;
    trace.errorSpans = traceSpans.filter(s => s.status === 'error').length;
    trace.hasErrors = trace.errorSpans > 0;
    
    // Send to tracing backend if sampled
    if (this.shouldSample()) {
      this.exportTrace(trace);
    }
    
    // Cleanup
    this.cleanupTrace(traceId);
  }

  shouldSample() {
    return Math.random() < this.samplingRate;
  }

  async exportTrace(trace) {
    // Export to tracing backend (Jaeger, Zipkin, etc.)
    const traceData = {
      traceId: trace.traceId,
      spans: trace.spans.map(spanId => this.spans.get(spanId)),
      duration: trace.duration,
      hasErrors: trace.hasErrors,
      serviceName: this.serviceName
    };
    
    // Send to tracing service
    console.log('Exporting trace:', JSON.stringify(traceData, null, 2));
  }

  cleanupTrace(traceId) {
    const trace = this.traces.get(traceId);
    if (trace) {
      // Remove spans
      trace.spans.forEach(spanId => this.spans.delete(spanId));
      // Remove trace
      this.traces.delete(traceId);
    }
  }

  generateTraceId() {
    return crypto.randomBytes(16).toString('hex');
  }

  generateSpanId() {
    return crypto.randomBytes(8).toString('hex');
  }

  extractTraceId(spanId) {
    const span = this.spans.get(spanId);
    return span ? span.traceId : this.generateTraceId();
  }

  // Express middleware for automatic request tracing
  expressMiddleware() {
    return (req, res, next) => {
      const spanId = this.startTrace(`${req.method} ${req.path}`);
      
      this.addSpanTag(spanId, 'http.method', req.method);
      this.addSpanTag(spanId, 'http.url', req.url);
      this.addSpanTag(spanId, 'user.id', req.user?.id);
      
      req.spanId = spanId;
      
      // Finish span when response ends
      res.on('finish', () => {
        this.addSpanTag(spanId, 'http.status_code', res.statusCode);
        this.finishSpan(spanId, res.statusCode >= 400 ? new Error(`HTTP ${res.statusCode}`) : null);
      });
      
      next();
    };
  }
}
```

## Logging Strategy

### Structured Logging Framework
```javascript
class StructuredLogger {
  constructor(options = {}) {
    this.serviceName = options.serviceName || 'unknown-service';
    this.environment = options.environment || 'development';
    this.logLevel = options.logLevel || 'info';
    this.outputs = options.outputs || [console];
    
    this.logLevels = {
      error: 0,
      warn: 1,
      info: 2,
      debug: 3,
      trace: 4
    };
  }

  log(level, message, context = {}) {
    if (this.logLevels[level] > this.logLevels[this.logLevel]) {
      return; // Skip if below log level threshold
    }
    
    const logEntry = {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      service: this.serviceName,
      environment: this.environment,
      message,
      ...context,
      // Add trace context if available
      ...(context.traceId && { traceId: context.traceId }),
      ...(context.spanId && { spanId: context.spanId })
    };
    
    // Sanitize sensitive data
    this.sanitizeLogEntry(logEntry);
    
    // Send to configured outputs
    this.outputs.forEach(output => {
      if (output.write) {
        output.write(JSON.stringify(logEntry) + '\n');
      } else {
        output.log(logEntry);
      }
    });
  }

  error(message, context = {}) {
    this.log('error', message, context);
  }

  warn(message, context = {}) {
    this.log('warn', message, context);
  }

  info(message, context = {}) {
    this.log('info', message, context);
  }

  debug(message, context = {}) {
    this.log('debug', message, context);
  }

  // API request logging
  logAPIRequest(service, endpoint, method, duration, statusCode, error = null, context = {}) {
    const logContext = {
      api: {
        service,
        endpoint,
        method,
        duration,
        statusCode,
        success: statusCode >= 200 && statusCode < 300
      },
      ...context
    };
    
    if (error) {
      logContext.error = {
        message: error.message,
        type: error.constructor.name,
        stack: error.stack
      };
      
      this.error(`API request failed: ${method} ${endpoint}`, logContext);
    } else {
      this.info(`API request completed: ${method} ${endpoint}`, logContext);
    }
  }

  // Business event logging
  logBusinessEvent(eventType, eventData, context = {}) {
    this.info(`Business event: ${eventType}`, {
      businessEvent: {
        type: eventType,
        data: eventData
      },
      ...context
    });
  }

  sanitizeLogEntry(logEntry) {
    // Remove sensitive fields
    const sensitiveFields = ['password', 'token', 'apiKey', 'secret', 'ssn', 'creditCard'];
    
    const sanitize = (obj) => {
      if (typeof obj !== 'object' || obj === null) return;
      
      for (const key in obj) {
        if (sensitiveFields.some(field => key.toLowerCase().includes(field.toLowerCase()))) {
          obj[key] = '[REDACTED]';
        } else if (typeof obj[key] === 'object') {
          sanitize(obj[key]);
        }
      }
    };
    
    sanitize(logEntry);
  }

  // Create child logger with additional context
  child(additionalContext = {}) {
    return new ChildLogger(this, additionalContext);
  }
}

class ChildLogger {
  constructor(parentLogger, context = {}) {
    this.parent = parentLogger;
    this.context = context;
  }

  log(level, message, additionalContext = {}) {
    this.parent.log(level, message, { ...this.context, ...additionalContext });
  }

  error(message, context = {}) { this.log('error', message, context); }
  warn(message, context = {}) { this.log('warn', message, context); }
  info(message, context = {}) { this.log('info', message, context); }
  debug(message, context = {}) { this.log('debug', message, context); }

  logAPIRequest(service, endpoint, method, duration, statusCode, error = null, context = {}) {
    this.parent.logAPIRequest(service, endpoint, method, duration, statusCode, error, { ...this.context, ...context });
  }

  logBusinessEvent(eventType, eventData, context = {}) {
    this.parent.logBusinessEvent(eventType, eventData, { ...this.context, ...context });
  }
}
```

## Health Checks and Service Discovery

### Health Check Framework
```javascript
class HealthCheckManager {
  constructor() {
    this.checks = new Map();
    this.results = new Map();
    this.checkInterval = 30000; // 30 seconds
    this.running = false;
  }

  registerCheck(name, checkFunction, options = {}) {
    this.checks.set(name, {
      name,
      check: checkFunction,
      timeout: options.timeout || 5000,
      critical: options.critical === true,
      tags: options.tags || [],
      interval: options.interval || this.checkInterval
    });
  }

  async runCheck(checkConfig) {
    const startTime = Date.now();
    
    try {
      const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Health check timeout')), checkConfig.timeout)
      );
      
      const checkPromise = checkConfig.check();
      
      const result = await Promise.race([checkPromise, timeoutPromise]);
      
      return {
        name: checkConfig.name,
        status: 'healthy',
        duration: Date.now() - startTime,
        result: result || {},
        timestamp: new Date().toISOString(),
        tags: checkConfig.tags
      };
    } catch (error) {
      return {
        name: checkConfig.name,
        status: 'unhealthy',
        duration: Date.now() - startTime,
        error: error.message,
        timestamp: new Date().toISOString(),
        tags: checkConfig.tags,
        critical: checkConfig.critical
      };
    }
  }

  async runAllChecks() {
    const checkPromises = Array.from(this.checks.values()).map(check => this.runCheck(check));
    const results = await Promise.all(checkPromises);
    
    // Store results
    results.forEach(result => {
      this.results.set(result.name, result);
    });
    
    // Calculate overall health
    const overallHealth = this.calculateOverallHealth(results);
    
    return {
      status: overallHealth.status,
      timestamp: new Date().toISOString(),
      checks: results,
      summary: overallHealth.summary
    };
  }

  calculateOverallHealth(results) {
    const totalChecks = results.length;
    const healthyChecks = results.filter(r => r.status === 'healthy').length;
    const criticalFailures = results.filter(r => r.status === 'unhealthy' && r.critical).length;
    
    let status = 'healthy';
    if (criticalFailures > 0) {
      status = 'critical';
    } else if (healthyChecks < totalChecks) {
      status = 'degraded';
    }
    
    return {
      status,
      summary: {
        total: totalChecks,
        healthy: healthyChecks,
        unhealthy: totalChecks - healthyChecks,
        critical: criticalFailures
      }
    };
  }

  start() {
    if (this.running) return;
    
    this.running = true;
    this.interval = setInterval(async () => {
      try {
        await this.runAllChecks();
      } catch (error) {
        console.error('Error running health checks:', error);
      }
    }, this.checkInterval);
  }

  stop() {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
    this.running = false;
  }

  // Express endpoint for health checks
  expressEndpoint() {
    return async (req, res) => {
      const health = await this.runAllChecks();
      
      let statusCode = 200;
      if (health.status === 'critical') statusCode = 503;
      else if (health.status === 'degraded') statusCode = 200; // Still operational
      
      res.status(statusCode).json(health);
    };
  }
}

// Common health checks
class CommonHealthChecks {
  static databaseConnection(db) {
    return async () => {
      const result = await db.query('SELECT 1');
      return { connected: true, result: result.rows[0] };
    };
  }

  static redisConnection(redis) {
    return async () => {
      const result = await redis.ping();
      return { connected: true, response: result };
    };
  }

  static externalServiceHealth(serviceName, healthUrl) {
    return async () => {
      const response = await fetch(healthUrl, { timeout: 3000 });
      if (!response.ok) {
        throw new Error(`${serviceName} returned ${response.status}`);
      }
      return { service: serviceName, status: response.status };
    };
  }

  static diskSpace(threshold = 0.9) {
    return async () => {
      const fs = require('fs');
      const stats = fs.statSync('/');
      const used = stats.size - stats.free;
      const usageRatio = used / stats.size;
      
      if (usageRatio > threshold) {
        throw new Error(`Disk usage ${(usageRatio * 100).toFixed(1)}% exceeds threshold ${(threshold * 100)}%`);
      }
      
      return { 
        diskUsage: `${(usageRatio * 100).toFixed(1)}%`,
        available: `${(stats.free / 1024 / 1024 / 1024).toFixed(2)} GB`
      };
    };
  }

  static memoryUsage(threshold = 0.9) {
    return async () => {
      const usage = process.memoryUsage();
      const totalMemory = require('os').totalmem();
      const usageRatio = usage.rss / totalMemory;
      
      if (usageRatio > threshold) {
        throw new Error(`Memory usage ${(usageRatio * 100).toFixed(1)}% exceeds threshold ${(threshold * 100)}%`);
      }
      
      return {
        memoryUsage: `${(usageRatio * 100).toFixed(1)}%`,
        rss: `${(usage.rss / 1024 / 1024).toFixed(2)} MB`,
        heapUsed: `${(usage.heapUsed / 1024 / 1024).toFixed(2)} MB`
      };
    };
  }
}
```

## Alerting and Incident Response

### Alert Manager
```javascript
class AlertManager {
  constructor(options = {}) {
    this.rules = new Map();
    this.alertHistory = [];
    this.cooldownPeriods = new Map();
    this.notificationChannels = options.channels || [];
  }

  addRule(name, condition, severity, options = {}) {
    this.rules.set(name, {
      name,
      condition,
      severity, // info, warning, critical
      description: options.description || '',
      cooldown: options.cooldown || 300000, // 5 minutes default
      channels: options.channels || this.notificationChannels,
      enabled: options.enabled !== false,
      metadata: options.metadata || {}
    });
  }

  async evaluateRules(metrics) {
    const alerts = [];
    
    for (const [ruleName, rule] of this.rules) {
      if (!rule.enabled) continue;
      
      // Check cooldown
      if (this.isInCooldown(ruleName)) continue;
      
      try {
        const shouldAlert = await rule.condition(metrics);
        
        if (shouldAlert) {
          const alert = {
            id: this.generateAlertId(),
            rule: ruleName,
            severity: rule.severity,
            description: rule.description,
            timestamp: new Date().toISOString(),
            metrics: this.extractRelevantMetrics(metrics, rule),
            metadata: rule.metadata
          };
          
          alerts.push(alert);
          this.alertHistory.push(alert);
          
          // Set cooldown
          this.cooldownPeriods.set(ruleName, Date.now());
          
          // Send notifications
          await this.sendAlert(alert, rule.channels);
        }
      } catch (error) {
        console.error(`Error evaluating rule ${ruleName}:`, error);
      }
    }
    
    return alerts;
  }

  isInCooldown(ruleName) {
    const rule = this.rules.get(ruleName);
    const lastAlert = this.cooldownPeriods.get(ruleName);
    
    if (!lastAlert || !rule.cooldown) return false;
    
    return (Date.now() - lastAlert) < rule.cooldown;
  }

  async sendAlert(alert, channels) {
    const notificationPromises = channels.map(channel => 
      this.sendToChannel(alert, channel)
    );
    
    const results = await Promise.allSettled(notificationPromises);
    
    results.forEach((result, index) => {
      if (result.status === 'rejected') {
        console.error(`Failed to send alert to channel ${channels[index].name}:`, result.reason);
      }
    });
  }

  async sendToChannel(alert, channel) {
    switch (channel.type) {
      case 'slack':
        return await this.sendSlackAlert(alert, channel);
      case 'email':
        return await this.sendEmailAlert(alert, channel);
      case 'webhook':
        return await this.sendWebhookAlert(alert, channel);
      default:
        console.warn(`Unknown channel type: ${channel.type}`);
    }
  }

  async sendSlackAlert(alert, channel) {
    const color = {
      info: '#36a64f',
      warning: '#ffb347',
      critical: '#ff4444'
    }[alert.severity] || '#cccccc';
    
    const message = {
      channel: channel.channel,
      attachments: [{
        color,
        title: `${alert.severity.toUpperCase()} Alert: ${alert.rule}`,
        text: alert.description,
        fields: [
          {
            title: 'Timestamp',
            value: alert.timestamp,
            short: true
          },
          {
            title: 'Alert ID',
            value: alert.id,
            short: true
          }
        ],
        footer: 'Service Monitoring',
        ts: Math.floor(Date.parse(alert.timestamp) / 1000)
      }]
    };
    
    const response = await fetch(channel.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(message)
    });
    
    if (!response.ok) {
      throw new Error(`Slack notification failed: ${response.statusText}`);
    }
  }

  generateAlertId() {
    return 'alert_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }

  extractRelevantMetrics(metrics, rule) {
    // Extract metrics that might be relevant to this rule
    // This is a simplified implementation
    return Object.fromEntries(
      Object.entries(metrics).filter(([key]) => 
        rule.metadata.relevantMetrics?.includes(key) || key.includes('error') || key.includes('response_time')
      )
    );
  }
}

// Common alert conditions
class AlertConditions {
  static errorRateExceeds(threshold, timeWindow = 300000) {
    return (metrics) => {
      const errorRates = Object.values(metrics)
        .filter(m => m.errorRate !== undefined)
        .map(m => m.errorRate);
      
      const avgErrorRate = errorRates.length > 0 ? 
        errorRates.reduce((sum, rate) => sum + rate, 0) / errorRates.length : 0;
      
      return avgErrorRate > threshold;
    };
  }

  static responseTimeExceeds(threshold) {
    return (metrics) => {
      const responseTimes = Object.values(metrics)
        .filter(m => m.averageDuration !== undefined)
        .map(m => m.averageDuration);
      
      const maxResponseTime = Math.max(...responseTimes, 0);
      
      return maxResponseTime > threshold;
    };
  }

  static serviceUnavailable(serviceName) {
    return (metrics) => {
      const serviceMetrics = Object.values(metrics)
        .filter(m => m.service === serviceName);
      
      return serviceMetrics.some(m => m.availability < 95); // Less than 95% availability
    };
  }

  static businessMetricThreshold(metricName, operator, threshold) {
    return (metrics) => {
      const businessMetrics = Object.values(metrics)
        .filter(m => m.type === 'business' && m.name === metricName);
      
      if (businessMetrics.length === 0) return false;
      
      const latestValue = businessMetrics[0].values?.slice(-1)[0]?.value || 0;
      
      switch (operator) {
        case '>': return latestValue > threshold;
        case '<': return latestValue < threshold;
        case '>=': return latestValue >= threshold;
        case '<=': return latestValue <= threshold;
        case '==': return latestValue === threshold;
        default: return false;
      }
    };
  }
}
```

## Dashboard and Visualization

### Metrics Dashboard Generator
```javascript
class DashboardGenerator {
  constructor() {
    this.widgets = [];
    this.layout = { rows: 0, cols: 12 };
  }

  addServiceHealthWidget(services) {
    this.widgets.push({
      type: 'service_health',
      title: 'Service Health Overview',
      services: services,
      position: { row: 0, col: 0, width: 6, height: 4 },
      refreshInterval: 30000
    });
  }

  addAPIMetricsWidget(service, endpoints) {
    this.widgets.push({
      type: 'api_metrics',
      title: `${service} API Metrics`,
      service: service,
      endpoints: endpoints,
      position: { row: 0, col: 6, width: 6, height: 4 },
      refreshInterval: 60000
    });
  }

  addBusinessMetricsWidget(metrics) {
    this.widgets.push({
      type: 'business_metrics',
      title: 'Key Business Metrics',
      metrics: metrics,
      position: { row: 1, col: 0, width: 12, height: 4 },
      refreshInterval: 300000 // 5 minutes
    });
  }

  addErrorRateWidget() {
    this.widgets.push({
      type: 'error_rate',
      title: 'Error Rates by Service',
      position: { row: 2, col: 0, width: 6, height: 4 },
      refreshInterval: 60000
    });
  }

  addResponseTimeWidget() {
    this.widgets.push({
      type: 'response_time',
      title: 'Response Time Distribution',
      position: { row: 2, col: 6, width: 6, height: 4 },
      refreshInterval: 60000
    });
  }

  generateDashboardConfig() {
    return {
      title: 'Service Integration Dashboard',
      layout: this.layout,
      widgets: this.widgets,
      autoRefresh: true,
      theme: 'dark'
    };
  }

  exportToGrafana() {
    // Convert to Grafana dashboard format
    const grafanaDashboard = {
      dashboard: {
        title: 'Service Integration Dashboard',
        panels: this.widgets.map((widget, index) => ({
          id: index + 1,
          title: widget.title,
          type: this.getGrafanaPanelType(widget.type),
          gridPos: {
            x: widget.position.col,
            y: widget.position.row,
            w: widget.position.width,
            h: widget.position.height
          },
          targets: this.getGrafanaTargets(widget)
        }))
      }
    };
    
    return grafanaDashboard;
  }

  getGrafanaPanelType(widgetType) {
    const typeMap = {
      service_health: 'stat',
      api_metrics: 'graph',
      business_metrics: 'stat',
      error_rate: 'graph',
      response_time: 'heatmap'
    };
    
    return typeMap[widgetType] || 'graph';
  }

  getGrafanaTargets(widget) {
    // Generate appropriate Prometheus/metrics queries based on widget type
    switch (widget.type) {
      case 'api_metrics':
        return [{
          expr: `rate(api_requests_total{service="${widget.service}"}[5m])`,
          legendFormat: 'Request Rate'
        }];
      case 'error_rate':
        return [{
          expr: `rate(api_requests_total{status=~"5.."}[5m]) / rate(api_requests_total[5m])`,
          legendFormat: 'Error Rate'
        }];
      default:
        return [];
    }
  }
}
```

## Best Practices

### 1. Metrics Strategy
- **Golden Signals**: Focus on latency, traffic, errors, and saturation
- **Business Metrics**: Track KPIs that matter to your business
- **SLA Metrics**: Monitor metrics that directly impact SLAs
- **Leading Indicators**: Track metrics that predict future problems

### 2. Logging Strategy
- **Structured Logging**: Use consistent JSON format
- **Correlation IDs**: Track requests across services
- **Log Levels**: Use appropriate levels (error, warn, info, debug)
- **Sensitive Data**: Never log credentials or PII

### 3. Alerting Strategy
- **Alert Fatigue**: Only alert on actionable issues
- **Severity Levels**: Use appropriate severity (info, warning, critical)
- **Runbooks**: Provide clear remediation steps
- **Escalation**: Define escalation paths for critical alerts

### 4. Dashboard Design
- **User-Focused**: Design for your audience (ops, dev, business)
- **Actionable**: Make it clear what actions to take
- **Context**: Provide enough context to understand the data
- **Performance**: Keep dashboards fast and responsive

## Resources

- [The Four Golden Signals](https://sre.google/sre-book/monitoring-distributed-systems/)
- [Observability Engineering](https://www.observability.engineering/)
- [Prometheus Monitoring](https://prometheus.io/docs/)
- [Grafana Dashboards](https://grafana.com/docs/)
- [OpenTelemetry](https://opentelemetry.io/)
- [Jaeger Tracing](https://www.jaegertracing.io/)