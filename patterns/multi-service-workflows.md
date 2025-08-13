# Multi-Service Integration Workflows

## Overview
Modern applications rarely rely on a single service. This primer covers common patterns for integrating multiple services together, including data synchronization, event-driven architectures, and workflow orchestration across platforms like Stripe, HubSpot, Salesforce, Google Analytics, and Firebase.

## Common Integration Patterns

### 1. E-commerce Customer Journey
```
Customer Registration → Analytics Tracking → Payment Processing → CRM Update → Email Automation
    ↓                        ↓                    ↓                ↓              ↓
  Firebase              Google Analytics        Stripe           HubSpot      Email Service
```

**Implementation:**
```javascript
class EcommerceWorkflow {
  constructor(services) {
    this.firebase = services.firebase;
    this.analytics = services.analytics;
    this.stripe = services.stripe;
    this.hubspot = services.hubspot;
  }

  async processCustomerRegistration(userData) {
    const workflow = new WorkflowOrchestrator();
    
    // Step 1: Create user account
    workflow.addStep('create_account', async () => {
      const user = await this.firebase.createUser(userData);
      return { userId: user.uid, email: userData.email };
    });

    // Step 2: Track registration event
    workflow.addStep('track_registration', async (context) => {
      await this.analytics.track('user_registered', {
        user_id: context.userId,
        registration_source: userData.source
      });
    });

    // Step 3: Create customer in payment system
    workflow.addStep('create_stripe_customer', async (context) => {
      const customer = await this.stripe.customers.create({
        email: context.email,
        metadata: { firebase_uid: context.userId }
      });
      return { stripeCustomerId: customer.id };
    });

    // Step 4: Add to CRM
    workflow.addStep('add_to_crm', async (context) => {
      await this.hubspot.createContact({
        email: context.email,
        firstname: userData.firstName,
        lastname: userData.lastName,
        stripe_customer_id: context.stripeCustomerId
      });
    });

    return await workflow.execute();
  }
}
```

### 2. Subscription Lifecycle Management
```
Trial Start → Usage Tracking → Billing → Payment Success/Failure → Account Updates
     ↓              ↓             ↓              ↓                      ↓
  Firebase    Google Analytics   Stripe      Webhook Handler         CRM Update
```

**Implementation:**
```javascript
class SubscriptionWorkflow {
  async handleSubscriptionEvent(stripeEvent) {
    const eventType = stripeEvent.type;
    
    switch (eventType) {
      case 'customer.subscription.created':
        return await this.handleSubscriptionCreated(stripeEvent.data.object);
      
      case 'invoice.payment_succeeded':
        return await this.handlePaymentSucceeded(stripeEvent.data.object);
      
      case 'invoice.payment_failed':
        return await this.handlePaymentFailed(stripeEvent.data.object);
      
      case 'customer.subscription.deleted':
        return await this.handleSubscriptionCancelled(stripeEvent.data.object);
    }
  }

  async handleSubscriptionCreated(subscription) {
    const workflow = new WorkflowOrchestrator();
    
    workflow.addStep('update_user_account', async () => {
      await this.firebase.updateUser(subscription.metadata.user_id, {
        subscriptionStatus: 'active',
        subscriptionId: subscription.id,
        planId: subscription.items.data[0].price.id
      });
    });

    workflow.addStep('track_subscription', async () => {
      await this.analytics.track('subscription_started', {
        user_id: subscription.metadata.user_id,
        plan: subscription.items.data[0].price.nickname,
        amount: subscription.items.data[0].price.unit_amount
      });
    });

    workflow.addStep('update_crm', async () => {
      await this.hubspot.updateContactByEmail(subscription.customer.email, {
        subscription_status: 'Active',
        subscription_plan: subscription.items.data[0].price.nickname,
        subscription_start_date: new Date(subscription.created * 1000)
      });
    });

    return await workflow.execute();
  }
}
```

### 3. Lead Qualification and Sales Pipeline
```
Lead Capture → Scoring → Qualification → Sales Assignment → Follow-up Automation
     ↓           ↓          ↓               ↓                    ↓
  Web Form   Analytics   HubSpot       Salesforce           Email Automation
```

**Implementation:**
```javascript
class LeadWorkflow {
  async processIncomingLead(leadData) {
    const workflow = new WorkflowOrchestrator();

    workflow.addStep('capture_lead', async () => {
      // Store in Firebase for immediate access
      const leadRef = await this.firebase.collection('leads').add({
        ...leadData,
        status: 'new',
        createdAt: new Date(),
        source: leadData.source || 'website'
      });
      return { leadId: leadRef.id };
    });

    workflow.addStep('track_lead_event', async (context) => {
      await this.analytics.track('lead_captured', {
        lead_id: context.leadId,
        source: leadData.source,
        campaign: leadData.campaign
      });
    });

    workflow.addStep('score_lead', async (context) => {
      const score = await this.calculateLeadScore(leadData);
      await this.firebase.collection('leads').doc(context.leadId).update({
        score: score,
        scoringFactors: this.getScoringFactors(leadData)
      });
      return { score };
    });

    workflow.addStep('create_hubspot_contact', async (context) => {
      const contact = await this.hubspot.createContact({
        email: leadData.email,
        firstname: leadData.firstName,
        lastname: leadData.lastName,
        company: leadData.company,
        lead_score: context.score,
        lead_source: leadData.source
      });
      return { hubspotContactId: contact.id };
    });

    workflow.addStep('qualify_and_route', async (context) => {
      if (context.score >= 80) {
        // High-quality lead - send to Salesforce
        await this.createSalesforceOpportunity(leadData, context);
      } else if (context.score >= 50) {
        // Medium-quality lead - nurture in HubSpot
        await this.startHubspotNurtureSequence(context.hubspotContactId);
      }
      // Low-quality leads stay in HubSpot for further nurturing
    });

    return await workflow.execute();
  }

  async calculateLeadScore(leadData) {
    let score = 0;
    
    // Company size scoring
    if (leadData.employeeCount > 1000) score += 30;
    else if (leadData.employeeCount > 100) score += 20;
    else if (leadData.employeeCount > 10) score += 10;
    
    // Industry scoring
    const highValueIndustries = ['technology', 'finance', 'healthcare'];
    if (highValueIndustries.includes(leadData.industry?.toLowerCase())) {
      score += 25;
    }
    
    // Engagement scoring
    if (leadData.source === 'demo_request') score += 40;
    else if (leadData.source === 'whitepaper_download') score += 20;
    else if (leadData.source === 'newsletter_signup') score += 5;
    
    return Math.min(100, score);
  }
}
```

## Workflow Orchestration Framework

### Base Orchestrator
```javascript
class WorkflowOrchestrator {
  constructor(options = {}) {
    this.steps = [];
    this.context = {};
    this.retryConfig = {
      maxRetries: options.maxRetries || 3,
      baseDelay: options.baseDelay || 1000
    };
    this.onError = options.onError || this.defaultErrorHandler;
    this.onSuccess = options.onSuccess || (() => {});
  }

  addStep(name, handler, options = {}) {
    this.steps.push({
      name,
      handler,
      retryable: options.retryable !== false,
      critical: options.critical === true,
      timeout: options.timeout || 30000
    });
  }

  async execute() {
    const results = [];
    
    for (const step of this.steps) {
      try {
        const result = await this.executeStep(step);
        results.push({ step: step.name, status: 'success', result });
        
        // Merge result into context for next steps
        this.context = { ...this.context, ...result };
      } catch (error) {
        const errorResult = { step: step.name, status: 'error', error: error.message };
        results.push(errorResult);
        
        if (step.critical) {
          await this.onError(error, step.name, this.context);
          throw new Error(`Critical step ${step.name} failed: ${error.message}`);
        } else {
          console.warn(`Non-critical step ${step.name} failed:`, error.message);
        }
      }
    }
    
    await this.onSuccess(results, this.context);
    return { results, context: this.context };
  }

  async executeStep(step) {
    let attempt = 0;
    
    while (attempt <= this.retryConfig.maxRetries) {
      try {
        const timeoutPromise = new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Step timeout')), step.timeout)
        );
        
        const stepPromise = step.handler(this.context);
        
        return await Promise.race([stepPromise, timeoutPromise]);
      } catch (error) {
        attempt++;
        
        if (attempt > this.retryConfig.maxRetries || !step.retryable) {
          throw error;
        }
        
        const delay = this.retryConfig.baseDelay * Math.pow(2, attempt - 1);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }

  defaultErrorHandler(error, stepName, context) {
    console.error(`Workflow failed at step ${stepName}:`, error);
    // Could send to monitoring service, create support ticket, etc.
  }
}
```

### Event-Driven Workflow Triggers
```javascript
class EventDrivenWorkflows {
  constructor(services) {
    this.services = services;
    this.workflows = new Map();
    this.setupEventListeners();
  }

  registerWorkflow(eventType, workflowHandler) {
    if (!this.workflows.has(eventType)) {
      this.workflows.set(eventType, []);
    }
    this.workflows.get(eventType).push(workflowHandler);
  }

  setupEventListeners() {
    // Stripe webhook events
    this.onStripeEvent('invoice.payment_succeeded', async (event) => {
      await this.triggerWorkflows('payment_success', event.data.object);
    });

    // HubSpot webhook events  
    this.onHubSpotEvent('contact.creation', async (event) => {
      await this.triggerWorkflows('contact_created', event.objectId);
    });

    // Firebase database triggers
    this.onFirebaseChange('users/{userId}', async (change, context) => {
      if (change.after.val()?.subscriptionStatus !== change.before.val()?.subscriptionStatus) {
        await this.triggerWorkflows('subscription_status_changed', {
          userId: context.params.userId,
          oldStatus: change.before.val()?.subscriptionStatus,
          newStatus: change.after.val()?.subscriptionStatus
        });
      }
    });
  }

  async triggerWorkflows(eventType, eventData) {
    const workflows = this.workflows.get(eventType) || [];
    
    // Execute workflows in parallel
    const workflowPromises = workflows.map(workflow => 
      this.executeWorkflowSafely(workflow, eventData)
    );
    
    const results = await Promise.allSettled(workflowPromises);
    
    // Log any workflow failures
    results.forEach((result, index) => {
      if (result.status === 'rejected') {
        console.error(`Workflow ${index} failed for event ${eventType}:`, result.reason);
      }
    });
    
    return results;
  }

  async executeWorkflowSafely(workflow, eventData) {
    try {
      return await workflow(eventData, this.services);
    } catch (error) {
      // Don't let one workflow failure affect others
      console.error('Workflow execution failed:', error);
      throw error;
    }
  }
}
```

## Data Synchronization Patterns

### Real-time Sync with Conflict Resolution
```javascript
class DataSynchronizer {
  constructor(services) {
    this.services = services;
    this.conflictResolvers = new Map();
  }

  async syncCustomerData(customerId, sourceSystem, updatedFields) {
    const syncTargets = this.determineSyncTargets(sourceSystem, updatedFields);
    const results = [];
    
    for (const target of syncTargets) {
      try {
        const result = await this.syncToTarget(
          customerId, 
          updatedFields, 
          sourceSystem, 
          target
        );
        results.push({ target, status: 'success', result });
      } catch (error) {
        results.push({ target, status: 'error', error: error.message });
      }
    }
    
    return results;
  }

  async syncToTarget(customerId, data, source, target) {
    // Get current data from target
    const currentData = await this.getCurrentData(customerId, target);
    
    // Check for conflicts
    const conflicts = this.detectConflicts(data, currentData, source, target);
    
    if (conflicts.length > 0) {
      const resolvedData = await this.resolveConflicts(conflicts, data, currentData);
      data = resolvedData;
    }
    
    // Apply transformation for target system
    const transformedData = this.transformDataForTarget(data, target);
    
    // Update target system
    return await this.updateTargetSystem(customerId, transformedData, target);
  }

  detectConflicts(newData, currentData, source, target) {
    const conflicts = [];
    
    for (const [field, newValue] of Object.entries(newData)) {
      const currentValue = currentData[field];
      
      if (currentValue && currentValue !== newValue) {
        conflicts.push({
          field,
          newValue,
          currentValue,
          source,
          target,
          timestamp: new Date()
        });
      }
    }
    
    return conflicts;
  }

  async resolveConflicts(conflicts, newData, currentData) {
    const resolvedData = { ...newData };
    
    for (const conflict of conflicts) {
      const resolver = this.conflictResolvers.get(conflict.field) || this.defaultConflictResolver;
      const resolvedValue = await resolver(conflict);
      resolvedData[conflict.field] = resolvedValue;
    }
    
    return resolvedData;
  }

  defaultConflictResolver(conflict) {
    // Last-write-wins strategy (could be more sophisticated)
    return conflict.newValue;
  }
}
```

## Error Handling and Rollback Strategies

### Saga Pattern Implementation
```javascript
class SagaOrchestrator {
  constructor() {
    this.transactions = [];
    this.compensations = [];
  }

  addTransaction(action, compensation) {
    this.transactions.push(action);
    this.compensations.unshift(compensation); // Reverse order for rollback
  }

  async execute() {
    const completedTransactions = [];
    
    try {
      for (const transaction of this.transactions) {
        const result = await transaction();
        completedTransactions.push(result);
      }
      
      return { success: true, results: completedTransactions };
    } catch (error) {
      console.error('Saga failed, initiating compensation:', error);
      
      // Run compensations for completed transactions
      await this.runCompensations(completedTransactions.length);
      
      return { success: false, error: error.message };
    }
  }

  async runCompensations(completedCount) {
    const compensationsToRun = this.compensations.slice(0, completedCount);
    
    for (const compensation of compensationsToRun) {
      try {
        await compensation();
      } catch (compensationError) {
        console.error('Compensation failed:', compensationError);
        // Log for manual intervention
      }
    }
  }
}

// Usage example
class OrderProcessingSaga {
  async processOrder(orderData) {
    const saga = new SagaOrchestrator();
    
    // Reserve inventory
    saga.addTransaction(
      () => this.inventory.reserve(orderData.items),
      () => this.inventory.release(orderData.items)
    );
    
    // Process payment
    saga.addTransaction(
      () => this.stripe.processPayment(orderData.payment),
      () => this.stripe.refundPayment(orderData.payment.id)
    );
    
    // Create shipping label
    saga.addTransaction(
      () => this.shipping.createLabel(orderData.shipping),
      () => this.shipping.cancelLabel(orderData.shipping.id)
    );
    
    // Update CRM
    saga.addTransaction(
      () => this.hubspot.logPurchase(orderData.customer, orderData),
      () => this.hubspot.removePurchase(orderData.customer, orderData.id)
    );
    
    return await saga.execute();
  }
}
```

## Monitoring and Observability

### Workflow Metrics and Tracing
```javascript
class WorkflowObservability {
  constructor() {
    this.metrics = new Map();
    this.traces = new Map();
  }

  startTrace(workflowName, context = {}) {
    const traceId = this.generateTraceId();
    
    this.traces.set(traceId, {
      workflowName,
      startTime: Date.now(),
      context,
      spans: [],
      status: 'running'
    });
    
    return traceId;
  }

  addSpan(traceId, spanName, startTime, endTime, success = true, metadata = {}) {
    const trace = this.traces.get(traceId);
    if (trace) {
      trace.spans.push({
        name: spanName,
        startTime,
        endTime,
        duration: endTime - startTime,
        success,
        metadata
      });
    }
  }

  completeTrace(traceId, success = true, error = null) {
    const trace = this.traces.get(traceId);
    if (trace) {
      trace.endTime = Date.now();
      trace.totalDuration = trace.endTime - trace.startTime;
      trace.status = success ? 'completed' : 'failed';
      trace.error = error;
      
      // Update metrics
      this.updateMetrics(trace);
      
      // Send to monitoring service
      this.sendTraceToMonitoring(trace);
    }
  }

  updateMetrics(trace) {
    const workflowName = trace.workflowName;
    
    if (!this.metrics.has(workflowName)) {
      this.metrics.set(workflowName, {
        totalRuns: 0,
        successfulRuns: 0,
        failedRuns: 0,
        averageDuration: 0,
        totalDuration: 0
      });
    }
    
    const metrics = this.metrics.get(workflowName);
    metrics.totalRuns++;
    metrics.totalDuration += trace.totalDuration;
    metrics.averageDuration = metrics.totalDuration / metrics.totalRuns;
    
    if (trace.status === 'completed') {
      metrics.successfulRuns++;
    } else {
      metrics.failedRuns++;
    }
  }

  generateTraceId() {
    return 'trace_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }
}
```

## Best Practices

### 1. Design for Failure
- Implement circuit breakers between services
- Use retry with exponential backoff
- Design compensation/rollback strategies
- Monitor and alert on failure patterns

### 2. Event-Driven Architecture
- Use events to decouple services
- Implement event sourcing for audit trails
- Design for eventual consistency
- Use message queues for reliability

### 3. Data Consistency
- Implement conflict resolution strategies
- Use distributed locks when necessary
- Design for eventual consistency
- Maintain audit trails for data changes

### 4. Security and Compliance
- Encrypt data in transit and at rest
- Implement proper authentication between services
- Maintain audit logs for compliance
- Use service mesh for secure communication

### 5. Testing Strategies
- Test individual service integrations
- Test end-to-end workflows
- Use chaos engineering to test failure scenarios
- Implement contract testing between services

## Resources

- [Microservices Patterns](https://microservices.io/patterns/)
- [Event-Driven Architecture Patterns](https://www.enterpriseintegrationpatterns.com/)
- [Saga Pattern Implementation](https://microservices.io/patterns/data/saga.html)
- [Circuit Breaker Pattern](https://martinfowler.com/bliki/CircuitBreaker.html)