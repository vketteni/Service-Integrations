# Testing Strategies for Service Integrations

## Overview
Testing multi-service integrations presents unique challenges compared to testing isolated applications. This primer covers comprehensive testing strategies for API integrations, webhook handling, authentication flows, and multi-service workflows, with practical examples for Stripe, HubSpot, Salesforce, Google Analytics, and Firebase.

## Testing Pyramid for Integrations

### 1. Unit Tests (Base Layer)
Test individual integration components in isolation.

### 2. Integration Tests (Middle Layer)
Test communication between your application and external services.

### 3. Contract Tests (Middle Layer)
Verify that service interfaces match expectations.

### 4. End-to-End Tests (Top Layer)
Test complete workflows across multiple services.

## Unit Testing Strategies

### Mocking External Services
```javascript
// Service wrapper for testing
class StripeService {
  constructor(client = null) {
    this.stripe = client || require('stripe')(process.env.STRIPE_SECRET_KEY);
  }

  async createCustomer(customerData) {
    try {
      const customer = await this.stripe.customers.create({
        email: customerData.email,
        name: `${customerData.firstName} ${customerData.lastName}`,
        metadata: customerData.metadata || {}
      });
      
      return {
        id: customer.id,
        email: customer.email,
        created: customer.created
      };
    } catch (error) {
      throw new Error(`Failed to create customer: ${error.message}`);
    }
  }

  async processPayment(paymentIntent) {
    const result = await this.stripe.paymentIntents.confirm(paymentIntent.id);
    
    if (result.status === 'succeeded') {
      return { success: true, paymentId: result.id };
    } else {
      throw new Error(`Payment failed: ${result.status}`);
    }
  }
}

// Unit tests with mocks
describe('StripeService', () => {
  let stripeService;
  let mockStripe;

  beforeEach(() => {
    mockStripe = {
      customers: {
        create: jest.fn()
      },
      paymentIntents: {
        confirm: jest.fn()
      }
    };
    
    stripeService = new StripeService(mockStripe);
  });

  describe('createCustomer', () => {
    it('should create customer with correct data', async () => {
      const mockCustomer = {
        id: 'cus_123',
        email: 'test@example.com',
        created: 1234567890
      };
      
      mockStripe.customers.create.mockResolvedValue(mockCustomer);

      const result = await stripeService.createCustomer({
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe'
      });

      expect(mockStripe.customers.create).toHaveBeenCalledWith({
        email: 'test@example.com',
        name: 'John Doe',
        metadata: {}
      });
      
      expect(result).toEqual({
        id: 'cus_123',
        email: 'test@example.com',
        created: 1234567890
      });
    });

    it('should handle API errors gracefully', async () => {
      mockStripe.customers.create.mockRejectedValue(
        new Error('Invalid email address')
      );

      await expect(stripeService.createCustomer({
        email: 'invalid-email',
        firstName: 'John',
        lastName: 'Doe'
      })).rejects.toThrow('Failed to create customer: Invalid email address');
    });
  });

  describe('processPayment', () => {
    it('should process successful payment', async () => {
      mockStripe.paymentIntents.confirm.mockResolvedValue({
        id: 'pi_123',
        status: 'succeeded'
      });

      const result = await stripeService.processPayment({ id: 'pi_123' });

      expect(result).toEqual({
        success: true,
        paymentId: 'pi_123'
      });
    });

    it('should handle failed payment', async () => {
      mockStripe.paymentIntents.confirm.mockResolvedValue({
        id: 'pi_123',
        status: 'requires_action'
      });

      await expect(stripeService.processPayment({ id: 'pi_123' }))
        .rejects.toThrow('Payment failed: requires_action');
    });
  });
});
```

### Testing Authentication Flows
```javascript
class OAuthService {
  constructor(config) {
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.redirectUri = config.redirectUri;
  }

  generateAuthUrl(scopes = [], state = null) {
    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      response_type: 'code',
      scope: scopes.join(' '),
      ...(state && { state })
    });

    return `https://accounts.google.com/oauth/authorize?${params.toString()}`;
  }

  async exchangeCodeForTokens(authCode, codeVerifier = null) {
    const tokenRequest = {
      client_id: this.clientId,
      client_secret: this.clientSecret,
      code: authCode,
      grant_type: 'authorization_code',
      redirect_uri: this.redirectUri,
      ...(codeVerifier && { code_verifier: codeVerifier })
    };

    const response = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(tokenRequest)
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Token exchange failed: ${error.error_description}`);
    }

    return await response.json();
  }
}

// Unit tests for OAuth
describe('OAuthService', () => {
  let oauthService;
  let mockFetch;

  beforeEach(() => {
    oauthService = new OAuthService({
      clientId: 'test_client_id',
      clientSecret: 'test_client_secret',
      redirectUri: 'http://localhost:3000/callback'
    });

    mockFetch = jest.fn();
    global.fetch = mockFetch;
  });

  describe('generateAuthUrl', () => {
    it('should generate correct authorization URL', () => {
      const url = oauthService.generateAuthUrl(['read', 'write'], 'test_state');
      
      expect(url).toContain('client_id=test_client_id');
      expect(url).toContain('redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback');
      expect(url).toContain('scope=read%20write');
      expect(url).toContain('state=test_state');
    });

    it('should work without optional parameters', () => {
      const url = oauthService.generateAuthUrl();
      
      expect(url).toContain('client_id=test_client_id');
      expect(url).not.toContain('state=');
      expect(url).toContain('scope=');
    });
  });

  describe('exchangeCodeForTokens', () => {
    it('should successfully exchange code for tokens', async () => {
      const mockTokenResponse = {
        access_token: 'access_123',
        refresh_token: 'refresh_123',
        expires_in: 3600,
        token_type: 'Bearer'
      };

      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockTokenResponse)
      });

      const result = await oauthService.exchangeCodeForTokens('auth_code_123');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://oauth2.googleapis.com/token',
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        })
      );

      expect(result).toEqual(mockTokenResponse);
    });

    it('should handle token exchange errors', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        json: () => Promise.resolve({
          error: 'invalid_grant',
          error_description: 'Authorization code has expired'
        })
      });

      await expect(oauthService.exchangeCodeForTokens('invalid_code'))
        .rejects.toThrow('Token exchange failed: Authorization code has expired');
    });
  });
});
```

## Integration Testing

### Testing Real API Endpoints
```javascript
// Integration test configuration
const testConfig = {
  stripe: {
    secretKey: process.env.STRIPE_TEST_SECRET_KEY,
    publishableKey: process.env.STRIPE_TEST_PUBLISHABLE_KEY
  },
  hubspot: {
    apiKey: process.env.HUBSPOT_TEST_API_KEY,
    portalId: process.env.HUBSPOT_TEST_PORTAL_ID
  }
};

describe('Stripe Integration', () => {
  let stripe;

  beforeAll(() => {
    stripe = require('stripe')(testConfig.stripe.secretKey);
  });

  describe('Customer Management', () => {
    let testCustomer;

    afterEach(async () => {
      // Cleanup created test data
      if (testCustomer) {
        await stripe.customers.del(testCustomer.id);
        testCustomer = null;
      }
    });

    it('should create and retrieve customer', async () => {
      // Create customer
      testCustomer = await stripe.customers.create({
        email: 'integration-test@example.com',
        name: 'Test Customer'
      });

      expect(testCustomer.id).toMatch(/^cus_/);
      expect(testCustomer.email).toBe('integration-test@example.com');

      // Retrieve customer
      const retrievedCustomer = await stripe.customers.retrieve(testCustomer.id);
      expect(retrievedCustomer.id).toBe(testCustomer.id);
      expect(retrievedCustomer.email).toBe(testCustomer.email);
    });

    it('should handle invalid customer data', async () => {
      await expect(stripe.customers.create({
        email: 'invalid-email-format'
      })).rejects.toMatchObject({
        type: 'StripeInvalidRequestError'
      });
    });
  });

  describe('Payment Processing', () => {
    let testCustomer;
    let testPaymentMethod;

    beforeEach(async () => {
      testCustomer = await stripe.customers.create({
        email: 'payment-test@example.com'
      });

      testPaymentMethod = await stripe.paymentMethods.create({
        type: 'card',
        card: {
          number: '4242424242424242', // Test card
          exp_month: 12,
          exp_year: new Date().getFullYear() + 1,
          cvc: '123'
        }
      });

      await stripe.paymentMethods.attach(testPaymentMethod.id, {
        customer: testCustomer.id
      });
    });

    afterEach(async () => {
      if (testCustomer) {
        await stripe.customers.del(testCustomer.id);
      }
    });

    it('should process successful payment', async () => {
      const paymentIntent = await stripe.paymentIntents.create({
        amount: 1000, // $10.00
        currency: 'usd',
        customer: testCustomer.id,
        payment_method: testPaymentMethod.id,
        confirm: true,
        return_url: 'https://example.com/return'
      });

      expect(paymentIntent.status).toBe('succeeded');
      expect(paymentIntent.amount).toBe(1000);
      expect(paymentIntent.customer).toBe(testCustomer.id);
    });

    it('should handle declined card', async () => {
      // Create payment method with declined test card
      const declinedPaymentMethod = await stripe.paymentMethods.create({
        type: 'card',
        card: {
          number: '4000000000000002', // Declined test card
          exp_month: 12,
          exp_year: new Date().getFullYear() + 1,
          cvc: '123'
        }
      });

      await stripe.paymentMethods.attach(declinedPaymentMethod.id, {
        customer: testCustomer.id
      });

      await expect(stripe.paymentIntents.create({
        amount: 1000,
        currency: 'usd',
        customer: testCustomer.id,
        payment_method: declinedPaymentMethod.id,
        confirm: true,
        return_url: 'https://example.com/return'
      })).rejects.toMatchObject({
        decline_code: 'generic_decline'
      });
    });
  });
});
```

### Testing Rate Limiting
```javascript
describe('Rate Limiting Behavior', () => {
  let rateLimitedService;

  beforeEach(() => {
    rateLimitedService = new RateLimitedAPIClient({
      baseURL: 'https://api.hubspot.com',
      apiKey: testConfig.hubspot.apiKey,
      maxRetries: 3,
      retryDelay: 1000
    });
  });

  it('should handle rate limit responses correctly', async () => {
    // This test requires careful setup to avoid hitting real rate limits
    jest.setTimeout(30000); // 30 second timeout

    const requests = [];
    
    // Fire multiple requests quickly to potentially trigger rate limiting
    for (let i = 0; i < 10; i++) {
      requests.push(
        rateLimitedService.get('/contacts/v1/lists/all/contacts/all')
          .catch(error => ({ error: error.message }))
      );
    }

    const results = await Promise.all(requests);
    
    // At least some requests should succeed
    const successes = results.filter(r => !r.error);
    expect(successes.length).toBeGreaterThan(0);

    // Check if rate limiting was handled gracefully
    const rateLimitErrors = results.filter(r => 
      r.error && r.error.includes('rate limit')
    );
    
    // If rate limiting occurred, ensure it was handled properly
    if (rateLimitErrors.length > 0) {
      console.log(`${rateLimitErrors.length} requests were rate limited`);
    }
  });
});
```

## Contract Testing

### API Contract Verification
```javascript
// Contract testing with Pact or similar
describe('HubSpot API Contract', () => {
  it('should match expected contact creation response', async () => {
    const expectedContract = {
      status: 200,
      headers: {
        'content-type': 'application/json'
      },
      body: {
        vid: expect.any(Number),
        'canonical-vid': expect.any(Number),
        'merged-vids': expect.any(Array),
        'portal-id': expect.any(Number),
        'is-contact': true,
        properties: {
          email: { value: expect.any(String) },
          firstname: { value: expect.any(String) },
          lastname: { value: expect.any(String) },
          createdate: { value: expect.any(String) }
        }
      }
    };

    const hubspot = new HubSpotClient(testConfig.hubspot.apiKey);
    
    const response = await hubspot.createContact({
      email: 'contract-test@example.com',
      firstname: 'Contract',
      lastname: 'Test'
    });

    expect(response).toMatchObject(expectedContract.body);
  });
});
```

### Schema Validation Testing
```javascript
const Joi = require('joi');

const webhookSchemas = {
  stripe: {
    invoice_payment_succeeded: Joi.object({
      id: Joi.string().required(),
      object: Joi.string().valid('event').required(),
      type: Joi.string().valid('invoice.payment_succeeded').required(),
      data: Joi.object({
        object: Joi.object({
          id: Joi.string().required(),
          object: Joi.string().valid('invoice').required(),
          amount_paid: Joi.number().required(),
          customer: Joi.string().required(),
          status: Joi.string().valid('paid').required()
        }).required()
      }).required(),
      created: Joi.number().required()
    })
  },
  
  hubspot: {
    contact_creation: Joi.object({
      eventId: Joi.number().required(),
      subscriptionId: Joi.number().required(),
      portalId: Joi.number().required(),
      objectId: Joi.number().required(),
      changeSource: Joi.string().required(),
      eventType: Joi.string().valid('contact.creation').required()
    })
  }
};

describe('Webhook Schema Validation', () => {
  describe('Stripe Webhooks', () => {
    it('should validate invoice.payment_succeeded webhook', () => {
      const sampleWebhook = {
        id: 'evt_1234567890',
        object: 'event',
        type: 'invoice.payment_succeeded',
        data: {
          object: {
            id: 'in_1234567890',
            object: 'invoice',
            amount_paid: 1000,
            customer: 'cus_1234567890',
            status: 'paid'
          }
        },
        created: 1234567890
      };

      const { error } = webhookSchemas.stripe.invoice_payment_succeeded
        .validate(sampleWebhook);
      
      expect(error).toBeUndefined();
    });

    it('should reject invalid webhook data', () => {
      const invalidWebhook = {
        id: 'evt_1234567890',
        object: 'event',
        type: 'invoice.payment_succeeded',
        data: {
          object: {
            id: 'in_1234567890',
            object: 'invoice',
            amount_paid: 'invalid_number', // Should be number
            customer: 'cus_1234567890',
            status: 'paid'
          }
        },
        created: 1234567890
      };

      const { error } = webhookSchemas.stripe.invoice_payment_succeeded
        .validate(invalidWebhook);
      
      expect(error).toBeDefined();
      expect(error.details[0].path).toEqual(['data', 'object', 'amount_paid']);
    });
  });
});
```

## End-to-End Testing

### Multi-Service Workflow Testing
```javascript
describe('E-commerce Workflow End-to-End', () => {
  let testUser;
  let testCustomer;
  let testContact;

  beforeAll(async () => {
    // Setup test data
    testUser = {
      email: 'e2e-test@example.com',
      firstName: 'E2E',
      lastName: 'Test',
      company: 'Test Company'
    };
  });

  afterAll(async () => {
    // Cleanup all test data
    try {
      if (testCustomer) {
        await stripe.customers.del(testCustomer.id);
      }
      if (testContact) {
        await hubspot.deleteContact(testContact.vid);
      }
    } catch (error) {
      console.warn('Cleanup warning:', error.message);
    }
  });

  it('should complete full customer registration workflow', async () => {
    const workflow = new EcommerceWorkflow({
      stripe: new StripeService(stripe),
      hubspot: new HubSpotService(testConfig.hubspot.apiKey),
      analytics: new MockAnalyticsService() // Mock for E2E
    });

    // Execute complete workflow
    const result = await workflow.processCustomerRegistration(testUser);

    expect(result.success).toBe(true);
    expect(result.context.stripeCustomerId).toMatch(/^cus_/);
    expect(result.context.hubspotContactId).toBeGreaterThan(0);

    // Store for cleanup
    testCustomer = { id: result.context.stripeCustomerId };
    testContact = { vid: result.context.hubspotContactId };

    // Verify data consistency across services
    const stripeCustomer = await stripe.customers.retrieve(
      result.context.stripeCustomerId
    );
    expect(stripeCustomer.email).toBe(testUser.email);

    const hubspotContact = await hubspot.getContact(
      result.context.hubspotContactId
    );
    expect(hubspotContact.properties.email.value).toBe(testUser.email);
    expect(hubspotContact.properties.stripe_customer_id.value)
      .toBe(result.context.stripeCustomerId);
  });

  it('should handle partial failures gracefully', async () => {
    // Create a workflow with one failing service
    const workflow = new EcommerceWorkflow({
      stripe: new StripeService(stripe),
      hubspot: new FailingHubSpotService(), // Mock that always fails
      analytics: new MockAnalyticsService()
    });

    const result = await workflow.processCustomerRegistration({
      ...testUser,
      email: 'partial-failure@example.com'
    });

    // Should have partial success
    expect(result.success).toBe(false);
    expect(result.context.stripeCustomerId).toMatch(/^cus_/);
    expect(result.context.hubspotContactId).toBeUndefined();

    // Verify compensation/rollback occurred
    try {
      await stripe.customers.retrieve(result.context.stripeCustomerId);
      fail('Customer should have been deleted during compensation');
    } catch (error) {
      expect(error.statusCode).toBe(404);
    }
  });
});
```

## Webhook Testing

### Webhook Handler Testing
```javascript
class WebhookHandler {
  constructor(services) {
    this.services = services;
  }

  async handleStripeWebhook(event) {
    switch (event.type) {
      case 'invoice.payment_succeeded':
        return await this.handlePaymentSucceeded(event.data.object);
      case 'customer.subscription.deleted':
        return await this.handleSubscriptionCancelled(event.data.object);
      default:
        return { processed: false, reason: 'Unhandled event type' };
    }
  }

  async handlePaymentSucceeded(invoice) {
    // Update user subscription status
    await this.services.firebase.updateUserSubscription(
      invoice.customer,
      'active'
    );

    // Track payment in analytics
    await this.services.analytics.track('payment_succeeded', {
      customer_id: invoice.customer,
      amount: invoice.amount_paid,
      invoice_id: invoice.id
    });

    return { processed: true, invoice_id: invoice.id };
  }
}

describe('Webhook Handler', () => {
  let webhookHandler;
  let mockServices;

  beforeEach(() => {
    mockServices = {
      firebase: {
        updateUserSubscription: jest.fn().mockResolvedValue(true)
      },
      analytics: {
        track: jest.fn().mockResolvedValue(true)
      }
    };

    webhookHandler = new WebhookHandler(mockServices);
  });

  describe('Stripe Webhooks', () => {
    it('should handle invoice.payment_succeeded', async () => {
      const webhookEvent = {
        id: 'evt_test_webhook',
        type: 'invoice.payment_succeeded',
        data: {
          object: {
            id: 'in_test_invoice',
            customer: 'cus_test_customer',
            amount_paid: 1000,
            status: 'paid'
          }
        }
      };

      const result = await webhookHandler.handleStripeWebhook(webhookEvent);

      expect(result.processed).toBe(true);
      expect(result.invoice_id).toBe('in_test_invoice');

      expect(mockServices.firebase.updateUserSubscription)
        .toHaveBeenCalledWith('cus_test_customer', 'active');

      expect(mockServices.analytics.track)
        .toHaveBeenCalledWith('payment_succeeded', {
          customer_id: 'cus_test_customer',
          amount: 1000,
          invoice_id: 'in_test_invoice'
        });
    });

    it('should handle unrecognized events gracefully', async () => {
      const webhookEvent = {
        id: 'evt_test_webhook',
        type: 'unknown.event.type',
        data: { object: {} }
      };

      const result = await webhookHandler.handleStripeWebhook(webhookEvent);

      expect(result.processed).toBe(false);
      expect(result.reason).toBe('Unhandled event type');
    });

    it('should handle service failures', async () => {
      mockServices.firebase.updateUserSubscription
        .mockRejectedValue(new Error('Database connection failed'));

      const webhookEvent = {
        id: 'evt_test_webhook',
        type: 'invoice.payment_succeeded',
        data: {
          object: {
            id: 'in_test_invoice',
            customer: 'cus_test_customer',
            amount_paid: 1000,
            status: 'paid'
          }
        }
      };

      await expect(webhookHandler.handleStripeWebhook(webhookEvent))
        .rejects.toThrow('Database connection failed');
    });
  });
});
```

### Webhook Signature Verification Testing
```javascript
const crypto = require('crypto');

class WebhookVerifier {
  static verifyStripeSignature(payload, signature, secret) {
    const elements = signature.split(',');
    const timestamp = elements.find(e => e.startsWith('t=')).substring(2);
    const v1Signature = elements.find(e => e.startsWith('v1=')).substring(3);

    const signedPayload = timestamp + '.' + payload;
    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(signedPayload, 'utf8')
      .digest('hex');

    if (expectedSignature !== v1Signature) {
      throw new Error('Invalid signature');
    }

    // Check timestamp to prevent replay attacks
    const timestampMillis = parseInt(timestamp) * 1000;
    const tolerance = 300000; // 5 minutes
    
    if (Date.now() - timestampMillis > tolerance) {
      throw new Error('Request timestamp too old');
    }

    return true;
  }
}

describe('Webhook Signature Verification', () => {
  const testSecret = 'whsec_test_secret';
  
  it('should verify valid Stripe signature', () => {
    const payload = JSON.stringify({ id: 'evt_test', type: 'test.event' });
    const timestamp = Math.floor(Date.now() / 1000);
    
    const signedPayload = timestamp + '.' + payload;
    const signature = crypto
      .createHmac('sha256', testSecret)
      .update(signedPayload, 'utf8')
      .digest('hex');
    
    const stripeSignature = `t=${timestamp},v1=${signature}`;

    expect(() => 
      WebhookVerifier.verifyStripeSignature(payload, stripeSignature, testSecret)
    ).not.toThrow();
  });

  it('should reject invalid signature', () => {
    const payload = JSON.stringify({ id: 'evt_test', type: 'test.event' });
    const timestamp = Math.floor(Date.now() / 1000);
    const invalidSignature = `t=${timestamp},v1=invalid_signature`;

    expect(() => 
      WebhookVerifier.verifyStripeSignature(payload, invalidSignature, testSecret)
    ).toThrow('Invalid signature');
  });

  it('should reject old timestamp', () => {
    const payload = JSON.stringify({ id: 'evt_test', type: 'test.event' });
    const oldTimestamp = Math.floor(Date.now() / 1000) - 400; // 6+ minutes ago
    
    const signedPayload = oldTimestamp + '.' + payload;
    const signature = crypto
      .createHmac('sha256', testSecret)
      .update(signedPayload, 'utf8')
      .digest('hex');
    
    const stripeSignature = `t=${oldTimestamp},v1=${signature}`;

    expect(() => 
      WebhookVerifier.verifyStripeSignature(payload, stripeSignature, testSecret)
    ).toThrow('Request timestamp too old');
  });
});
```

## Performance Testing

### Load Testing API Integrations
```javascript
describe('Performance Tests', () => {
  it('should handle concurrent API calls', async () => {
    const concurrentRequests = 10;
    const service = new HubSpotService(testConfig.hubspot.apiKey);
    
    const startTime = Date.now();
    
    const promises = Array.from({ length: concurrentRequests }, (_, i) => 
      service.createContact({
        email: `load-test-${i}@example.com`,
        firstname: 'Load',
        lastname: `Test${i}`
      }).catch(error => ({ error: error.message }))
    );

    const results = await Promise.all(promises);
    const endTime = Date.now();
    
    const successes = results.filter(r => !r.error);
    const failures = results.filter(r => r.error);
    
    console.log(`Completed ${concurrentRequests} requests in ${endTime - startTime}ms`);
    console.log(`Successes: ${successes.length}, Failures: ${failures.length}`);
    
    // Cleanup
    await Promise.all(
      successes.map(contact => 
        service.deleteContact(contact.vid).catch(() => {})
      )
    );
    
    expect(successes.length).toBeGreaterThan(concurrentRequests * 0.8); // 80% success rate
  });

  it('should perform within acceptable latency limits', async () => {
    const service = new StripeService();
    const maxLatency = 2000; // 2 seconds
    
    const startTime = Date.now();
    
    const customer = await service.createCustomer({
      email: 'latency-test@example.com',
      firstName: 'Latency',
      lastName: 'Test'
    });
    
    const latency = Date.now() - startTime;
    
    // Cleanup
    await stripe.customers.del(customer.id);
    
    expect(latency).toBeLessThan(maxLatency);
  });
});
```

## Test Data Management

### Test Data Factory
```javascript
class TestDataFactory {
  static createTestCustomer(overrides = {}) {
    return {
      email: `test-${Date.now()}@example.com`,
      firstName: 'Test',
      lastName: 'Customer',
      phone: '+1234567890',
      company: 'Test Company',
      ...overrides
    };
  }

  static createTestPayment(overrides = {}) {
    return {
      amount: 1000,
      currency: 'usd',
      description: 'Test payment',
      ...overrides
    };
  }

  static createTestSubscription(overrides = {}) {
    return {
      priceId: 'price_test_123',
      customerId: 'cus_test_123',
      trialPeriodDays: 14,
      ...overrides
    };
  }

  static createStripeTestCard(overrides = {}) {
    return {
      number: '4242424242424242', // Default successful test card
      exp_month: 12,
      exp_year: new Date().getFullYear() + 1,
      cvc: '123',
      ...overrides
    };
  }

  static getDeclinedTestCard() {
    return this.createStripeTestCard({
      number: '4000000000000002' // Declined test card
    });
  }

  static getInsufficientFundsTestCard() {
    return this.createStripeTestCard({
      number: '4000000000009995' // Insufficient funds test card
    });
  }
}

// Usage in tests
describe('Payment Processing', () => {
  it('should process payment with test data', async () => {
    const customer = TestDataFactory.createTestCustomer();
    const payment = TestDataFactory.createTestPayment({ amount: 2000 });
    const card = TestDataFactory.createStripeTestCard();

    // Use test data in your tests...
  });
});
```

### Database Seeding for Tests
```javascript
class TestDatabaseSeeder {
  static async seedTestData() {
    // Create test customers
    const customers = await Promise.all([
      this.createTestCustomer('active'),
      this.createTestCustomer('trial'),
      this.createTestCustomer('cancelled')
    ]);

    // Create test subscriptions
    const subscriptions = await Promise.all(
      customers.map(customer => this.createTestSubscription(customer.id))
    );

    return { customers, subscriptions };
  }

  static async createTestCustomer(status) {
    const customerData = TestDataFactory.createTestCustomer({
      metadata: { test_status: status, created_by: 'test_suite' }
    });

    return await stripe.customers.create(customerData);
  }

  static async createTestSubscription(customerId) {
    return await stripe.subscriptions.create({
      customer: customerId,
      items: [{ price: 'price_test_monthly' }],
      trial_period_days: 7,
      metadata: { created_by: 'test_suite' }
    });
  }

  static async cleanupTestData() {
    // Find all test customers
    const customers = await stripe.customers.list({
      limit: 100
    });

    const testCustomers = customers.data.filter(customer => 
      customer.metadata.created_by === 'test_suite'
    );

    // Delete test customers (this will also cancel subscriptions)
    await Promise.all(
      testCustomers.map(customer => 
        stripe.customers.del(customer.id).catch(console.warn)
      )
    );
  }
}

// Setup/teardown hooks
beforeAll(async () => {
  await TestDatabaseSeeder.seedTestData();
});

afterAll(async () => {
  await TestDatabaseSeeder.cleanupTestData();
});
```

## Monitoring and Observability in Tests

### Test Metrics Collection
```javascript
class TestMetricsCollector {
  constructor() {
    this.metrics = {
      testDuration: [],
      apiCallLatency: [],
      errorRates: new Map(),
      resourceUsage: []
    };
  }

  recordTestDuration(testName, duration) {
    this.metrics.testDuration.push({ testName, duration, timestamp: Date.now() });
  }

  recordAPILatency(service, endpoint, latency) {
    this.metrics.apiCallLatency.push({ service, endpoint, latency, timestamp: Date.now() });
  }

  recordError(testName, error) {
    if (!this.metrics.errorRates.has(testName)) {
      this.metrics.errorRates.set(testName, []);
    }
    this.metrics.errorRates.get(testName).push({ error: error.message, timestamp: Date.now() });
  }

  generateReport() {
    const avgTestDuration = this.metrics.testDuration.reduce((sum, test) => sum + test.duration, 0) / this.metrics.testDuration.length;
    
    const avgAPILatency = this.metrics.apiCallLatency.reduce((sum, call) => sum + call.latency, 0) / this.metrics.apiCallLatency.length;

    return {
      summary: {
        totalTests: this.metrics.testDuration.length,
        averageTestDuration: avgTestDuration,
        averageAPILatency: avgAPILatency,
        totalErrors: Array.from(this.metrics.errorRates.values()).flat().length
      },
      slowestTests: this.metrics.testDuration
        .sort((a, b) => b.duration - a.duration)
        .slice(0, 5),
      slowestAPICalls: this.metrics.apiCallLatency
        .sort((a, b) => b.latency - a.latency)
        .slice(0, 5)
    };
  }
}

// Jest setup to use metrics collector
const metricsCollector = new TestMetricsCollector();

beforeEach(() => {
  global.testStartTime = Date.now();
});

afterEach(() => {
  const duration = Date.now() - global.testStartTime;
  const testName = expect.getState().currentTestName;
  metricsCollector.recordTestDuration(testName, duration);
});

afterAll(() => {
  const report = metricsCollector.generateReport();
  console.log('Test Performance Report:', JSON.stringify(report, null, 2));
});
```

## Best Practices

### 1. Test Environment Management
- Use dedicated test credentials and sandbox accounts
- Implement proper test data cleanup
- Isolate test environments from production
- Use feature flags to control test behavior

### 2. Test Data Strategy
- Generate realistic but obviously fake test data
- Use factories for consistent test data creation
- Implement proper cleanup to avoid data pollution
- Consider using test databases or reset mechanisms

### 3. API Testing Patterns
- Test both success and failure scenarios
- Verify error handling and edge cases
- Test rate limiting and retry behavior
- Validate response schemas and contracts

### 4. Test Organization
- Group tests by service or feature area
- Use descriptive test names that explain intent
- Implement proper setup/teardown hooks
- Maintain test independence (no shared state)

### 5. Continuous Integration
- Run different test types at appropriate pipeline stages
- Use parallel execution for faster feedback
- Implement proper reporting and notifications
- Monitor test reliability and flakiness

## Resources

- [Testing Microservices](https://martinfowler.com/articles/microservice-testing/)
- [Contract Testing with Pact](https://docs.pact.io/)
- [Jest Testing Framework](https://jestjs.io/docs/getting-started)
- [Stripe Testing Guide](https://stripe.com/docs/testing)
- [API Testing Best Practices](https://assertible.com/blog/api-testing-best-practices)
- [Test Data Management](https://www.thoughtworks.com/insights/articles/test-data-management)