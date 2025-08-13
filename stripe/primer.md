# Stripe Primer

## Overview
Stripe is a comprehensive payment processing platform that enables businesses to accept payments online and in mobile apps. It provides APIs for handling transactions, subscriptions, marketplaces, and financial services with strong security and compliance features.

## Key Features
- **Payment Processing**: Credit cards, digital wallets, bank transfers
- **Subscriptions**: Recurring billing and subscription management
- **Connect**: Marketplace and multi-party payments
- **Terminal**: In-person payment processing
- **Billing**: Invoice management and automated billing
- **Radar**: Fraud detection and prevention
- **Atlas**: Business incorporation services

## API Overview
Stripe provides RESTful APIs for all payment operations:

- **Payment Intents API**: Modern payment flow with Strong Customer Authentication
- **Charges API**: Legacy direct charge processing
- **Subscriptions API**: Recurring payment management
- **Connect API**: Multi-party payment flows
- **Webhooks**: Real-time event notifications

### Base URL
```
https://api.stripe.com/v1/
```

### Authentication
Stripe uses API keys for authentication - publishable keys for client-side and secret keys for server-side:

```javascript
// Server-side (secret key)
const stripe = require('stripe')('sk_test_...');

// Client-side headers
const headers = {
  'Authorization': 'Bearer sk_test_...',
  'Content-Type': 'application/x-www-form-urlencoded'
};
```

## Common Use Cases for Developers

### 1. Basic Payment Processing
```javascript
const stripe = require('stripe')('sk_test_...');

// Create a Payment Intent
const createPaymentIntent = async (amount, currency = 'usd') => {
  const paymentIntent = await stripe.paymentIntents.create({
    amount: amount * 100, // Amount in cents
    currency: currency,
    payment_method_types: ['card'],
    metadata: {
      order_id: '12345',
      customer_email: 'customer@example.com'
    }
  });

  return paymentIntent;
};

// Confirm a Payment Intent
const confirmPayment = async (paymentIntentId, paymentMethodId) => {
  const paymentIntent = await stripe.paymentIntents.confirm(paymentIntentId, {
    payment_method: paymentMethodId,
    return_url: 'https://yoursite.com/return'
  });

  return paymentIntent;
};
```

### 2. Customer Management
```javascript
// Create a customer
const createCustomer = async (email, name, metadata = {}) => {
  const customer = await stripe.customers.create({
    email: email,
    name: name,
    metadata: metadata
  });

  return customer;
};

// Attach payment method to customer
const attachPaymentMethod = async (paymentMethodId, customerId) => {
  await stripe.paymentMethods.attach(paymentMethodId, {
    customer: customerId,
  });
};

// Set default payment method
const setDefaultPaymentMethod = async (customerId, paymentMethodId) => {
  await stripe.customers.update(customerId, {
    invoice_settings: {
      default_payment_method: paymentMethodId,
    },
  });
};
```

### 3. Subscription Management
```javascript
// Create a subscription
const createSubscription = async (customerId, priceId, trialDays = null) => {
  const subscriptionData = {
    customer: customerId,
    items: [{ price: priceId }],
    payment_behavior: 'default_incomplete',
    expand: ['latest_invoice.payment_intent'],
  };

  if (trialDays) {
    subscriptionData.trial_period_days = trialDays;
  }

  const subscription = await stripe.subscriptions.create(subscriptionData);
  return subscription;
};

// Update subscription
const updateSubscription = async (subscriptionId, newPriceId) => {
  const subscription = await stripe.subscriptions.retrieve(subscriptionId);
  
  await stripe.subscriptions.update(subscriptionId, {
    items: [{
      id: subscription.items.data[0].id,
      price: newPriceId,
    }],
    proration_behavior: 'create_prorations',
  });
};

// Cancel subscription
const cancelSubscription = async (subscriptionId, atPeriodEnd = true) => {
  const subscription = await stripe.subscriptions.update(subscriptionId, {
    cancel_at_period_end: atPeriodEnd,
  });

  return subscription;
};
```

### 4. Product and Pricing
```javascript
// Create a product
const createProduct = async (name, description, type = 'service') => {
  const product = await stripe.products.create({
    name: name,
    description: description,
    type: type,
  });

  return product;
};

// Create a price
const createPrice = async (productId, unitAmount, currency = 'usd', recurring = null) => {
  const priceData = {
    product: productId,
    unit_amount: unitAmount,
    currency: currency,
  };

  if (recurring) {
    priceData.recurring = recurring; // { interval: 'month' } or { interval: 'year' }
  }

  const price = await stripe.prices.create(priceData);
  return price;
};
```

### 5. Webhooks Handling
```javascript
const express = require('express');
const app = express();

// Webhook endpoint
app.post('/webhook', express.raw({type: 'application/json'}), (request, response) => {
  const sig = request.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(request.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.log(`Webhook signature verification failed.`, err.message);
    return response.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle the event
  switch (event.type) {
    case 'payment_intent.succeeded':
      const paymentIntent = event.data.object;
      console.log('Payment succeeded:', paymentIntent.id);
      // Fulfill the order
      break;
    
    case 'invoice.payment_succeeded':
      const invoice = event.data.object;
      console.log('Subscription payment succeeded:', invoice.subscription);
      break;
    
    case 'customer.subscription.deleted':
      const subscription = event.data.object;
      console.log('Subscription cancelled:', subscription.id);
      // Handle cancellation
      break;
    
    default:
      console.log(`Unhandled event type ${event.type}`);
  }

  response.json({received: true});
});
```

### 6. Connect (Marketplace) Payments
```javascript
// Create connected account
const createConnectedAccount = async (email, country = 'US') => {
  const account = await stripe.accounts.create({
    type: 'express',
    country: country,
    email: email,
  });

  return account;
};

// Create account link for onboarding
const createAccountLink = async (accountId, returnUrl, refreshUrl) => {
  const accountLink = await stripe.accountLinks.create({
    account: accountId,
    refresh_url: refreshUrl,
    return_url: returnUrl,
    type: 'account_onboarding',
  });

  return accountLink;
};

// Transfer funds to connected account
const createTransfer = async (amount, connectedAccountId, currency = 'usd') => {
  const transfer = await stripe.transfers.create({
    amount: amount,
    currency: currency,
    destination: connectedAccountId,
  });

  return transfer;
};
```

## SDKs and Libraries
- **JavaScript/Node.js**: `stripe` (official)
- **Python**: `stripe` (official)
- **PHP**: `stripe/stripe-php` (official)
- **Ruby**: `stripe` (official)
- **Go**: `stripe/stripe-go` (official)
- **Java**: `stripe-java` (official)

### Frontend Integration Example
```javascript
// Client-side with Stripe.js
const stripe = Stripe('pk_test_...');

// Create payment method
const createPaymentMethod = async (cardElement) => {
  const {error, paymentMethod} = await stripe.createPaymentMethod({
    type: 'card',
    card: cardElement,
    billing_details: {
      name: 'Customer Name',
      email: 'customer@example.com',
    },
  });

  if (error) {
    console.error('Error creating payment method:', error);
    return null;
  }

  return paymentMethod;
};

// Confirm payment on client
const confirmCardPayment = async (clientSecret, paymentMethod) => {
  const {error, paymentIntent} = await stripe.confirmCardPayment(clientSecret, {
    payment_method: paymentMethod.id
  });

  if (error) {
    console.error('Payment failed:', error);
    return null;
  }

  return paymentIntent;
};
```

## Rate Limits and Quotas
- **API Requests**: 100 requests per second per account in live mode
- **Test Mode**: Higher limits for testing
- **Burst Allowance**: Short bursts above limits are allowed
- **Webhook Delivery**: Automatic retries with exponential backoff

## Security Best Practices

### PCI Compliance
```javascript
// NEVER store raw card data
// Always use Stripe.js or mobile SDKs for card collection

// Server-side: only handle tokens/payment methods
const processPayment = async (paymentMethodId, amount) => {
  // This is safe - no card data on your servers
  const paymentIntent = await stripe.paymentIntents.create({
    amount: amount,
    currency: 'usd',
    payment_method: paymentMethodId,
    confirm: true,
  });

  return paymentIntent;
};
```

### Webhook Security
```javascript
// Always verify webhook signatures
const verifyWebhookSignature = (payload, signature, secret) => {
  try {
    const event = stripe.webhooks.constructEvent(payload, signature, secret);
    return event;
  } catch (err) {
    throw new Error('Invalid webhook signature');
  }
};
```

## Common Patterns

### Checkout Session (Hosted Payment Page)
```javascript
const createCheckoutSession = async (priceId, successUrl, cancelUrl) => {
  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    line_items: [
      {
        price: priceId,
        quantity: 1,
      },
    ],
    mode: 'payment', // or 'subscription' for recurring
    success_url: successUrl,
    cancel_url: cancelUrl,
  });

  return session;
};
```

### Subscription with Trial
```javascript
const createTrialSubscription = async (customerId, priceId, trialEnd) => {
  const subscription = await stripe.subscriptions.create({
    customer: customerId,
    items: [{ price: priceId }],
    trial_end: trialEnd, // Unix timestamp
    payment_behavior: 'default_incomplete',
    expand: ['latest_invoice.payment_intent'],
  });

  return subscription;
};
```

### Metered Billing
```javascript
// Create usage record for metered billing
const recordUsage = async (subscriptionItemId, quantity, timestamp = null) => {
  const usageRecord = await stripe.subscriptionItems.createUsageRecord(
    subscriptionItemId,
    {
      quantity: quantity,
      timestamp: timestamp || Math.floor(Date.now() / 1000),
    }
  );

  return usageRecord;
};
```

## Testing

### Test Card Numbers
```javascript
const testCards = {
  visa: '4242424242424242',
  visaDebit: '4000056655665556',
  mastercard: '5555555555554444',
  amex: '378282246310005',
  declined: '4000000000000002',
  insufficientFunds: '4000000000009995',
  requiresAuthentication: '4000002760003184'
};
```

### Test Webhooks
```bash
# Install Stripe CLI for local webhook testing
stripe listen --forward-to localhost:3000/webhook

# Trigger test events
stripe trigger payment_intent.succeeded
```

## Error Handling
```javascript
const handleStripeError = (error) => {
  switch (error.type) {
    case 'card_error':
      // Card was declined
      console.log('Card error:', error.message);
      break;
    case 'rate_limit_error':
      // Too many requests hit the API too quickly
      console.log('Rate limit error');
      break;
    case 'invalid_request_error':
      // Invalid parameters were supplied to Stripe's API
      console.log('Invalid request:', error.message);
      break;
    case 'authentication_error':
      // Authentication with Stripe's API failed
      console.log('Authentication error');
      break;
    case 'api_connection_error':
      // Network communication with Stripe failed
      console.log('API connection error');
      break;
    default:
      // Handle any other types of unexpected errors
      console.log('Unknown error:', error.message);
      break;
  }
};
```

## Best Practices
1. **Use Payment Intents**: Modern flow with SCA compliance
2. **Implement Webhooks**: Don't rely solely on client-side confirmations
3. **Handle Idempotency**: Use idempency keys for critical operations
4. **Store Customer IDs**: For repeat customers and subscriptions
5. **Test Thoroughly**: Use test mode and various test scenarios
6. **Monitor Events**: Set up proper logging and monitoring

## Common Gotchas
- Amounts are in cents (multiply by 100)
- Webhook events can arrive out of order
- Payment methods need to be attached to customers before use
- Subscriptions have complex lifecycle states
- Connected accounts have different capabilities during onboarding
- Test and live mode data are completely separate

## Resources
- [Stripe API Documentation](https://stripe.com/docs/api)
- [Stripe.js Reference](https://stripe.com/docs/js)
- [Webhooks Guide](https://stripe.com/docs/webhooks)
- [Connect Documentation](https://stripe.com/docs/connect)
- [Testing Guide](https://stripe.com/docs/testing)