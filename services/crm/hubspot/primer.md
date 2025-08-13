# HubSpot Primer

## Overview
HubSpot is an all-in-one customer relationship management (CRM) platform that provides tools for marketing, sales, customer service, and content management. It offers both free and premium tiers with extensive API capabilities for integrating with external applications.

## Key Features
- **CRM**: Contact, company, and deal management
- **Marketing Hub**: Email marketing, lead generation, analytics
- **Sales Hub**: Pipeline management, email tracking, meeting scheduling
- **Service Hub**: Ticketing, knowledge base, customer feedback
- **Content Hub**: Website and blog management

## API Overview
HubSpot provides comprehensive REST APIs across all its hubs:

- **CRM API**: Manage contacts, companies, deals, tickets
- **Marketing API**: Access email campaigns, forms, workflows
- **Analytics API**: Retrieve performance metrics and reports
- **Webhooks**: Real-time notifications for data changes

### Base URL
```
https://api.hubapi.com
```

### Authentication
HubSpot uses API keys or OAuth 2.0 for authentication:

```javascript
// API Key (deprecated for new integrations)
const headers = {
  'Authorization': 'Bearer YOUR_API_KEY'
}

// OAuth 2.0 (recommended)
const headers = {
  'Authorization': 'Bearer YOUR_ACCESS_TOKEN'
}
```

## Common Use Cases for Developers

### 1. Contact Management
```javascript
// Create a contact
const createContact = async (email, firstName, lastName) => {
  const response = await fetch('https://api.hubapi.com/crm/v3/objects/contacts', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer YOUR_ACCESS_TOKEN'
    },
    body: JSON.stringify({
      properties: {
        email,
        firstname: firstName,
        lastname: lastName
      }
    })
  });
  return response.json();
};

// Get contact by email
const getContactByEmail = async (email) => {
  const response = await fetch(`https://api.hubapi.com/crm/v3/objects/contacts/${email}?idProperty=email`, {
    headers: {
      'Authorization': 'Bearer YOUR_ACCESS_TOKEN'
    }
  });
  return response.json();
};
```

### 2. Deal Pipeline Management
```javascript
// Create a deal
const createDeal = async (dealName, amount, stage) => {
  const response = await fetch('https://api.hubapi.com/crm/v3/objects/deals', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer YOUR_ACCESS_TOKEN'
    },
    body: JSON.stringify({
      properties: {
        dealname: dealName,
        amount,
        dealstage: stage
      }
    })
  });
  return response.json();
};
```

### 3. Email Marketing
```javascript
// Send marketing email
const sendEmail = async (contactId, emailId) => {
  const response = await fetch('https://api.hubapi.com/marketing/v3/transactional/single-send', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer YOUR_ACCESS_TOKEN'
    },
    body: JSON.stringify({
      emailId,
      to: contactId,
      customProperties: {}
    })
  });
  return response.json();
};
```

## SDKs and Libraries
- **JavaScript/Node.js**: `@hubspot/api-client`
- **Python**: `hubspot-api-client`
- **PHP**: `hubspot/hubspot-php`
- **Ruby**: `hubspot-ruby`

### Node.js Example
```javascript
const hubspot = require('@hubspot/api-client');

const hubspotClient = new hubspot.Client({
  accessToken: 'YOUR_ACCESS_TOKEN'
});

// Get all contacts
const contacts = await hubspotClient.crm.contacts.basicApi.getPage();
```

## Rate Limits
- **Professional/Enterprise**: 100 requests per 10 seconds
- **Free/Starter**: 100 requests per 10 seconds (daily limits apply)
- **Burst limit**: 150 requests per 10 seconds

## Webhooks
### Step 1
Register a webhook with HubSpot
1. You go into the developer portal or API.
2. You register https://your-server.com/hubspot-webhook as your callback URL.
3. You select events you care about (e.g., Contact created, Deal updated).
4. HubSpot will then POST JSON to that URL when those events occur.
### Step 2
Create a local HTTP endpoint in your server to handle incoming POST requests from Hubspot's webhook:

```javascript
// Webhook endpoint example
app.post('/hubspot-webhook', (req, res) => {
  const events = req.body;
  
  events.forEach(event => {
    console.log(`Event: ${event.eventType}`);
    console.log(`Object: ${event.objectType}`);
    console.log(`Properties:`, event.properties);
  });
  
  res.status(200).send('OK');
});
```

## Best Practices
1. Use OAuth 2.0 instead of API keys for new integrations
2. Implement proper error handling and retry logic
3. Respect rate limits with exponential backoff
4. Use batch operations when possible to reduce API calls
5. Store webhook signatures for security validation
6. Use property groups to minimize data transfer

## Common Gotchas
- Property names are case-sensitive and use specific formatting
- Deal stages must match exactly with pipeline configuration
- Some endpoints require specific scopes in OAuth
- Bulk operations have different rate limits
- Custom properties need to be created before use

## Resources
- [HubSpot Developer Documentation](https://developers.hubspot.com/)
- [API Reference](https://developers.hubspot.com/docs/api/overview)
- [OAuth Guide](https://developers.hubspot.com/docs/api/oauth-quickstart-guide)
- [Webhooks Guide](https://developers.hubspot.com/docs/api/webhooks)
