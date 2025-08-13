# Customer Relationship Management (CRM) Integrations

This directory contains primers for integrating with Customer Relationship Management platforms. CRM systems help businesses manage customer relationships, sales processes, and marketing campaigns.

## Available CRM Platforms

### [HubSpot](./hubspot.md)
**Best for:** Marketing automation, inbound sales, all-in-one CRM needs

**Key Features:**
- All-in-one CRM with marketing, sales, and service hubs
- Generous free tier with substantial functionality
- Strong marketing automation and lead nurturing
- Excellent API documentation and developer tools
- Built-in reporting and analytics

**Use When:**
- Starting a new CRM implementation
- Need marketing automation integrated with CRM
- Want a user-friendly interface for non-technical teams
- Building inbound marketing and sales processes
- Need good free tier to start with

### [Salesforce](./salesforce.md)
**Best for:** Enterprise sales processes, complex customization, large teams

**Key Features:**
- Highly customizable enterprise CRM platform
- Extensive app marketplace (AppExchange)
- Advanced workflow automation and business processes
- Comprehensive API suite with enterprise features
- Strong enterprise security and compliance features

**Use When:**
- Managing complex enterprise sales processes
- Need extensive customization and business logic
- Have dedicated Salesforce administrators
- Require advanced reporting and analytics
- Need enterprise-grade security and compliance

## 🔄 Integration Comparison

| Feature | HubSpot | Salesforce |
|---------|---------|------------|
| **Learning Curve** | Low to Medium | Medium to High |
| **Setup Time** | 1-2 weeks | 2-4 weeks |
| **API Complexity** | Simple | Comprehensive |
| **Customization** | Good | Excellent |
| **Free Tier** | Yes (generous) | Limited |
| **Enterprise Features** | Good | Excellent |
| **Marketing Tools** | Excellent | Good (with additional products) |
| **Developer Experience** | Excellent | Good |

## 🚀 Common Integration Patterns

### Lead to Customer Journey
```javascript
// HubSpot Example: Simple lead capture to customer conversion
const hubspotFlow = async (leadData) => {
  // 1. Create contact
  const contact = await hubspot.createContact(leadData);
  
  // 2. Track engagement
  await hubspot.trackEvent('page_view', contact.id);
  
  // 3. Trigger marketing automation
  await hubspot.enrollInWorkflow(contact.id, 'lead_nurture_sequence');
  
  return contact;
};

// Salesforce Example: Complex lead qualification process
const salesforceFlow = async (leadData) => {
  // 1. Create lead with scoring
  const lead = await salesforce.createLead({
    ...leadData,
    LeadScore: calculateLeadScore(leadData)
  });
  
  // 2. Auto-assign based on territory rules
  await salesforce.assignLead(lead.Id);
  
  // 3. Create follow-up tasks
  await salesforce.createTask({
    WhoId: lead.Id,
    Subject: 'Follow up on new lead',
    ActivityDate: new Date(Date.now() + 24 * 60 * 60 * 1000) // Tomorrow
  });
  
  return lead;
};
```

### Deal Pipeline Management
```javascript
// HubSpot: Simple deal progression
const progressDeal = async (dealId, newStage) => {
  await hubspot.updateDeal(dealId, {
    dealstage: newStage,
    closedate: newStage === 'closedwon' ? new Date() : null
  });
  
  // Trigger automation based on stage
  if (newStage === 'closedwon') {
    await hubspot.enrollInWorkflow(dealId, 'customer_onboarding');
  }
};

// Salesforce: Complex opportunity management with validation
const progressOpportunity = async (opportunityId, newStage) => {
  // Get current opportunity
  const opp = await salesforce.getOpportunity(opportunityId);
  
  // Validate stage progression rules
  if (!isValidStageProgression(opp.StageName, newStage)) {
    throw new Error('Invalid stage progression');
  }
  
  // Update with required fields for stage
  const updateData = {
    StageName: newStage,
    ...getRequiredFieldsForStage(newStage)
  };
  
  await salesforce.updateOpportunity(opportunityId, updateData);
  
  // Trigger approval process if needed
  if (requiresApproval(newStage, opp.Amount)) {
    await salesforce.submitForApproval(opportunityId);
  }
};
```

## 🎯 Use Case Recommendations

### Small to Medium Business (SMB)
**Recommended:** HubSpot
- Lower total cost of ownership
- Easier implementation and maintenance
- Built-in marketing tools reduce need for additional platforms
- User-friendly for non-technical teams

### Enterprise Organizations
**Recommended:** Salesforce
- Advanced customization capabilities
- Enterprise security and compliance features
- Extensive integration ecosystem
- Supports complex business processes

### Marketing-Heavy Organizations
**Recommended:** HubSpot
- Superior marketing automation features
- Integrated content management
- Built-in social media tools
- Strong inbound marketing focus

### Sales-Heavy Organizations
**Recommended:** Salesforce
- Advanced sales process automation
- Comprehensive forecasting and reporting
- Territory and quota management
- Advanced opportunity management

## 🔗 Integration Ecosystem

### Common Integration Partners

**For HubSpot:**
- **Payments:** Stripe for subscription billing
- **Analytics:** Google Analytics for web tracking
- **Support:** Zendesk for customer service
- **E-commerce:** Shopify for online stores

**For Salesforce:**
- **Marketing:** Marketo, Pardot for advanced marketing automation
- **Analytics:** Tableau for advanced reporting
- **ERP:** NetSuite, SAP for business operations
- **Communication:** Slack, Microsoft Teams for collaboration

### Data Flow Patterns
```javascript
// Typical e-commerce integration flow
const ecommerceIntegration = {
  // Website -> HubSpot -> Stripe -> HubSpot
  leadCapture: async (formData) => {
    const contact = await hubspot.createContact(formData);
    const customer = await stripe.createCustomer({
      email: formData.email,
      metadata: { hubspot_contact_id: contact.id }
    });
    await hubspot.updateContact(contact.id, {
      stripe_customer_id: customer.id
    });
  },
  
  // Stripe -> HubSpot (via webhook)
  paymentSuccess: async (stripeEvent) => {
    const customerId = stripeEvent.customer;
    const customer = await stripe.retrieveCustomer(customerId);
    await hubspot.updateContact(customer.metadata.hubspot_contact_id, {
      lifecycle_stage: 'customer',
      last_purchase_date: new Date()
    });
  }
};
```

## 📊 Performance Considerations

### API Rate Limits
- **HubSpot:** 100 requests per 10 seconds (Professional/Enterprise)
- **Salesforce:** Varies by license type (5,000-100,000+ daily API calls)

### Bulk Operations
- **HubSpot:** Batch API for up to 100 records per request
- **Salesforce:** Bulk API for large data operations (up to 10,000 records)

### Real-time Updates
- **HubSpot:** Webhooks for immediate notifications
- **Salesforce:** Platform Events and Change Data Capture for real-time streaming

## 🛡️ Security Best Practices

### Authentication
```javascript
// HubSpot OAuth implementation
const hubspotOAuth = {
  getAuthUrl: () => {
    return `https://app.hubspot.com/oauth/authorize?` +
           `client_id=${CLIENT_ID}&` +
           `scope=contacts%20deals&` +
           `redirect_uri=${REDIRECT_URI}`;
  },
  
  exchangeCodeForTokens: async (code) => {
    // Implement OAuth code exchange
    const tokens = await hubspot.oauth.tokensApi.createToken(/* ... */);
    return tokens;
  }
};

// Salesforce Connected App setup
const salesforceOAuth = {
  getAuthUrl: () => {
    return `https://login.salesforce.com/services/oauth2/authorize?` +
           `response_type=code&` +
           `client_id=${CLIENT_ID}&` +
           `redirect_uri=${REDIRECT_URI}&` +
           `scope=api%20refresh_token`;
  }
};
```

### Data Protection
- Use field-level security in Salesforce for sensitive data
- Implement proper data retention policies
- Follow GDPR/CCPA guidelines for customer data
- Use encryption for data at rest and in transit

## 📚 Additional Resources

### Official Documentation
- [HubSpot Developer Documentation](https://developers.hubspot.com/)
- [Salesforce Developer Documentation](https://developer.salesforce.com/)

### Learning Resources
- [HubSpot Academy](https://academy.hubspot.com/) - Free CRM and marketing courses
- [Trailhead](https://trailhead.salesforce.com/) - Salesforce learning platform

### Community & Support
- [HubSpot Developer Community](https://community.hubspot.com/t5/HubSpot-Developers/ct-p/developers)
- [Salesforce Developer Forums](https://developer.salesforce.com/forums/)

## 🤝 Contributing

CRM integration primers should include:
- Platform-specific API examples
- Common business process implementations
- Integration patterns with other business systems
- Performance optimization techniques
- Security and compliance considerations

Each primer follows our standard structure with CRM-specific focus on business process automation and customer lifecycle management.