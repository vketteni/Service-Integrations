# Analytics & Data Platform Integrations

This directory contains primers for integrating with analytics and business intelligence platforms. These services help track user behavior, measure business performance, and create data-driven insights.

## Available Analytics Platforms

### [Google Analytics](./google-analytics/primer.md)
**Best for:** Web analytics, user behavior tracking, conversion analysis

**Key Features:**
- Comprehensive web and app analytics with GA4
- Real-time user behavior tracking
- Conversion funnel analysis and attribution
- Integration with Google Ads and Search Console
- Custom events and goal tracking

**Use When:**
- Tracking website and mobile app performance
- Understanding user journey and behavior patterns
- Measuring marketing campaign effectiveness
- Need free, robust analytics platform
- Want integration with Google marketing ecosystem

### [Databox](./databox/primer.md)
**Best for:** Business KPI dashboards, multi-source data aggregation

**Key Features:**
- Connects to 70+ business tools and data sources
- Pre-built dashboards for common business metrics
- Mobile app for on-the-go monitoring
- Custom KPI tracking and goal setting
- Automated reporting and alerts

**Use When:**
- Need unified dashboard across multiple tools
- Want to track business KPIs in real-time
- Building executive dashboards and reports
- Consolidating data from CRM, analytics, and marketing tools
- Need mobile access to business metrics

## 🔄 Integration Comparison

| Feature | Google Analytics | Databox |
|---------|------------------|---------|
| **Primary Focus** | Web/App Analytics | Business Dashboards |
| **Data Sources** | Website, Mobile Apps | 70+ Business Tools |
| **Learning Curve** | Medium | Low |
| **Setup Time** | 1-2 weeks | 3-5 days |
| **Customization** | High | Medium |
| **Real-time Data** | Yes | Yes |
| **Free Tier** | Yes (generous) | Limited |
| **Mobile App** | Yes | Yes (excellent) |
| **API Complexity** | High | Low |

## 🚀 Common Integration Patterns

### E-commerce Tracking
```javascript
// Google Analytics 4: Enhanced E-commerce tracking
const trackPurchase = async (transactionData) => {
  // Track purchase event
  await ga4.track('purchase', {
    transaction_id: transactionData.orderId,
    value: transactionData.total,
    currency: 'USD',
    items: transactionData.items.map(item => ({
      item_id: item.sku,
      item_name: item.name,
      category: item.category,
      quantity: item.quantity,
      price: item.price
    }))
  });
  
  // Send to Databox for business dashboard
  await databox.push([{
    key: 'revenue',
    value: transactionData.total,
    date: new Date().toISOString()
  }, {
    key: 'orders',
    value: 1,
    date: new Date().toISOString()
  }]);
};

// Combined funnel tracking
const trackFunnelStep = async (step, userId, metadata = {}) => {
  // Track in GA4 for detailed analysis
  await ga4.track('funnel_step', {
    step_name: step,
    user_id: userId,
    ...metadata
  });
  
  // Track conversion rate in Databox
  await databox.push({
    key: `funnel_${step}`,
    value: 1,
    date: new Date().toISOString()
  });
};
```

### SaaS Metrics Tracking
```javascript
// Track user engagement across platforms
const trackUserEngagement = async (userId, action, properties) => {
  // Detailed event tracking in GA4
  await ga4.track('user_engagement', {
    user_id: userId,
    engagement_time_msec: properties.duration,
    action: action,
    page_location: properties.page,
    custom_parameters: properties.custom
  });
  
  // Business metrics in Databox
  const metrics = [];
  
  if (action === 'feature_used') {
    metrics.push({
      key: `feature_usage_${properties.feature}`,
      value: 1,
      date: new Date().toISOString()
    });
  }
  
  if (action === 'session_start') {
    metrics.push({
      key: 'daily_active_users',
      value: 1,
      date: new Date().toISOString()
    });
  }
  
  if (metrics.length > 0) {
    await databox.push(metrics);
  }
};

// Subscription metrics tracking
const trackSubscriptionMetrics = async (subscriptionData) => {
  // Track subscription events in GA4
  await ga4.track('subscription_change', {
    user_id: subscriptionData.userId,
    subscription_tier: subscriptionData.tier,
    event_type: subscriptionData.eventType, // upgrade, downgrade, cancel
    mrr_change: subscriptionData.mrrChange
  });
  
  // Update business KPIs in Databox
  await databox.push([
    {
      key: 'mrr',
      value: subscriptionData.totalMrr,
      date: new Date().toISOString()
    },
    {
      key: 'active_subscriptions',
      value: subscriptionData.activeCount,
      date: new Date().toISOString()
    },
    {
      key: `${subscriptionData.eventType}_rate`,
      value: 1,
      date: new Date().toISOString()
    }
  ]);
};
```

### Marketing Attribution
```javascript
// Cross-platform attribution tracking
const trackMarketingAttribution = async (conversionData) => {
  // Detailed attribution in GA4
  await ga4.track('conversion', {
    campaign: conversionData.campaign,
    source: conversionData.source,
    medium: conversionData.medium,
    content: conversionData.content,
    conversion_value: conversionData.value,
    attribution_model: 'last_click'
  });
  
  // Campaign performance in Databox
  await databox.push([
    {
      key: `conversions_${conversionData.campaign}`,
      value: 1,
      date: new Date().toISOString()
    },
    {
      key: `revenue_${conversionData.source}`,
      value: conversionData.value,
      date: new Date().toISOString()
    },
    {
      key: 'total_conversions',
      value: 1,
      date: new Date().toISOString()
    }
  ]);
};
```

## 🎯 Use Case Recommendations

### Content Websites & Blogs
**Recommended:** Google Analytics
- Comprehensive page view and user behavior tracking
- Content performance analysis
- Audience insights and demographics
- Integration with Google Search Console for SEO insights

### E-commerce Stores
**Recommended:** Google Analytics + Databox
- GA4 for detailed customer journey analysis
- Databox for real-time sales and inventory dashboards
- Combined approach for both detailed analysis and executive reporting

### SaaS Applications
**Recommended:** Google Analytics + Databox
- GA4 for user engagement and feature usage tracking
- Databox for business metrics (MRR, churn, DAU/MAU)
- Custom event tracking for product analytics

### Enterprise Organizations
**Recommended:** Databox + Custom Analytics
- Databox for unified business intelligence dashboards
- Integration with enterprise tools (Salesforce, HubSpot, etc.)
- Custom analytics solutions for specific business needs

## 🔗 Analytics Integration Ecosystem

### Common Data Flow Patterns
```javascript
// Multi-platform analytics pipeline
const analyticsePipeline = {
  // Website events -> GA4 + Databox
  trackWebEvent: async (eventData) => {
    await Promise.all([
      ga4.track(eventData.event, eventData.parameters),
      databox.push({
        key: eventData.businessMetric,
        value: eventData.value,
        date: new Date().toISOString()
      })
    ]);
  },
  
  // CRM data -> Databox dashboard
  syncCRMMetrics: async (crmData) => {
    const metrics = [
      { key: 'leads_generated', value: crmData.newLeads },
      { key: 'deals_closed', value: crmData.closedDeals },
      { key: 'revenue_closed', value: crmData.revenue }
    ].map(metric => ({
      ...metric,
      date: new Date().toISOString()
    }));
    
    await databox.push(metrics);
  },
  
  // Payment events -> Analytics
  syncPaymentData: async (paymentData) => {
    // Track in GA4 for attribution analysis
    await ga4.track('purchase', {
      transaction_id: paymentData.id,
      value: paymentData.amount,
      currency: paymentData.currency
    });
    
    // Update business metrics in Databox
    await databox.push([
      { key: 'revenue', value: paymentData.amount },
      { key: 'transactions', value: 1 }
    ].map(metric => ({
      ...metric,
      date: new Date().toISOString()
    })));
  }
};
```

### Integration with Business Tools
- **CRM Integration:** Sync lead and customer data for complete funnel analysis
- **Email Marketing:** Track campaign performance and user engagement
- **Customer Support:** Monitor support ticket metrics and customer satisfaction
- **Financial Systems:** Connect revenue and financial data for business intelligence

## 📊 Metrics Strategy Framework

### The Analytics Hierarchy
```
Business Outcomes (What matters to the business)
    ↑
Key Performance Indicators (KPIs that drive outcomes)
    ↑
Actionable Metrics (Metrics you can influence)
    ↑
Vanity Metrics (Nice to know but not actionable)
```

### Essential Metrics by Business Type

**E-commerce:**
- **Business Outcomes:** Revenue, Profit Margin, Customer Lifetime Value
- **KPIs:** Conversion Rate, Average Order Value, Customer Acquisition Cost
- **Actionable:** Cart Abandonment Rate, Page Load Time, Product Page Views
- **Vanity:** Total Page Views, Social Media Followers

**SaaS:**
- **Business Outcomes:** Monthly Recurring Revenue (MRR), Churn Rate, Customer Lifetime Value
- **KPIs:** User Activation Rate, Feature Adoption, Net Promoter Score
- **Actionable:** Time to First Value, Daily/Monthly Active Users, Support Ticket Volume
- **Vanity:** Total Sign-ups, App Downloads

**Content/Media:**
- **Business Outcomes:** Ad Revenue, Subscription Revenue, Brand Awareness
- **KPIs:** Engagement Rate, Time on Site, Content Conversion Rate
- **Actionable:** Bounce Rate, Content Consumption Depth, Email Sign-up Rate
- **Vanity:** Total Page Views, Social Shares

## 🛡️ Privacy & Compliance

### Data Privacy Considerations
```javascript
// Privacy-compliant analytics implementation
const privacyCompliantTracking = {
  // Respect user consent
  trackWithConsent: async (eventData, userConsent) => {
    if (userConsent.analytics) {
      await ga4.track(eventData.event, {
        ...eventData.parameters,
        // Anonymize IP by default in GA4
        anonymize_ip: true
      });
    }
    
    if (userConsent.businessMetrics) {
      // Business metrics without PII
      await databox.push({
        key: eventData.businessMetric,
        value: eventData.value,
        date: new Date().toISOString()
        // No user identifiers included
      });
    }
  },
  
  // GDPR-compliant user deletion
  deleteUserData: async (userId) => {
    // GA4 user deletion request
    await ga4.requestUserDeletion(userId);
    
    // Remove user-specific data from custom systems
    await customAnalytics.deleteUser(userId);
  }
};
```

### Compliance Best Practices
- **GDPR/CCPA:** Implement proper consent management
- **Data Retention:** Set appropriate data retention policies
- **Anonymization:** Remove or hash personal identifiers
- **User Rights:** Provide data export and deletion capabilities

## 📈 Performance Optimization

### Analytics Performance Best Practices
```javascript
// Optimized analytics implementation
const optimizedAnalytics = {
  // Batch events to reduce API calls
  eventQueue: [],
  
  track: function(event, properties) {
    this.eventQueue.push({ event, properties, timestamp: Date.now() });
    
    // Batch send every 5 seconds or 10 events
    if (this.eventQueue.length >= 10) {
      this.flush();
    }
  },
  
  flush: async function() {
    if (this.eventQueue.length === 0) return;
    
    const events = this.eventQueue.splice(0);
    
    try {
      // Send to GA4 in batch
      await ga4.batchTrack(events);
      
      // Send business metrics to Databox
      const businessMetrics = events
        .filter(e => e.businessMetric)
        .map(e => ({
          key: e.businessMetric,
          value: e.value || 1,
          date: new Date(e.timestamp).toISOString()
        }));
      
      if (businessMetrics.length > 0) {
        await databox.push(businessMetrics);
      }
    } catch (error) {
      console.error('Analytics batch send failed:', error);
      // Could implement retry logic here
    }
  }
};

// Auto-flush every 5 seconds
setInterval(() => optimizedAnalytics.flush(), 5000);
```

## 📚 Additional Resources

### Official Documentation
- [Google Analytics 4 Documentation](https://developers.google.com/analytics/devguides/collection/ga4)
- [Databox API Documentation](https://databox.com/developers/)

### Learning Resources
- [Google Analytics Academy](https://analytics.google.com/analytics/academy/) - Free GA training
- [Databox University](https://databox.com/university/) - Dashboard and KPI best practices

### Tools & Libraries
- **Google Analytics:** `gtag`, `@google-analytics/data`, `google-analytics-data`
- **Databox:** Official SDK, REST API
- **Privacy:** `@analytics/privacy-utils`, `cookieconsent`

## 🤝 Contributing

Analytics integration primers should include:
- Platform-specific tracking implementations
- Privacy-compliant data collection patterns
- Business metrics and KPI frameworks
- Performance optimization techniques
- Multi-platform integration strategies

Each primer follows our standard structure with analytics-specific focus on data collection, privacy compliance, and business intelligence.