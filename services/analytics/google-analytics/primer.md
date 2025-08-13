# Google Analytics Primer

## Overview
Google Analytics is a web analytics service that tracks and reports website traffic, user behavior, and conversion metrics. Google Analytics 4 (GA4) is the current version, replacing Universal Analytics, and provides enhanced measurement capabilities with a focus on events and user-centric data.

## Key Features
- **Traffic Analysis**: Page views, sessions, user demographics
- **Event Tracking**: Custom events, conversions, goals
- **Audience Insights**: User segments, cohort analysis
- **E-commerce Tracking**: Revenue, transactions, product performance
- **Real-time Reporting**: Live user activity monitoring
- **Attribution Modeling**: Multi-channel conversion paths

## API Overview
Google Analytics provides several APIs for data access and management:

- **Google Analytics Reporting API v4**: Access GA4 data
- **Google Analytics Data API**: New GA4-specific API
- **Management API**: Configure GA properties and accounts
- **Real Time Reporting API**: Access real-time data

### Base URL
```
https://analyticsreporting.googleapis.com/v4/reports:batchGet
https://analyticsdata.googleapis.com/v1beta/properties/{property_id}:runReport
```

### Authentication
Google Analytics uses OAuth 2.0 or Service Account credentials:

```javascript
// OAuth 2.0
const { google } = require('googleapis');

const oauth2Client = new google.auth.OAuth2(
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URL
);

oauth2Client.setCredentials({
  access_token: ACCESS_TOKEN,
  refresh_token: REFRESH_TOKEN
});

// Service Account
const auth = new google.auth.GoogleAuth({
  keyFile: 'path/to/service-account-key.json',
  scopes: ['https://www.googleapis.com/auth/analytics.readonly']
});
```

## Common Use Cases for Developers

### 1. GA4 Data API - Basic Report
```javascript
const { BetaAnalyticsDataClient } = require('@google-analytics/data');

const analyticsDataClient = new BetaAnalyticsDataClient({
  keyFilename: 'path/to/service-account-key.json'
});

async function runReport() {
  const [response] = await analyticsDataClient.runReport({
    property: `properties/${GA4_PROPERTY_ID}`,
    dateRanges: [
      {
        startDate: '7daysAgo',
        endDate: 'today',
      },
    ],
    dimensions: [
      {
        name: 'country',
      },
      {
        name: 'city',
      },
    ],
    metrics: [
      {
        name: 'activeUsers',
      },
      {
        name: 'sessions',
      },
    ],
  });

  return response;
}
```

### 2. Real-time Data
```javascript
async function getRealTimeData() {
  const [response] = await analyticsDataClient.runRealtimeReport({
    property: `properties/${GA4_PROPERTY_ID}`,
    dimensions: [
      {
        name: 'country',
      },
    ],
    metrics: [
      {
        name: 'activeUsers',
      },
    ],
  });

  return response;
}
```

### 3. E-commerce Data
```javascript
async function getEcommerceData() {
  const [response] = await analyticsDataClient.runReport({
    property: `properties/${GA4_PROPERTY_ID}`,
    dateRanges: [
      {
        startDate: '30daysAgo',
        endDate: 'today',
      },
    ],
    dimensions: [
      {
        name: 'itemName',
      },
      {
        name: 'itemCategory',
      },
    ],
    metrics: [
      {
        name: 'purchaseRevenue',
      },
      {
        name: 'itemsPurchased',
      },
    ],
  });

  return response;
}
```

### 4. Custom Events Query
```javascript
async function getCustomEvents() {
  const [response] = await analyticsDataClient.runReport({
    property: `properties/${GA4_PROPERTY_ID}`,
    dateRanges: [
      {
        startDate: '7daysAgo',
        endDate: 'today',
      },
    ],
    dimensions: [
      {
        name: 'eventName',
      },
      {
        name: 'customEvent:button_name', // Custom parameter
      },
    ],
    metrics: [
      {
        name: 'eventCount',
      },
    ],
    dimensionFilter: {
      filter: {
        fieldName: 'eventName',
        stringFilter: {
          value: 'button_click',
          matchType: 'EXACT',
        },
      },
    },
  });

  return response;
}
```

### 5. Universal Analytics (Legacy) - Reporting API v4
```javascript
const { google } = require('googleapis');

async function getUniversalAnalyticsData() {
  const analytics = google.analytics('v3');
  
  const response = await analytics.data.ga.get({
    auth: oauth2Client,
    ids: `ga:${VIEW_ID}`,
    'start-date': '7daysAgo',
    'end-date': 'today',
    metrics: 'ga:sessions,ga:users,ga:pageviews',
    dimensions: 'ga:country,ga:browser'
  });

  return response.data;
}
```

## SDKs and Libraries
- **Node.js**: `@google-analytics/data`, `googleapis`
- **Python**: `google-analytics-data`, `google-api-python-client`
- **PHP**: `google/analytics-data`
- **Java**: `google-analytics-data`
- **C#**: `Google.Analytics.Data`

### Node.js Setup Example
```javascript
// Install dependencies
// npm install @google-analytics/data googleapis

const { BetaAnalyticsDataClient } = require('@google-analytics/data');

class GoogleAnalyticsService {
  constructor(keyFilename, propertyId) {
    this.analyticsDataClient = new BetaAnalyticsDataClient({
      keyFilename: keyFilename
    });
    this.propertyId = propertyId;
  }

  async getBasicMetrics(startDate = '7daysAgo', endDate = 'today') {
    const [response] = await this.analyticsDataClient.runReport({
      property: `properties/${this.propertyId}`,
      dateRanges: [{ startDate, endDate }],
      metrics: [
        { name: 'activeUsers' },
        { name: 'sessions' },
        { name: 'screenPageViews' }
      ]
    });

    return this.formatResponse(response);
  }

  formatResponse(response) {
    const { rows, metricHeaders } = response;
    return rows.map(row => {
      const metrics = {};
      row.metricValues.forEach((value, index) => {
        metrics[metricHeaders[index].name] = value.value;
      });
      return metrics;
    });
  }
}
```

## Rate Limits and Quotas
- **GA4 Data API**: 25,000 requests per day (free), higher limits for paid accounts
- **Real-time API**: 10 requests per second per property
- **Management API**: 300 requests per minute per project
- **Concurrent requests**: Maximum 10 concurrent requests

## Key Concepts

### GA4 Event-Based Model
Unlike Universal Analytics, GA4 uses an event-based data model:

```javascript
// Everything is an event in GA4
const eventTypes = [
  'page_view',      // Automatic
  'session_start',  // Automatic
  'purchase',       // Enhanced e-commerce
  'login',          // Custom event
  'sign_up',        // Custom event
  'button_click'    // Custom event
];
```

### Dimensions vs Metrics
- **Dimensions**: Qualitative attributes (country, page, device)
- **Metrics**: Quantitative measurements (users, sessions, revenue)

```javascript
const commonDimensions = [
  'country', 'city', 'browser', 'deviceType',
  'pagePath', 'eventName', 'source', 'medium'
];

const commonMetrics = [
  'activeUsers', 'sessions', 'screenPageViews',
  'purchaseRevenue', 'eventCount', 'conversions'
];
```

## Advanced Querying

### Filtering Data
```javascript
async function getFilteredData() {
  const [response] = await analyticsDataClient.runReport({
    property: `properties/${GA4_PROPERTY_ID}`,
    dateRanges: [{ startDate: '30daysAgo', endDate: 'today' }],
    dimensions: [{ name: 'pagePath' }],
    metrics: [{ name: 'screenPageViews' }],
    dimensionFilter: {
      filter: {
        fieldName: 'pagePath',
        stringFilter: {
          value: '/product',
          matchType: 'CONTAINS'
        }
      }
    },
    orderBys: [
      {
        metric: {
          metricName: 'screenPageViews'
        },
        desc: true
      }
    ],
    limit: 10
  });

  return response;
}
```

### Cohort Analysis
```javascript
async function getCohortData() {
  const [response] = await analyticsDataClient.runReport({
    property: `properties/${GA4_PROPERTY_ID}`,
    dateRanges: [{ startDate: '30daysAgo', endDate: 'today' }],
    dimensions: [
      { name: 'cohort' },
      { name: 'cohortNthDay' }
    ],
    metrics: [
      { name: 'cohortActiveUsers' },
      { name: 'cohortTotalUsers' }
    ],
    cohortSpec: {
      cohorts: [
        {
          name: 'cohort_1',
          dateRange: { startDate: '30daysAgo', endDate: '30daysAgo' }
        }
      ],
      cohortsRange: {
        granularity: 'DAILY',
        startOffset: 0,
        endOffset: 29
      }
    }
  });

  return response;
}
```

## Best Practices
1. **Use Service Accounts**: More reliable than OAuth for server-to-server communication
2. **Implement Caching**: Cache reports that don't need real-time data
3. **Batch Requests**: Use batch requests when possible to reduce API calls
4. **Handle Quotas**: Implement exponential backoff for rate limiting
5. **Validate Property IDs**: Ensure correct GA4 property IDs are used
6. **Monitor API Usage**: Track API quota consumption

## Common Gotchas
- GA4 property IDs are different from Universal Analytics view IDs
- Data processing delay: GA4 data can take 24-48 hours to appear
- Sampling may occur on large datasets
- Custom dimensions/metrics need to be configured in GA4 interface first
- Date ranges are inclusive of start and end dates
- Different metric names between UA and GA4

## Migration from Universal Analytics

### Key Differences
```javascript
// Universal Analytics (deprecated)
const uaMetrics = ['ga:sessions', 'ga:users', 'ga:pageviews'];
const uaDimensions = ['ga:country', 'ga:browser'];

// GA4 equivalent
const ga4Metrics = ['sessions', 'activeUsers', 'screenPageViews'];
const ga4Dimensions = ['country', 'browser'];
```

### Data Model Changes
- Sessions → Events (everything is an event in GA4)
- Users → Active Users (different calculation)
- Pageviews → Screen/Page Views
- Goals → Conversions (event-based)

## Resources
- [Google Analytics Data API Documentation](https://developers.google.com/analytics/devguides/reporting/data/v1)
- [GA4 Dimensions & Metrics Reference](https://developers.google.com/analytics/devguides/reporting/data/v1/api-schema)
- [Migration Guide from Universal Analytics](https://developers.google.com/analytics/devguides/migration)
- [Google Analytics Intelligence API](https://developers.google.com/analytics/devguides/reporting/intelligence/v1)