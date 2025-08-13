# Databox Primer

## Overview
Databox is a business analytics platform that aggregates data from multiple sources into unified dashboards and reports. It specializes in connecting various business tools and presenting KPIs and metrics in an easily digestible format for stakeholders.

## Key Features
- **Data Integration**: Connect 70+ data sources including Google Analytics, HubSpot, Salesforce, Facebook Ads
- **Custom Dashboards**: Drag-and-drop dashboard builder
- **Mobile App**: Native iOS/Android apps for on-the-go monitoring
- **Automated Reporting**: Scheduled reports and alerts
- **Goal Tracking**: Set and monitor performance targets
- **Data Studio**: Custom metric calculations and transformations

## API Overview
Databox provides several APIs for data integration and dashboard management:

- **Push API**: Send custom data to Databox
- **Query API**: Retrieve data and metrics
- **Dashboard API**: Manage dashboards and visualizations

### Base URL
```
https://push.databox.com
```

### Authentication
Databox uses API tokens for authentication:

```javascript
const headers = {
  'Content-Type': 'application/json',
  'User-Agent': 'YourApp/1.0',
  'Authorization': 'Basic ' + Buffer.from('YOUR_API_TOKEN:').toString('base64')
}
```

## Common Use Cases for Developers

### 1. Pushing Custom Data
```javascript
// Push single metric
const pushMetric = async (metric, value, date = null) => {
  const data = {
    $metric: metric,
    $value: value
  };
  
  if (date) {
    data.$date = date; // Format: YYYY-MM-DD or YYYY-MM-DD HH:mm:ss
  }

  const response = await fetch('https://push.databox.com', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'YourApp/1.0',
      'Authorization': 'Basic ' + Buffer.from('YOUR_API_TOKEN:').toString('base64')
    },
    body: JSON.stringify(data)
  });
  
  return response.json();
};

// Example usage
await pushMetric('website_visitors', 1250);
await pushMetric('revenue', 15000.50, '2023-12-01');
```

### 2. Batch Data Push
```javascript
// Push multiple metrics at once
const pushBatchMetrics = async (metrics) => {
  const response = await fetch('https://push.databox.com', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'YourApp/1.0',
      'Authorization': 'Basic ' + Buffer.from('YOUR_API_TOKEN:').toString('base64')
    },
    body: JSON.stringify(metrics)
  });
  
  return response.json();
};

// Example batch data
const batchData = [
  { $metric: 'sales', $value: 100, $date: '2023-12-01' },
  { $metric: 'leads', $value: 25, $date: '2023-12-01' },
  { $metric: 'conversion_rate', $value: 0.25, $date: '2023-12-01' }
];

await pushBatchMetrics(batchData);
```

### 3. Dimensional Data
```javascript
// Push data with dimensions for segmentation
const pushDimensionalData = async () => {
  const data = {
    $metric: 'sales',
    $value: 500,
    $date: '2023-12-01',
    region: 'North America',
    product: 'Premium Plan',
    channel: 'Organic Search'
  };

  const response = await fetch('https://push.databox.com', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'YourApp/1.0',
      'Authorization': 'Basic ' + Buffer.from('YOUR_API_TOKEN:').toString('base64')
    },
    body: JSON.stringify(data)
  });
  
  return response.json();
};
```

### 4. Query API Usage
```javascript
// Retrieve metrics data
const queryMetrics = async (metric, startDate, endDate) => {
  const params = new URLSearchParams({
    metric: metric,
    start_date: startDate,
    end_date: endDate
  });

  const response = await fetch(`https://api.databox.com/metrics?${params}`, {
    headers: {
      'Authorization': 'Bearer YOUR_QUERY_API_TOKEN'
    }
  });
  
  return response.json();
};
```

## SDKs and Libraries
- **PHP**: Official PHP SDK available
- **Python**: Community-maintained packages
- **Node.js**: REST API integration via HTTP clients
- **Ruby**: Community gems available

### Node.js Example with Axios
```javascript
const axios = require('axios');

class DataboxClient {
  constructor(token) {
    this.token = token;
    this.baseURL = 'https://push.databox.com';
  }

  async push(data) {
    try {
      const response = await axios.post(this.baseURL, data, {
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'MyApp/1.0',
          'Authorization': 'Basic ' + Buffer.from(`${this.token}:`).toString('base64')
        }
      });
      
      return response.data;
    } catch (error) {
      throw new Error(`Databox API Error: ${error.message}`);
    }
  }
}

// Usage
const client = new DataboxClient('your_token');
await client.push({ $metric: 'revenue', $value: 1000 });
```

## Rate Limits
- **Push API**: 1000 requests per minute per token
- **Query API**: 100 requests per minute per token
- **Burst allowance**: Short bursts above limits are tolerated

## Data Types and Formats

### Supported Metric Types
- **Numbers**: Integer or decimal values
- **Percentages**: Values between 0 and 1 (will be displayed as percentages)
- **Currency**: Numerical values (currency formatting handled in dashboard)
- **Durations**: Time values in seconds

### Date Formats
- `YYYY-MM-DD` for daily data
- `YYYY-MM-DD HH:mm:ss` for hourly/minute data
- ISO 8601 format supported
- Timezone handling: UTC recommended

## Dashboard Management

### Creating Custom Dashboards
```javascript
// Example dashboard configuration
const dashboardConfig = {
  name: "Sales Performance",
  metrics: [
    {
      metric: "revenue",
      visualization: "number",
      goal: 10000
    },
    {
      metric: "sales",
      visualization: "line_chart",
      time_period: "last_30_days"
    }
  ]
};
```

## Best Practices
1. **Batch Operations**: Send multiple metrics in single requests when possible
2. **Consistent Naming**: Use clear, consistent metric names
3. **Proper Dimensions**: Use dimensions for data segmentation
4. **Error Handling**: Implement retry logic for failed requests
5. **Data Validation**: Validate data before sending to avoid errors
6. **Timezone Awareness**: Always specify timezones or use UTC

## Common Gotchas
- Metric names are case-sensitive
- Historical data has limits (typically 2 years)
- Duplicate data points (same metric, date, dimensions) will overwrite
- API tokens are account-specific, not user-specific
- Date ranges in queries are inclusive
- Large batch requests may timeout

## Integration Patterns

### Real-time Data Sync
```javascript
// Example: Sync e-commerce data
const syncOrderData = async (orders) => {
  const metrics = [];
  
  orders.forEach(order => {
    metrics.push(
      { $metric: 'revenue', $value: order.total, $date: order.date },
      { $metric: 'orders', $value: 1, $date: order.date, product: order.product }
    );
  });
  
  return await pushBatchMetrics(metrics);
};
```

### Scheduled Data Updates
```javascript
// Example: Daily metrics aggregation
const dailySync = async () => {
  const yesterday = new Date();
  yesterday.setDate(yesterday.getDate() - 1);
  const dateStr = yesterday.toISOString().split('T')[0];
  
  // Aggregate your data
  const metrics = await aggregateDailyMetrics(dateStr);
  
  // Push to Databox
  return await pushBatchMetrics(metrics);
};

// Schedule with cron or similar
setInterval(dailySync, 24 * 60 * 60 * 1000); // Daily
```

## Resources
- [Databox Developer Documentation](https://developers.databox.com/)
- [Push API Documentation](https://developers.databox.com/docs/push-api)
- [Query API Documentation](https://developers.databox.com/docs/query-api)
- [Metric Builder Guide](https://help.databox.com/article/945-metric-builder)