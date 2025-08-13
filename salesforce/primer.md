# Salesforce Primer

## Overview
Salesforce is a cloud-based Customer Relationship Management (CRM) platform that provides tools for sales, marketing, customer service, and business analytics. It offers extensive customization capabilities and a robust API ecosystem for integrating with external applications.

## Key Features
- **Sales Cloud**: Lead and opportunity management, forecasting
- **Service Cloud**: Case management, knowledge base, live chat
- **Marketing Cloud**: Email marketing, automation, customer journeys
- **Commerce Cloud**: E-commerce platform and tools
- **Platform Tools**: Custom objects, workflows, automation
- **AppExchange**: Third-party app marketplace

## API Overview
Salesforce provides multiple APIs for different use cases:

- **REST API**: Standard CRUD operations, modern JSON-based
- **SOAP API**: Enterprise integration, strongly typed
- **Bulk API**: Large data operations (insert/update/delete)
- **Streaming API**: Real-time event notifications
- **Metadata API**: Deploy and retrieve configuration changes
- **Tooling API**: Development tools and IDE integration

### Base URLs
```
// REST API
https://yourinstance.salesforce.com/services/data/v58.0/

// SOAP API
https://yourinstance.salesforce.com/services/Soap/u/58.0/

// Bulk API
https://yourinstance.salesforce.com/services/async/58.0/
```

### Authentication
Salesforce uses OAuth 2.0 for authentication:

```javascript
// OAuth 2.0 Username-Password Flow
const getAccessToken = async () => {
  const params = new URLSearchParams({
    grant_type: 'password',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    username: USERNAME,
    password: PASSWORD + SECURITY_TOKEN
  });

  const response = await fetch('https://login.salesforce.com/services/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params
  });

  return response.json();
};

// Use access token in API calls
const headers = {
  'Authorization': `Bearer ${accessToken}`,
  'Content-Type': 'application/json'
};
```

## Common Use Cases for Developers

### 1. CRUD Operations on Standard Objects
```javascript
// Create a Lead
const createLead = async (leadData) => {
  const response = await fetch(`${instanceUrl}/services/data/v58.0/sobjects/Lead/`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      FirstName: leadData.firstName,
      LastName: leadData.lastName,
      Email: leadData.email,
      Company: leadData.company
    })
  });

  return response.json();
};

// Get Account by ID
const getAccount = async (accountId) => {
  const response = await fetch(
    `${instanceUrl}/services/data/v58.0/sobjects/Account/${accountId}`,
    {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    }
  );

  return response.json();
};

// Update Opportunity
const updateOpportunity = async (oppId, updates) => {
  const response = await fetch(
    `${instanceUrl}/services/data/v58.0/sobjects/Opportunity/${oppId}`,
    {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(updates)
    }
  );

  return response.status === 204;
};
```

### 2. SOQL Queries
```javascript
// Query records using SOQL
const queryRecords = async (soqlQuery) => {
  const encodedQuery = encodeURIComponent(soqlQuery);
  const response = await fetch(
    `${instanceUrl}/services/data/v58.0/query?q=${encodedQuery}`,
    {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    }
  );

  return response.json();
};

// Example queries
const getRecentOpportunities = async () => {
  const query = `
    SELECT Id, Name, Amount, StageName, CloseDate, Account.Name
    FROM Opportunity
    WHERE CreatedDate = LAST_N_DAYS:30
    ORDER BY CreatedDate DESC
    LIMIT 100
  `;
  
  return await queryRecords(query);
};

const getContactsWithAccounts = async () => {
  const query = `
    SELECT Id, Name, Email, Account.Name, Account.Industry
    FROM Contact
    WHERE Account.Industry != null
  `;
  
  return await queryRecords(query);
};
```

### 3. Custom Objects
```javascript
// Work with custom objects (note the __c suffix)
const createCustomRecord = async (customData) => {
  const response = await fetch(
    `${instanceUrl}/services/data/v58.0/sobjects/Custom_Product__c/`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        Name: customData.name,
        Category__c: customData.category,
        Price__c: customData.price
      })
    }
  );

  return response.json();
};
```

### 4. Bulk Operations
```javascript
// Bulk API for large data operations
const createBulkJob = async (operation, objectType) => {
  const jobData = {
    operation: operation, // insert, update, delete, upsert
    object: objectType,
    contentType: 'JSON',
    lineEnding: 'LF'
  };

  const response = await fetch(
    `${instanceUrl}/services/async/58.0/job`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(jobData)
    }
  );

  return response.json();
};

// Add batch to job
const addBatchToJob = async (jobId, records) => {
  const response = await fetch(
    `${instanceUrl}/services/async/58.0/job/${jobId}/batch`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(records)
    }
  );

  return response.json();
};
```

### 5. Metadata API Usage
```javascript
// Deploy metadata (requires JSZip or similar for package creation)
const deployMetadata = async (zipFileBase64) => {
  const deployOptions = {
    allowMissingFiles: false,
    autoUpdatePackage: false,
    checkOnly: false,
    ignoreWarnings: false,
    performRetrieve: false,
    purgeOnDelete: false,
    rollbackOnError: true,
    singlePackage: true
  };

  const soapBody = `
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:met="http://soap.sforce.com/2006/04/metadata">
      <soapenv:Header>
        <met:SessionHeader>
          <met:sessionId>${accessToken}</met:sessionId>
        </met:SessionHeader>
      </soapenv:Header>
      <soapenv:Body>
        <met:deploy>
          <met:ZipFile>${zipFileBase64}</met:ZipFile>
          <met:DeployOptions>
            <met:allowMissingFiles>${deployOptions.allowMissingFiles}</met:allowMissingFiles>
            <met:autoUpdatePackage>${deployOptions.autoUpdatePackage}</met:autoUpdatePackage>
            <met:checkOnly>${deployOptions.checkOnly}</met:checkOnly>
            <met:ignoreWarnings>${deployOptions.ignoreWarnings}</met:ignoreWarnings>
            <met:performRetrieve>${deployOptions.performRetrieve}</met:performRetrieve>
            <met:purgeOnDelete>${deployOptions.purgeOnDelete}</met:purgeOnDelete>
            <met:rollbackOnError>${deployOptions.rollbackOnError}</met:rollbackOnError>
            <met:singlePackage>${deployOptions.singlePackage}</met:singlePackage>
          </met:DeployOptions>
        </met:deploy>
      </soapenv:Body>
    </soapenv:Envelope>
  `;

  const response = await fetch(
    `${instanceUrl}/services/Soap/m/58.0/`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'text/xml; charset=UTF-8',
        'SOAPAction': 'deploy'
      },
      body: soapBody
    }
  );

  return response.text();
};
```

## SDKs and Libraries
- **JavaScript/Node.js**: `jsforce`, `@salesforce/core`
- **Python**: `simple-salesforce`, `salesforce-bulk`
- **Java**: `force-wsc`, `salesforce-sdk`
- **PHP**: `developerforce/force.com-toolkit-for-php`
- **.NET**: `DeveloperForce.Force`

### JSForce Example (Popular Node.js SDK)
```javascript
const jsforce = require('jsforce');

// Connection
const conn = new jsforce.Connection({
  loginUrl: 'https://login.salesforce.com'
});

// Login
await conn.login(username, password);

// Query
const result = await conn.query('SELECT Id, Name FROM Account LIMIT 5');

// Create record
const ret = await conn.sobject('Lead').create({
  FirstName: 'John',
  LastName: 'Doe',
  Email: 'john.doe@example.com',
  Company: 'Acme Corp'
});

// Bulk operations
const job = conn.bulk.createJob('Account', 'insert');
const batch = job.createBatch();
batch.execute(records);
```

## Rate Limits and Quotas
- **API Calls**: Varies by Salesforce edition (Developer: 15,000/day, Enterprise: 100,000/day)
- **Bulk API**: Separate limits for bulk operations
- **Concurrent Requests**: Up to 25 concurrent API calls
- **Data Storage**: Limited by Salesforce org storage limits

## Salesforce Object Model

### Standard Objects
- **Account**: Companies/Organizations
- **Contact**: Individual people
- **Lead**: Potential customers
- **Opportunity**: Sales deals
- **Case**: Customer service issues
- **Task/Event**: Activities and calendar items

### Relationships
```javascript
// Parent-to-Child (One-to-Many)
const accountWithContacts = await conn.query(`
  SELECT Id, Name, (SELECT Id, Name, Email FROM Contacts)
  FROM Account
  WHERE Id = '${accountId}'
`);

// Child-to-Parent (Many-to-One)
const contactsWithAccount = await conn.query(`
  SELECT Id, Name, Email, Account.Name, Account.Industry
  FROM Contact
  WHERE AccountId != null
`);
```

## Advanced Features

### Platform Events
```javascript
// Subscribe to platform events
const platformEventClient = new jsforce.StreamingExtension.Replay(
  '/event/Custom_Event__e',
  -1 // Replay from saved position
);

conn.streaming.subscribe('/event/Custom_Event__e', (message) => {
  console.log('Received platform event:', message);
});
```

### Change Data Capture (CDC)
```javascript
// Subscribe to data changes
conn.streaming.subscribe('/data/AccountChangeEvent', (message) => {
  console.log('Account changed:', message.payload);
});
```

### Apex REST Services
```javascript
// Call custom Apex REST service
const callApexRest = async (endpoint, method = 'GET', data = null) => {
  const response = await fetch(
    `${instanceUrl}/services/apexrest/${endpoint}`,
    {
      method,
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: data ? JSON.stringify(data) : null
    }
  );

  return response.json();
};
```

## Best Practices
1. **Use Bulk API**: For operations on more than 200 records
2. **Implement Proper Error Handling**: Handle API limits and errors gracefully
3. **Cache Access Tokens**: Tokens are valid for hours, don't get new ones for each request
4. **Use SOQL Efficiently**: Select only needed fields, use proper WHERE clauses
5. **Monitor API Usage**: Track API call consumption against limits
6. **Use Sandbox for Development**: Test against sandbox environments first

## Common Gotchas
- API field names are case-sensitive
- Custom fields and objects have `__c` suffix
- SOQL has different syntax than SQL (no `*`, different date formats)
- API limits are shared across all integrations in the org
- Large result sets require pagination with `nextRecordsUrl`
- Security tokens change when passwords are reset

## Environment Management
```javascript
// Different endpoints for different environments
const endpoints = {
  production: 'https://login.salesforce.com',
  sandbox: 'https://test.salesforce.com',
  scratch: 'https://MyDomainName--ScratchOrgName.my.salesforce.com'
};
```

## Error Handling
```javascript
const handleSalesforceError = (error) => {
  if (error.status === 401) {
    // Token expired, refresh or re-authenticate
    return refreshToken();
  } else if (error.status === 403) {
    // Insufficient permissions
    throw new Error('Insufficient permissions for this operation');
  } else if (error.status === 400) {
    // Bad request, check field validation
    console.error('Validation errors:', error.body);
  }
};
```

## Resources
- [Salesforce REST API Developer Guide](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/)
- [SOQL and SOSL Reference](https://developer.salesforce.com/docs/atlas.en-us.soql_sosl.meta/soql_sosl/)
- [Salesforce APIs Documentation](https://developer.salesforce.com/docs/apis)
- [Trailhead (Salesforce Learning Platform)](https://trailhead.salesforce.com/)
- [Salesforce DX Developer Guide](https://developer.salesforce.com/docs/atlas.en-us.sfdx_dev.meta/sfdx_dev/)