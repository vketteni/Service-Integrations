# Data Privacy and Compliance Considerations Primer

## Overview
Data privacy and compliance are critical aspects of modern API integrations. With regulations like GDPR, CCPA, HIPAA, and SOX, developers must implement proper data handling, consent management, and audit trails. This primer covers essential compliance requirements and practical implementation patterns for maintaining regulatory compliance across service integrations.

## Key Privacy Regulations

### GDPR (General Data Protection Regulation)
**Scope**: EU residents' personal data  
**Key Requirements**:
- Explicit consent for data processing
- Right to be forgotten (data deletion)
- Data portability rights
- Privacy by design principles
- 72-hour breach notification
- Data Processing Impact Assessments (DPIA)

### CCPA (California Consumer Privacy Act)
**Scope**: California residents' personal information  
**Key Requirements**:
- Right to know what data is collected
- Right to delete personal information
- Right to opt-out of sale of personal information
- Non-discrimination for privacy rights exercise

### HIPAA (Health Insurance Portability and Accountability Act)
**Scope**: Protected Health Information (PHI) in healthcare  
**Key Requirements**:
- Administrative, physical, and technical safeguards
- Minimum necessary standard
- Business Associate Agreements (BAAs)
- Breach notification requirements

### SOX (Sarbanes-Oxley Act)
**Scope**: Financial data and reporting  
**Key Requirements**:
- Internal controls over financial reporting
- Data integrity and accuracy
- Audit trails and documentation
- Management attestation

## Data Classification and Handling

### Data Classification System
```javascript
class DataClassifier {
  constructor() {
    this.classifications = {
      PUBLIC: {
        level: 0,
        description: 'Publicly available information',
        retention: 'indefinite',
        encryption: false
      },
      INTERNAL: {
        level: 1,
        description: 'Internal business information',
        retention: '7 years',
        encryption: false
      },
      CONFIDENTIAL: {
        level: 2,
        description: 'Sensitive business information',
        retention: '5 years',
        encryption: true
      },
      PII: {
        level: 3,
        description: 'Personally identifiable information',
        retention: 'varies by regulation',
        encryption: true,
        regulations: ['GDPR', 'CCPA']
      },
      PHI: {
        level: 4,
        description: 'Protected health information',
        retention: '6 years minimum',
        encryption: true,
        regulations: ['HIPAA']
      },
      FINANCIAL: {
        level: 4,
        description: 'Financial and payment data',
        retention: '7 years',
        encryption: true,
        regulations: ['SOX', 'PCI-DSS']
      }
    };
  }

  classifyData(data, context = {}) {
    const classification = this.determineClassification(data, context);
    
    return {
      classification: classification.level,
      type: this.getClassificationName(classification),
      requirements: this.getRequirements(classification),
      metadata: {
        timestamp: new Date().toISOString(),
        source: context.source || 'unknown',
        purpose: context.purpose || 'not specified'
      }
    };
  }

  determineClassification(data, context) {
    // Check for PHI indicators
    if (this.containsPHI(data)) {
      return this.classifications.PHI;
    }
    
    // Check for financial data
    if (this.containsFinancialData(data)) {
      return this.classifications.FINANCIAL;
    }
    
    // Check for PII
    if (this.containsPII(data)) {
      return this.classifications.PII;
    }
    
    // Default classification based on context
    return context.defaultClassification || this.classifications.INTERNAL;
  }

  containsPII(data) {
    const piiPatterns = [
      /\b\d{3}-\d{2}-\d{4}\b/, // SSN
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, // Email
      /\b\d{3}-\d{3}-\d{4}\b/, // Phone number
      /\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b/ // Credit card (basic pattern)
    ];
    
    const dataStr = JSON.stringify(data).toLowerCase();
    return piiPatterns.some(pattern => pattern.test(dataStr));
  }

  containsPHI(data) {
    const phiIndicators = [
      'medical_record', 'diagnosis', 'treatment', 'prescription',
      'patient_id', 'healthcare_provider', 'insurance_claim'
    ];
    
    const dataStr = JSON.stringify(data).toLowerCase();
    return phiIndicators.some(indicator => dataStr.includes(indicator));
  }

  containsFinancialData(data) {
    const financialIndicators = [
      'account_number', 'routing_number', 'credit_card',
      'bank_account', 'payment_method', 'transaction_amount'
    ];
    
    const dataStr = JSON.stringify(data).toLowerCase();
    return financialIndicators.some(indicator => dataStr.includes(indicator));
  }

  getRequirements(classification) {
    return {
      encryption: classification.encryption,
      retention: classification.retention,
      regulations: classification.regulations || [],
      auditRequired: classification.level >= 3
    };
  }

  getClassificationName(classification) {
    return Object.keys(this.classifications).find(
      key => this.classifications[key] === classification
    );
  }
}
```

### Data Masking and Pseudonymization
```javascript
const crypto = require('crypto');

class DataPrivacyManager {
  constructor(encryptionKey) {
    this.encryptionKey = encryptionKey;
    this.algorithm = 'aes-256-gcm';
  }

  // Pseudonymization - reversible with key
  pseudonymize(data, identifier) {
    const hash = crypto.createHmac('sha256', this.encryptionKey)
      .update(identifier + JSON.stringify(data))
      .digest('hex');
    
    return {
      pseudonymId: hash.substring(0, 16),
      encryptedData: this.encrypt(JSON.stringify(data)),
      timestamp: new Date().toISOString()
    };
  }

  // Anonymization - irreversible
  anonymize(data) {
    const anonymized = { ...data };
    
    // Remove direct identifiers
    delete anonymized.email;
    delete anonymized.phone;
    delete anonymized.ssn;
    delete anonymized.name;
    delete anonymized.address;
    
    // Generalize quasi-identifiers
    if (anonymized.age) {
      anonymized.ageRange = this.getAgeRange(anonymized.age);
      delete anonymized.age;
    }
    
    if (anonymized.zipCode) {
      anonymized.region = anonymized.zipCode.substring(0, 3) + '**';
      delete anonymized.zipCode;
    }
    
    return anonymized;
  }

  // Data masking for display/logging
  maskSensitiveData(data) {
    const masked = { ...data };
    
    // Mask email
    if (masked.email) {
      const [username, domain] = masked.email.split('@');
      masked.email = `${username.substring(0, 2)}***@${domain}`;
    }
    
    // Mask phone
    if (masked.phone) {
      masked.phone = masked.phone.replace(/\d(?=\d{4})/g, '*');
    }
    
    // Mask credit card
    if (masked.creditCard) {
      masked.creditCard = '**** **** **** ' + masked.creditCard.slice(-4);
    }
    
    // Mask SSN
    if (masked.ssn) {
      masked.ssn = '***-**-' + masked.ssn.slice(-4);
    }
    
    return masked;
  }

  encrypt(text) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipher(this.algorithm, this.encryptionKey);
    cipher.setAAD(Buffer.from('sensitive-data'));
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    };
  }

  decrypt(encryptedData) {
    const decipher = crypto.createDecipher(this.algorithm, this.encryptionKey);
    decipher.setAAD(Buffer.from('sensitive-data'));
    decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  getAgeRange(age) {
    if (age < 18) return '0-17';
    if (age < 25) return '18-24';
    if (age < 35) return '25-34';
    if (age < 45) return '35-44';
    if (age < 55) return '45-54';
    if (age < 65) return '55-64';
    return '65+';
  }
}
```

## Consent Management

### GDPR Consent Implementation
```javascript
class ConsentManager {
  constructor() {
    this.consentRecords = new Map();
    this.legalBases = {
      CONSENT: 'consent',
      CONTRACT: 'contract',
      LEGAL_OBLIGATION: 'legal_obligation',
      VITAL_INTERESTS: 'vital_interests',
      PUBLIC_TASK: 'public_task',
      LEGITIMATE_INTERESTS: 'legitimate_interests'
    };
  }

  recordConsent(userId, consentData) {
    const consentRecord = {
      userId,
      timestamp: new Date().toISOString(),
      consentId: this.generateConsentId(),
      purposes: consentData.purposes || [],
      legalBasis: consentData.legalBasis || this.legalBases.CONSENT,
      consentString: consentData.consentString,
      ipAddress: consentData.ipAddress,
      userAgent: consentData.userAgent,
      version: consentData.privacyPolicyVersion || '1.0',
      granular: consentData.granular || {},
      withdrawn: false,
      source: consentData.source || 'web'
    };

    // Validate consent requirements
    this.validateConsent(consentRecord);
    
    this.consentRecords.set(consentRecord.consentId, consentRecord);
    
    // Store in persistent storage
    this.persistConsentRecord(consentRecord);
    
    return consentRecord.consentId;
  }

  validateConsent(consent) {
    if (consent.legalBasis === this.legalBases.CONSENT) {
      if (!consent.consentString || !consent.purposes.length) {
        throw new Error('Explicit consent requires clear consent string and purposes');
      }
      
      if (!consent.ipAddress || !consent.userAgent) {
        throw new Error('Consent proof requires IP address and user agent');
      }
    }
  }

  withdrawConsent(consentId, withdrawalReason = 'User request') {
    const consent = this.consentRecords.get(consentId);
    if (!consent) {
      throw new Error('Consent record not found');
    }

    const withdrawal = {
      ...consent,
      withdrawn: true,
      withdrawnAt: new Date().toISOString(),
      withdrawalReason,
      originalConsentId: consentId,
      withdrawalId: this.generateConsentId()
    };

    this.consentRecords.set(consentId, withdrawal);
    this.persistConsentRecord(withdrawal);

    // Trigger data processing stop
    this.triggerDataProcessingStop(consent.userId, consent.purposes);

    return withdrawal.withdrawalId;
  }

  checkConsent(userId, purpose) {
    const userConsents = Array.from(this.consentRecords.values())
      .filter(record => record.userId === userId && !record.withdrawn)
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    const relevantConsent = userConsents.find(consent => 
      consent.purposes.includes(purpose) || 
      (consent.granular && consent.granular[purpose])
    );

    if (!relevantConsent) {
      return { allowed: false, reason: 'No consent found' };
    }

    // Check if consent is still valid (not expired)
    const consentAge = Date.now() - new Date(relevantConsent.timestamp).getTime();
    const maxAge = 365 * 24 * 60 * 60 * 1000; // 1 year

    if (consentAge > maxAge) {
      return { allowed: false, reason: 'Consent expired' };
    }

    return { 
      allowed: true, 
      consentId: relevantConsent.consentId,
      legalBasis: relevantConsent.legalBasis
    };
  }

  generateConsentProof(consentId) {
    const consent = this.consentRecords.get(consentId);
    if (!consent) {
      throw new Error('Consent record not found');
    }

    return {
      consentId,
      userId: consent.userId,
      timestamp: consent.timestamp,
      purposes: consent.purposes,
      legalBasis: consent.legalBasis,
      consentString: consent.consentString,
      technicalDetails: {
        ipAddress: this.hashIP(consent.ipAddress),
        userAgent: consent.userAgent,
        source: consent.source
      },
      verification: this.generateConsentHash(consent)
    };
  }

  generateConsentId() {
    return 'consent_' + crypto.randomBytes(16).toString('hex');
  }

  hashIP(ipAddress) {
    return crypto.createHash('sha256').update(ipAddress).digest('hex').substring(0, 16);
  }

  generateConsentHash(consent) {
    const consentString = JSON.stringify({
      userId: consent.userId,
      timestamp: consent.timestamp,
      purposes: consent.purposes,
      consentString: consent.consentString
    });
    
    return crypto.createHash('sha256').update(consentString).digest('hex');
  }

  async persistConsentRecord(consent) {
    // Store in database with encryption
    // Implementation depends on your storage solution
    console.log('Persisting consent record:', consent.consentId);
  }

  triggerDataProcessingStop(userId, purposes) {
    // Notify all data processors to stop processing
    console.log(`Stopping data processing for user ${userId}, purposes:`, purposes);
  }
}

// Express middleware for consent checking
const checkConsentMiddleware = (purpose) => {
  return (req, res, next) => {
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const consentManager = req.app.get('consentManager');
    const consentCheck = consentManager.checkConsent(userId, purpose);

    if (!consentCheck.allowed) {
      return res.status(403).json({ 
        error: 'Consent required',
        reason: consentCheck.reason,
        purpose: purpose
      });
    }

    req.consentId = consentCheck.consentId;
    req.legalBasis = consentCheck.legalBasis;
    next();
  };
};

// Usage
// app.post('/analytics/track', checkConsentMiddleware('analytics'), (req, res) => {
//   // Process analytics data only if consent exists
// });
```

## Data Subject Rights Implementation

### Right to be Forgotten (Data Deletion)
```javascript
class DataDeletionManager {
  constructor() {
    this.deletionRequests = new Map();
    this.dataLocations = [
      'primary_database',
      'analytics_warehouse',
      'backup_storage',
      'third_party_services',
      'log_files',
      'cache_systems'
    ];
  }

  async processDeleteionRequest(userId, requestDetails = {}) {
    const deletionId = this.generateDeletionId();
    
    const deletionRequest = {
      deletionId,
      userId,
      requestedAt: new Date().toISOString(),
      requestedBy: requestDetails.requestedBy || 'user',
      reason: requestDetails.reason || 'GDPR Article 17',
      status: 'initiated',
      verificationRequired: requestDetails.verificationRequired !== false,
      retentionExceptions: requestDetails.retentionExceptions || [],
      completedSteps: [],
      errors: []
    };

    this.deletionRequests.set(deletionId, deletionRequest);

    try {
      // Step 1: Verify identity if required
      if (deletionRequest.verificationRequired) {
        await this.verifyIdentity(userId, requestDetails.verificationData);
      }

      // Step 2: Check for legal retention requirements
      const retentionCheck = await this.checkRetentionRequirements(userId);
      if (retentionCheck.hasRetentionRequirements) {
        deletionRequest.retentionExceptions = retentionCheck.exceptions;
      }

      // Step 3: Execute deletion across all systems
      await this.executeComprehensiveDeletion(userId, deletionRequest);

      // Step 4: Generate deletion certificate
      const certificate = await this.generateDeletionCertificate(deletionRequest);

      deletionRequest.status = 'completed';
      deletionRequest.completedAt = new Date().toISOString();
      deletionRequest.certificate = certificate;

      return deletionRequest;
    } catch (error) {
      deletionRequest.status = 'failed';
      deletionRequest.errors.push({
        timestamp: new Date().toISOString(),
        error: error.message,
        step: 'execution'
      });
      throw error;
    }
  }

  async executeComprehensiveDeletion(userId, deletionRequest) {
    const deletionTasks = [];

    // Primary database deletion
    deletionTasks.push(this.deletePrimaryData(userId, deletionRequest));

    // Third-party service deletion
    deletionTasks.push(this.deleteThirdPartyData(userId, deletionRequest));

    // Backup and archive deletion
    deletionTasks.push(this.scheduleBackupDeletion(userId, deletionRequest));

    // Log file anonymization
    deletionTasks.push(this.anonymizeLogFiles(userId, deletionRequest));

    // Cache invalidation
    deletionTasks.push(this.invalidateCaches(userId));

    const results = await Promise.allSettled(deletionTasks);
    
    results.forEach((result, index) => {
      const location = this.dataLocations[index];
      if (result.status === 'fulfilled') {
        deletionRequest.completedSteps.push(location);
      } else {
        deletionRequest.errors.push({
          location,
          error: result.reason.message,
          timestamp: new Date().toISOString()
        });
      }
    });
  }

  async deletePrimaryData(userId, deletionRequest) {
    // Soft delete first for recovery period
    await this.softDeleteUserData(userId);
    
    // Schedule hard delete after legal retention period
    setTimeout(() => {
      this.hardDeleteUserData(userId);
    }, this.getRetentionPeriod('soft_delete'));

    return { location: 'primary_database', status: 'soft_deleted' };
  }

  async deleteThirdPartyData(userId, deletionRequest) {
    const thirdPartyServices = [
      { name: 'analytics', api: this.deleteFromAnalytics.bind(this) },
      { name: 'crm', api: this.deleteFromCRM.bind(this) },
      { name: 'email_service', api: this.deleteFromEmailService.bind(this) },
      { name: 'payment_processor', api: this.deleteFromPaymentProcessor.bind(this) }
    ];

    const deletionResults = [];
    
    for (const service of thirdPartyServices) {
      try {
        const result = await service.api(userId);
        deletionResults.push({ service: service.name, status: 'success', result });
      } catch (error) {
        deletionResults.push({ 
          service: service.name, 
          status: 'error', 
          error: error.message 
        });
      }
    }

    return deletionResults;
  }

  async deleteFromAnalytics(userId) {
    // Google Analytics User Deletion API
    // Implementation would call GA4 Data Deletion API
    return { deletedRecords: 0, estimatedCompletion: '72 hours' };
  }

  async deleteFromCRM(userId) {
    // CRM deletion (HubSpot, Salesforce, etc.)
    return { deletedContacts: 1, deletedDeals: 0 };
  }

  async generateDeletionCertificate(deletionRequest) {
    const certificate = {
      certificateId: crypto.randomBytes(16).toString('hex'),
      deletionId: deletionRequest.deletionId,
      userId: deletionRequest.userId,
      completedAt: deletionRequest.completedAt,
      scopeOfDeletion: deletionRequest.completedSteps,
      retentionExceptions: deletionRequest.retentionExceptions,
      verificationHash: this.generateVerificationHash(deletionRequest),
      legalBasis: 'GDPR Article 17 - Right to erasure',
      certification: 'This certificate confirms that personal data has been deleted in accordance with applicable data protection laws.'
    };

    return certificate;
  }

  generateDeletionId() {
    return 'del_' + crypto.randomBytes(16).toString('hex');
  }

  generateVerificationHash(deletionRequest) {
    const hashInput = JSON.stringify({
      deletionId: deletionRequest.deletionId,
      userId: deletionRequest.userId,
      completedSteps: deletionRequest.completedSteps.sort(),
      completedAt: deletionRequest.completedAt
    });
    
    return crypto.createHash('sha256').update(hashInput).digest('hex');
  }

  getRetentionPeriod(type) {
    const periods = {
      soft_delete: 30 * 24 * 60 * 60 * 1000, // 30 days
      legal_hold: 7 * 365 * 24 * 60 * 60 * 1000 // 7 years
    };
    
    return periods[type] || periods.soft_delete;
  }
}
```

### Data Portability Implementation
```javascript
class DataPortabilityManager {
  constructor() {
    this.exportFormats = ['json', 'csv', 'xml'];
    this.maxExportSize = 100 * 1024 * 1024; // 100MB
  }

  async generateDataExport(userId, exportRequest = {}) {
    const exportId = this.generateExportId();
    
    const exportJob = {
      exportId,
      userId,
      requestedAt: new Date().toISOString(),
      format: exportRequest.format || 'json',
      dataTypes: exportRequest.dataTypes || ['all'],
      status: 'initiated',
      progress: 0
    };

    try {
      // Verify user identity
      await this.verifyExportRequest(userId, exportRequest);

      // Collect data from all sources
      const userData = await this.collectUserData(userId, exportJob.dataTypes);
      
      // Transform to requested format
      const exportData = await this.transformData(userData, exportJob.format);
      
      // Check size limits
      if (exportData.size > this.maxExportSize) {
        throw new Error('Export size exceeds limit. Please request specific data types.');
      }

      // Generate secure download link
      const downloadInfo = await this.createSecureDownload(exportData, exportJob);
      
      exportJob.status = 'completed';
      exportJob.progress = 100;
      exportJob.downloadUrl = downloadInfo.url;
      exportJob.expiresAt = downloadInfo.expiresAt;
      exportJob.completedAt = new Date().toISOString();

      // Log export for audit
      await this.logDataExport(exportJob);

      return exportJob;
    } catch (error) {
      exportJob.status = 'failed';
      exportJob.error = error.message;
      throw error;
    }
  }

  async collectUserData(userId, dataTypes) {
    const userData = {
      profile: null,
      activities: [],
      preferences: {},
      communications: [],
      transactions: [],
      analytics: {}
    };

    if (dataTypes.includes('all') || dataTypes.includes('profile')) {
      userData.profile = await this.getUserProfile(userId);
    }

    if (dataTypes.includes('all') || dataTypes.includes('activities')) {
      userData.activities = await this.getUserActivities(userId);
    }

    if (dataTypes.includes('all') || dataTypes.includes('preferences')) {
      userData.preferences = await this.getUserPreferences(userId);
    }

    if (dataTypes.includes('all') || dataTypes.includes('communications')) {
      userData.communications = await this.getUserCommunications(userId);
    }

    if (dataTypes.includes('all') || dataTypes.includes('transactions')) {
      userData.transactions = await this.getUserTransactions(userId);
    }

    // Clean sensitive data before export
    return this.cleanSensitiveData(userData);
  }

  cleanSensitiveData(userData) {
    const cleaned = JSON.parse(JSON.stringify(userData));
    
    // Remove internal system fields
    this.removeInternalFields(cleaned);
    
    // Remove references to other users
    this.anonymizeUserReferences(cleaned);
    
    return cleaned;
  }

  async transformData(userData, format) {
    switch (format) {
      case 'json':
        return {
          data: JSON.stringify(userData, null, 2),
          filename: `user_data_${Date.now()}.json`,
          contentType: 'application/json',
          size: Buffer.byteLength(JSON.stringify(userData))
        };
      
      case 'csv':
        return {
          data: this.convertToCSV(userData),
          filename: `user_data_${Date.now()}.csv`,
          contentType: 'text/csv',
          size: Buffer.byteLength(this.convertToCSV(userData))
        };
      
      case 'xml':
        return {
          data: this.convertToXML(userData),
          filename: `user_data_${Date.now()}.xml`,
          contentType: 'application/xml',
          size: Buffer.byteLength(this.convertToXML(userData))
        };
      
      default:
        throw new Error('Unsupported export format');
    }
  }

  async createSecureDownload(exportData, exportJob) {
    // Generate temporary secure URL
    const downloadToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    
    // Store encrypted export data temporarily
    await this.storeTemporaryExport(downloadToken, exportData);
    
    return {
      url: `/api/exports/download/${downloadToken}`,
      expiresAt: expiresAt.toISOString(),
      filename: exportData.filename
    };
  }

  generateExportId() {
    return 'exp_' + crypto.randomBytes(16).toString('hex');
  }
}
```

## Audit Trail and Compliance Logging

### Comprehensive Audit System
```javascript
class ComplianceAuditLogger {
  constructor() {
    this.auditTypes = {
      DATA_ACCESS: 'data_access',
      DATA_MODIFICATION: 'data_modification',
      CONSENT_CHANGE: 'consent_change',
      DATA_EXPORT: 'data_export',
      DATA_DELETION: 'data_deletion',
      POLICY_CHANGE: 'policy_change',
      SECURITY_EVENT: 'security_event'
    };
    
    this.retentionPeriods = {
      GDPR: 6 * 365, // 6 years
      HIPAA: 6 * 365, // 6 years  
      SOX: 7 * 365, // 7 years
      CCPA: 24 * 30, // 24 months
      DEFAULT: 7 * 365 // 7 years
    };
  }

  async logEvent(eventData) {
    const auditEntry = {
      id: this.generateAuditId(),
      timestamp: new Date().toISOString(),
      eventType: eventData.type,
      userId: eventData.userId,
      actorId: eventData.actorId || eventData.userId,
      actorType: eventData.actorType || 'user', // user, admin, system, api
      resource: eventData.resource,
      action: eventData.action,
      outcome: eventData.outcome || 'success',
      details: eventData.details || {},
      ipAddress: this.hashIP(eventData.ipAddress),
      userAgent: eventData.userAgent,
      sessionId: eventData.sessionId,
      requestId: eventData.requestId,
      legalBasis: eventData.legalBasis,
      dataClassification: eventData.dataClassification,
      retentionDate: this.calculateRetentionDate(eventData.regulations || ['DEFAULT'])
    };

    // Add regulation-specific fields
    if (eventData.regulations) {
      auditEntry.regulations = eventData.regulations;
      auditEntry.complianceMetadata = this.generateComplianceMetadata(eventData);
    }

    // Encrypt sensitive audit data
    if (this.containsSensitiveData(auditEntry)) {
      auditEntry.encrypted = true;
      auditEntry.details = this.encryptAuditDetails(auditEntry.details);
    }

    // Store audit entry
    await this.persistAuditEntry(auditEntry);
    
    // Check for compliance alerts
    await this.checkComplianceAlerts(auditEntry);
    
    return auditEntry.id;
  }

  async logDataAccess(userId, resource, details = {}) {
    return await this.logEvent({
      type: this.auditTypes.DATA_ACCESS,
      userId: userId,
      resource: resource,
      action: 'read',
      details: {
        fields: details.fields || [],
        purpose: details.purpose,
        recordCount: details.recordCount || 1
      },
      ...details
    });
  }

  async logConsentChange(userId, consentId, changeType, details = {}) {
    return await this.logEvent({
      type: this.auditTypes.CONSENT_CHANGE,
      userId: userId,
      resource: `consent:${consentId}`,
      action: changeType, // granted, withdrawn, updated
      details: {
        consentId: consentId,
        purposes: details.purposes || [],
        legalBasis: details.legalBasis,
        previousState: details.previousState
      },
      legalBasis: details.legalBasis,
      regulations: ['GDPR', 'CCPA'],
      ...details
    });
  }

  async logDataDeletion(userId, deletionId, details = {}) {
    return await this.logEvent({
      type: this.auditTypes.DATA_DELETION,
      userId: userId,
      resource: `user:${userId}`,
      action: 'delete',
      details: {
        deletionId: deletionId,
        scope: details.scope || 'complete',
        retentionExceptions: details.retentionExceptions || [],
        thirdPartyDeletions: details.thirdPartyDeletions || []
      },
      regulations: ['GDPR', 'CCPA'],
      ...details
    });
  }

  generateComplianceReport(regulation, startDate, endDate) {
    const reportId = `report_${regulation}_${Date.now()}`;
    
    // This would query the audit database
    const auditEntries = this.queryAuditEntries({
      regulations: [regulation],
      startDate,
      endDate
    });

    const report = {
      reportId,
      regulation,
      period: { startDate, endDate },
      generatedAt: new Date().toISOString(),
      summary: this.generateComplianceSummary(auditEntries, regulation),
      events: auditEntries,
      recommendations: this.generateRecommendations(auditEntries, regulation)
    };

    return report;
  }

  generateComplianceSummary(auditEntries, regulation) {
    const summary = {
      totalEvents: auditEntries.length,
      eventsByType: {},
      dataSubjectRequests: 0,
      consentEvents: 0,
      securityIncidents: 0,
      averageResponseTime: 0
    };

    auditEntries.forEach(entry => {
      // Count by event type
      summary.eventsByType[entry.eventType] = 
        (summary.eventsByType[entry.eventType] || 0) + 1;
      
      // Count specific compliance events
      if (entry.eventType === this.auditTypes.DATA_EXPORT ||
          entry.eventType === this.auditTypes.DATA_DELETION) {
        summary.dataSubjectRequests++;
      }
      
      if (entry.eventType === this.auditTypes.CONSENT_CHANGE) {
        summary.consentEvents++;
      }
      
      if (entry.eventType === this.auditTypes.SECURITY_EVENT) {
        summary.securityIncidents++;
      }
    });

    return summary;
  }

  calculateRetentionDate(regulations) {
    const maxRetention = Math.max(
      ...regulations.map(reg => this.retentionPeriods[reg] || this.retentionPeriods.DEFAULT)
    );
    
    const retentionDate = new Date();
    retentionDate.setDate(retentionDate.getDate() + maxRetention);
    
    return retentionDate.toISOString();
  }

  generateAuditId() {
    return 'aud_' + crypto.randomBytes(16).toString('hex');
  }

  hashIP(ipAddress) {
    if (!ipAddress) return null;
    return crypto.createHash('sha256').update(ipAddress).digest('hex').substring(0, 16);
  }
}
```

## Data Breach Response

### Automated Breach Detection and Response
```javascript
class DataBreachResponseManager {
  constructor() {
    this.breachSeverityLevels = {
      LOW: { notificationWindow: 72, authorities: false },
      MEDIUM: { notificationWindow: 24, authorities: true },
      HIGH: { notificationWindow: 1, authorities: true, immediate: true },
      CRITICAL: { notificationWindow: 0.5, authorities: true, immediate: true }
    };
  }

  async detectAndRespondToBreach(securityEvent) {
    const breachId = this.generateBreachId();
    
    const breachAssessment = {
      breachId,
      detectedAt: new Date().toISOString(),
      eventType: securityEvent.type,
      affectedSystems: securityEvent.systems || [],
      potentialDataTypes: securityEvent.dataTypes || [],
      severity: this.assessBreachSeverity(securityEvent),
      affectedUserCount: securityEvent.affectedUsers?.length || 0,
      containmentStatus: 'initiated',
      notificationStatus: 'pending',
      regulatoryFiling: 'pending'
    };

    try {
      // Immediate containment
      await this.containBreach(breachAssessment);
      
      // Assess impact
      const impactAssessment = await this.assessBreachImpact(breachAssessment);
      breachAssessment.impactAssessment = impactAssessment;
      
      // Determine notification requirements
      const notificationPlan = this.determineNotificationRequirements(breachAssessment);
      breachAssessment.notificationPlan = notificationPlan;
      
      // Execute notifications
      if (notificationPlan.immediate) {
        await this.executeImmediateNotifications(breachAssessment);
      }
      
      // Schedule regulatory notifications
      await this.scheduleRegulatoryNotifications(breachAssessment);
      
      // Generate incident report
      const incidentReport = await this.generateIncidentReport(breachAssessment);
      breachAssessment.incidentReport = incidentReport;
      
      return breachAssessment;
    } catch (error) {
      breachAssessment.responseErrors = [{
        timestamp: new Date().toISOString(),
        error: error.message
      }];
      throw error;
    }
  }

  assessBreachSeverity(securityEvent) {
    let score = 0;
    
    // Data sensitivity scoring
    if (securityEvent.dataTypes?.includes('PHI')) score += 40;
    if (securityEvent.dataTypes?.includes('PII')) score += 30;
    if (securityEvent.dataTypes?.includes('FINANCIAL')) score += 35;
    if (securityEvent.dataTypes?.includes('CREDENTIALS')) score += 45;
    
    // Scope scoring
    const affectedUsers = securityEvent.affectedUsers?.length || 0;
    if (affectedUsers > 10000) score += 30;
    else if (affectedUsers > 1000) score += 20;
    else if (affectedUsers > 100) score += 10;
    
    // System criticality
    if (securityEvent.systems?.includes('production_database')) score += 25;
    if (securityEvent.systems?.includes('authentication_system')) score += 30;
    
    // Access type
    if (securityEvent.accessType === 'external_unauthorized') score += 35;
    if (securityEvent.accessType === 'internal_unauthorized') score += 20;
    
    // Determine severity level
    if (score >= 80) return 'CRITICAL';
    if (score >= 60) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    return 'LOW';
  }

  async containBreach(breachAssessment) {
    const containmentActions = [];
    
    // Revoke compromised credentials
    if (breachAssessment.eventType === 'credential_compromise') {
      containmentActions.push(this.revokeCompromisedCredentials(breachAssessment));
    }
    
    // Isolate affected systems
    if (breachAssessment.affectedSystems.length > 0) {
      containmentActions.push(this.isolateAffectedSystems(breachAssessment.affectedSystems));
    }
    
    // Block suspicious IP addresses
    if (breachAssessment.suspiciousIPs) {
      containmentActions.push(this.blockSuspiciousIPs(breachAssessment.suspiciousIPs));
    }
    
    const results = await Promise.allSettled(containmentActions);
    
    breachAssessment.containmentActions = results.map((result, index) => ({
      action: containmentActions[index].name || `action_${index}`,
      status: result.status,
      result: result.value,
      error: result.reason?.message
    }));
    
    breachAssessment.containmentStatus = 'completed';
  }

  determineNotificationRequirements(breachAssessment) {
    const requirements = {
      immediate: false,
      authorities: [],
      users: false,
      timeline: {},
      templates: []
    };
    
    const severity = breachAssessment.severity;
    const config = this.breachSeverityLevels[severity];
    
    // Determine if immediate notification required
    requirements.immediate = config.immediate || false;
    
    // GDPR requirements
    if (this.isGDPRApplicable(breachAssessment)) {
      requirements.authorities.push({
        authority: 'Data Protection Authority',
        deadline: new Date(Date.now() + (72 * 60 * 60 * 1000)), // 72 hours
        regulation: 'GDPR'
      });
      
      if (this.isHighRiskToBreach(breachAssessment)) {
        requirements.users = true;
        requirements.timeline.userNotification = new Date(Date.now() + (24 * 60 * 60 * 1000)); // 24 hours
      }
    }
    
    // CCPA requirements
    if (this.isCCPAApplicable(breachAssessment)) {
      requirements.authorities.push({
        authority: 'California Attorney General',
        deadline: new Date(Date.now() + (72 * 60 * 60 * 1000)),
        regulation: 'CCPA'
      });
    }
    
    // HIPAA requirements
    if (this.isHIPAAApplicable(breachAssessment)) {
      requirements.authorities.push({
        authority: 'HHS Office for Civil Rights',
        deadline: new Date(Date.now() + (60 * 24 * 60 * 60 * 1000)), // 60 days
        regulation: 'HIPAA'
      });
      
      requirements.users = true;
      requirements.timeline.userNotification = new Date(Date.now() + (60 * 24 * 60 * 60 * 1000));
    }
    
    return requirements;
  }

  async generateIncidentReport(breachAssessment) {
    const report = {
      reportId: `breach_report_${breachAssessment.breachId}`,
      breachId: breachAssessment.breachId,
      generatedAt: new Date().toISOString(),
      executiveSummary: this.generateExecutiveSummary(breachAssessment),
      timeline: this.generateBreachTimeline(breachAssessment),
      impactAnalysis: breachAssessment.impactAssessment,
      rootCauseAnalysis: await this.performRootCauseAnalysis(breachAssessment),
      containmentActions: breachAssessment.containmentActions,
      lessonsLearned: [],
      remediation: this.generateRemediationPlan(breachAssessment),
      complianceStatus: this.assessComplianceStatus(breachAssessment)
    };
    
    return report;
  }

  generateBreachId() {
    return 'breach_' + new Date().getFullYear() + '_' + crypto.randomBytes(8).toString('hex');
  }
}
```

## Platform-Specific Compliance Features

### Google Analytics Compliance
```javascript
class GoogleAnalyticsComplianceManager {
  constructor(analyticsConfig) {
    this.config = analyticsConfig;
    this.cookieConsent = new Map();
  }

  // GDPR-compliant analytics setup
  setupGDPRCompliantAnalytics() {
    return {
      // Anonymize IP addresses
      anonymize_ip: true,
      
      // Disable data sharing with Google
      allow_google_signals: false,
      allow_ad_personalization_signals: false,
      
      // Set data retention period
      data_retention: {
        event_data_retention: 'TWENTY_SIX_MONTHS',
        reset_user_data_on_new_activity: true
      },
      
      // Enhanced ecommerce settings
      enhanced_ecommerce: {
        anonymize_customer_data: true,
        exclude_pii_fields: ['customer_email', 'customer_name', 'customer_phone']
      },
      
      // Custom dimensions for consent tracking
      custom_dimensions: {
        analytics_consent: 'dimension1',
        marketing_consent: 'dimension2',
        consent_timestamp: 'dimension3'
      }
    };
  }

  // Check consent before sending data
  trackEventWithConsent(eventName, parameters, userId) {
    const consent = this.checkAnalyticsConsent(userId);
    
    if (!consent.analytics) {
      console.log('Analytics consent not granted, skipping event:', eventName);
      return;
    }
    
    // Add consent status to event parameters
    const enhancedParameters = {
      ...parameters,
      consent_mode: consent.consentMode,
      consent_timestamp: consent.timestamp
    };
    
    // Remove PII from parameters
    const cleanParameters = this.removePII(enhancedParameters);
    
    gtag('event', eventName, cleanParameters);
  }

  // User deletion request
  async deleteUserData(userId) {
    try {
      // Use Google Analytics 4 User Deletion API
      const response = await fetch('https://analyticsadmin.googleapis.com/v1alpha/properties/PROPERTY_ID:deleteUserData', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.config.accessToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          requests: [{
            userId: {
              userId: userId
            }
          }]
        })
      });
      
      if (!response.ok) {
        throw new Error(`Failed to delete user data: ${response.statusText}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error deleting user data from GA4:', error);
      throw error;
    }
  }

  removePII(parameters) {
    const piiFields = ['email', 'phone', 'name', 'address', 'ssn', 'user_id'];
    const cleaned = { ...parameters };
    
    piiFields.forEach(field => {
      delete cleaned[field];
    });
    
    return cleaned;
  }
}
```

### Stripe PCI DSS Compliance
```javascript
class StripePCIComplianceManager {
  constructor(stripeConfig) {
    this.config = stripeConfig;
  }

  // PCI-compliant payment processing
  async processPaymentSecurely(paymentData, complianceOptions = {}) {
    // Never store raw card data
    const {
      paymentMethodId,
      customerId,
      amount,
      currency = 'usd'
    } = paymentData;

    const paymentIntent = await stripe.paymentIntents.create({
      amount,
      currency,
      customer: customerId,
      payment_method: paymentMethodId,
      confirmation_method: 'manual',
      confirm: true,
      
      // PCI compliance settings
      capture_method: 'automatic',
      setup_future_usage: complianceOptions.saveCard ? 'off_session' : undefined,
      
      // Enhanced security
      radar: {
        session: complianceOptions.radarSession
      },
      
      metadata: {
        compliance_level: 'PCI_DSS_Level_1',
        data_classification: 'PAYMENT_DATA',
        retention_period: '7_years'
      }
    });

    // Log transaction for audit
    await this.logPaymentTransaction(paymentIntent, complianceOptions);
    
    return paymentIntent;
  }

  // Secure cardholder data handling
  handleCardholderData(cardData) {
    // Never log or store full PAN
    const maskedPAN = this.maskPAN(cardData.number);
    
    return {
      last4: cardData.number.slice(-4),
      brand: cardData.brand,
      exp_month: cardData.exp_month,
      exp_year: cardData.exp_year,
      // Never include: full PAN, CVV, PIN
      audit_trail: {
        masked_pan: maskedPAN,
        processed_at: new Date().toISOString(),
        compliance_level: 'PCI_DSS'
      }
    };
  }

  maskPAN(pan) {
    if (!pan || pan.length < 8) return '****';
    return pan.slice(0, 4) + '*'.repeat(pan.length - 8) + pan.slice(-4);
  }

  async logPaymentTransaction(paymentIntent, complianceOptions) {
    const auditEntry = {
      transaction_id: paymentIntent.id,
      timestamp: new Date().toISOString(),
      amount: paymentIntent.amount,
      currency: paymentIntent.currency,
      status: paymentIntent.status,
      customer_id: paymentIntent.customer,
      payment_method: {
        type: paymentIntent.payment_method?.type,
        last4: paymentIntent.payment_method?.card?.last4,
        brand: paymentIntent.payment_method?.card?.brand
      },
      compliance: {
        pci_scope: 'LEVEL_1',
        data_encrypted: true,
        audit_required: true,
        retention_years: 7
      }
    };
    
    // Store in secure audit database
    await this.storeComplianceAudit(auditEntry);
  }
}
```

## Testing Compliance Implementation

### Compliance Testing Framework
```javascript
class ComplianceTestSuite {
  constructor() {
    this.testResults = [];
  }

  async runGDPRTests(systemComponents) {
    const tests = [
      { name: 'Consent Recording', test: this.testConsentRecording.bind(this) },
      { name: 'Right to Access', test: this.testRightToAccess.bind(this) },
      { name: 'Right to Rectification', test: this.testRightToRectification.bind(this) },
      { name: 'Right to Erasure', test: this.testRightToErasure.bind(this) },
      { name: 'Data Portability', test: this.testDataPortability.bind(this) },
      { name: 'Breach Notification', test: this.testBreachNotification.bind(this) },
      { name: 'Privacy by Design', test: this.testPrivacyByDesign.bind(this) }
    ];

    const results = [];
    
    for (const testCase of tests) {
      try {
        const result = await testCase.test(systemComponents);
        results.push({
          name: testCase.name,
          passed: true,
          result: result,
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        results.push({
          name: testCase.name,
          passed: false,
          error: error.message,
          timestamp: new Date().toISOString()
        });
      }
    }

    this.testResults.push({
      regulation: 'GDPR',
      totalTests: tests.length,
      passed: results.filter(r => r.passed).length,
      failed: results.filter(r => !r.passed).length,
      details: results
    });

    return results;
  }

  async testConsentRecording(components) {
    const consentManager = components.consentManager;
    
    // Test consent recording
    const consentId = consentManager.recordConsent('test_user', {
      purposes: ['analytics', 'marketing'],
      legalBasis: 'consent',
      consentString: 'I agree to the processing of my personal data',
      ipAddress: '192.168.1.1',
      userAgent: 'Test Agent'
    });

    // Test consent retrieval
    const consentCheck = consentManager.checkConsent('test_user', 'analytics');
    
    if (!consentCheck.allowed) {
      throw new Error('Consent not properly recorded or retrieved');
    }

    // Test consent withdrawal
    const withdrawalId = consentManager.withdrawConsent(consentId, 'Test withdrawal');
    
    const postWithdrawalCheck = consentManager.checkConsent('test_user', 'analytics');
    if (postWithdrawalCheck.allowed) {
      throw new Error('Consent not properly withdrawn');
    }

    return { consentId, withdrawalId, status: 'passed' };
  }

  async testRightToErasure(components) {
    const deletionManager = components.deletionManager;
    
    // Create test user data
    const testUserId = 'test_user_deletion';
    
    // Process deletion request
    const deletionResult = await deletionManager.processDeleteionRequest(testUserId, {
      verificationRequired: false
    });
    
    if (deletionResult.status !== 'completed') {
      throw new Error('User deletion not completed successfully');
    }
    
    // Verify data is actually deleted
    const userData = await this.attemptDataRetrieval(testUserId);
    if (userData) {
      throw new Error('User data still accessible after deletion');
    }
    
    return { deletionId: deletionResult.deletionId, status: 'passed' };
  }

  generateComplianceReport() {
    const report = {
      reportId: `compliance_test_${Date.now()}`,
      generatedAt: new Date().toISOString(),
      summary: {
        totalRegulations: this.testResults.length,
        overallStatus: this.calculateOverallStatus(),
        recommendations: this.generateRecommendations()
      },
      regulationResults: this.testResults,
      nextTestDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() // 30 days
    };
    
    return report;
  }

  calculateOverallStatus() {
    const allTests = this.testResults.flatMap(r => r.details);
    const passedTests = allTests.filter(t => t.passed).length;
    const totalTests = allTests.length;
    
    const passRate = (passedTests / totalTests) * 100;
    
    if (passRate === 100) return 'COMPLIANT';
    if (passRate >= 90) return 'MOSTLY_COMPLIANT';
    if (passRate >= 70) return 'PARTIALLY_COMPLIANT';
    return 'NON_COMPLIANT';
  }
}
```

## Best Practices and Common Pitfalls

### Implementation Checklist
```javascript
const complianceChecklist = {
  dataMapping: [
    'Identify all personal data collection points',
    'Map data flows between systems',
    'Document data retention periods',
    'Classify data sensitivity levels',
    'Identify legal bases for processing'
  ],
  
  consentManagement: [
    'Implement granular consent collection',
    'Provide clear consent withdrawal mechanisms',
    'Maintain consent audit trails',
    'Regular consent refresh processes',
    'Age verification for minors'
  ],
  
  dataSubjectRights: [
    'Automated data access portals',
    'Efficient deletion processes',
    'Data rectification workflows',
    'Objection handling procedures',
    'Response time tracking'
  ],
  
  security: [
    'Data encryption at rest and in transit',
    'Access controls and authentication',
    'Regular security assessments',
    'Incident response procedures',
    'Staff training and awareness'
  ],
  
  documentation: [
    'Privacy policies and notices',
    'Data processing records',
    'Impact assessments (DPIA)',
    'Breach response plans',
    'Audit and compliance reports'
  ]
};
```

### Common Compliance Mistakes
```javascript
// ❌ BAD: Storing PII without proper classification
const userData = {
  email: 'user@example.com',
  ssn: '123-45-6789',
  creditCard: '4111111111111111'
};
// No encryption, no classification, no retention policy

// ✅ GOOD: Proper data handling
const classifiedUserData = dataClassifier.classifyData({
  email: 'user@example.com'
}, { purpose: 'service_delivery', legalBasis: 'contract' });

if (classifiedUserData.requirements.encryption) {
  classifiedUserData.encryptedData = privacyManager.encrypt(userData);
}

// ❌ BAD: Processing without consent check
function trackAnalytics(userId, event) {
  gtag('event', event.name, event.properties);
}

// ✅ GOOD: Consent-aware processing
function trackAnalytics(userId, event) {
  const consent = consentManager.checkConsent(userId, 'analytics');
  if (!consent.allowed) {
    console.log('Analytics consent not granted');
    return;
  }
  
  auditLogger.logDataAccess(userId, 'analytics', {
    purpose: 'analytics',
    legalBasis: consent.legalBasis
  });
  
  gtag('event', event.name, privacyManager.removePII(event.properties));
}
```

## Resources

### Regulatory Documentation
- [GDPR Official Text](https://gdpr-info.eu/)
- [CCPA California Attorney General](https://oag.ca.gov/privacy/ccpa)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/)

### Implementation Tools
- **Consent Management**: OneTrust, Cookiebot, TrustArc
- **Data Discovery**: Microsoft Purview, Varonis, BigID  
- **Privacy Engineering**: PrivacyOps, DataGrail, Osano
- **Encryption**: AWS KMS, HashiCorp Vault, Azure Key Vault

### Legal Resources
- **GDPR**: European Data Protection Board (EDPB)
- **CCPA**: California Privacy Protection Agency
- **HIPAA**: HHS Office for Civil Rights
- **International**: International Association of Privacy Professionals (IAPP)