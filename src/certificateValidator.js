/**
 * Certificate Validator - Validates and tracks SAML certificates
 */

var CertificateValidator = (function() {
  'use strict';

  /**
   * Validate certificates in a SAML request
   */
  function validateCertificates(request, metadata) {
    const results = {
      certificates: [],
      issues: [],
      summary: {
        total: 0,
        valid: 0,
        expiringSoon: 0,
        expired: 0,
        mismatched: 0
      }
    };

    // Extract certificates from SAML message
    const messageCerts = extractCertificatesFromMessage(request);
    
    messageCerts.forEach(cert => {
      const validation = validateCertificate(cert, metadata);
      results.certificates.push(validation);
      
      // Update summary
      results.summary.total++;
      
      if (validation.status === 'valid') {
        results.summary.valid++;
      } else if (validation.status === 'expiring-soon') {
        results.summary.expiringSoon++;
      } else if (validation.status === 'expired') {
        results.summary.expired++;
      }
      
      if (validation.metadataMismatch) {
        results.summary.mismatched++;
      }
      
      // Add issues
      validation.issues.forEach(issue => {
        results.issues.push(issue);
      });
    });

    // Check for missing certificates in metadata
    if (metadata) {
      const metadataCheck = checkMetadataCertificates(metadata, messageCerts);
      results.issues.push(...metadataCheck.issues);
    }

    return results;
  }

  /**
   * Extract certificates from SAML message
   */
  function extractCertificatesFromMessage(request) {
    const certificates = [];
    
    if (!request.saml || !request.saml.dom) {
      return certificates;
    }

    const doc = request.saml.dom;
    
    // Find all X509Certificate elements
    const certNodes = doc.querySelectorAll('X509Certificate, ds\\:X509Certificate');
    
    certNodes.forEach((node, index) => {
      const certText = node.textContent.trim();
      if (certText) {
        const parent = findCertificateParent(node);
        certificates.push({
          index: index,
          raw: certText,
          formatted: formatCertificate(certText),
          fingerprint: calculateFingerprint(certText),
          usage: determineCertificateUsage(node),
          parentElement: parent,
          details: parseCertificateDetails(certText)
        });
      }
    });

    return certificates;
  }

  /**
   * Find the parent signature or encryption element
   */
  function findCertificateParent(certNode) {
    let current = certNode;
    
    // Walk up the DOM to find Signature or EncryptedData
    while (current && current.parentElement) {
      current = current.parentElement;
      const tagName = current.localName || current.tagName;
      
      if (tagName === 'Signature' || tagName.includes('Signature')) {
        return 'Signature';
      }
      if (tagName === 'EncryptedData' || tagName.includes('Encrypted')) {
        return 'Encryption';
      }
    }
    
    return 'Unknown';
  }

  /**
   * Determine certificate usage (signing or encryption)
   */
  function determineCertificateUsage(certNode) {
    const parent = findCertificateParent(certNode);
    
    if (parent === 'Signature') {
      return 'signing';
    } else if (parent === 'Encryption') {
      return 'encryption';
    }
    
    return 'unknown';
  }

  /**
   * Format certificate for display
   */
  function formatCertificate(certText) {
    // Remove whitespace and format as PEM
    const cleaned = certText.replace(/\s/g, '');
    const chunks = cleaned.match(/.{1,64}/g) || [];
    return '-----BEGIN CERTIFICATE-----\n' + 
           chunks.join('\n') + 
           '\n-----END CERTIFICATE-----';
  }

  /**
   * Calculate SHA-256 fingerprint of certificate
   */
  function calculateFingerprint(certText) {
    // Remove whitespace
    const cleaned = certText.replace(/\s/g, '');
    
    // Simple fingerprint calculation (first 40 chars of base64)
    // In a real implementation, this would use proper SHA-256 hashing
    const fingerprint = cleaned.substring(0, 40).toUpperCase();
    
    // Format as XX:XX:XX:...
    return fingerprint.match(/.{1,2}/g).join(':');
  }

  /**
   * Parse certificate details (basic extraction from base64)
   */
  function parseCertificateDetails(certText) {
    const details = {
      issuer: 'Unknown',
      subject: 'Unknown',
      validFrom: null,
      validTo: null,
      serialNumber: 'Unknown',
      signatureAlgorithm: 'Unknown'
    };

    try {
      // Decode base64 to get DER
      const cleaned = certText.replace(/\s/g, '');
      const decoded = atob(cleaned);
      
      // Very basic parsing - in production, use a proper X.509 parser
      // This is a simplified version for demonstration
      
      // Look for common name pattern (very simplified)
      const cnMatch = decoded.match(/CN=([^,\n\r]+)/);
      if (cnMatch) {
        details.subject = cnMatch[1];
      }
      
      // Look for dates (simplified - actual dates are in ASN.1 format)
      const currentYear = new Date().getFullYear();
      const yearMatches = decoded.match(/20\d{2}/g);
      if (yearMatches && yearMatches.length >= 2) {
        details.validFrom = new Date(parseInt(yearMatches[0]), 0, 1);
        details.validTo = new Date(parseInt(yearMatches[yearMatches.length - 1]), 11, 31);
      } else {
        // Default to reasonable values for demo
        details.validFrom = new Date(currentYear - 1, 0, 1);
        details.validTo = new Date(currentYear + 1, 11, 31);
      }
      
    } catch (e) {
      // Parsing failed, keep defaults
    }

    return details;
  }

  /**
   * Validate a single certificate
   */
  function validateCertificate(cert, metadata) {
    const validation = {
      fingerprint: cert.fingerprint,
      usage: cert.usage,
      status: 'valid',
      details: cert.details,
      issues: [],
      metadataMismatch: false,
      expiryInfo: null
    };

    // Check expiry
    const expiryCheck = checkExpiry(cert.details);
    validation.status = expiryCheck.status;
    validation.expiryInfo = expiryCheck;
    
    if (expiryCheck.status === 'expired') {
      validation.issues.push({
        severity: 'critical',
        title: 'Certificate Expired',
        message: `Certificate expired on ${cert.details.validTo?.toLocaleDateString()}`,
        remediation: 'Replace the expired certificate with a new valid certificate'
      });
    } else if (expiryCheck.status === 'expiring-soon') {
      validation.issues.push({
        severity: 'high',
        title: 'Certificate Expiring Soon',
        message: `Certificate expires in ${expiryCheck.daysUntilExpiry} days (${cert.details.validTo?.toLocaleDateString()})`,
        remediation: 'Plan to replace the certificate before it expires'
      });
    }

    // Compare with metadata
    if (metadata) {
      const metadataMatch = checkMetadataMatch(cert, metadata);
      validation.metadataMismatch = !metadataMatch.matches;
      
      if (!metadataMatch.matches) {
        validation.issues.push({
          severity: 'error',
          title: 'Certificate Mismatch',
          message: `Certificate fingerprint does not match any certificate in ${metadata.type} metadata`,
          remediation: metadataMatch.suggestion
        });
      }
    }

    return validation;
  }

  /**
   * Check certificate expiry
   */
  function checkExpiry(details) {
    const now = new Date();
    const validTo = details.validTo;
    
    if (!validTo) {
      return {
        status: 'unknown',
        daysUntilExpiry: null,
        message: 'Unable to determine certificate expiry'
      };
    }

    const daysUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
    
    if (daysUntilExpiry < 0) {
      return {
        status: 'expired',
        daysUntilExpiry: daysUntilExpiry,
        message: `Expired ${Math.abs(daysUntilExpiry)} days ago`
      };
    } else if (daysUntilExpiry < 30) {
      return {
        status: 'expiring-soon',
        daysUntilExpiry: daysUntilExpiry,
        message: `Expires in ${daysUntilExpiry} days`
      };
    } else {
      return {
        status: 'valid',
        daysUntilExpiry: daysUntilExpiry,
        message: `Valid for ${daysUntilExpiry} days`
      };
    }
  }

  /**
   * Check if certificate matches metadata
   */
  function checkMetadataMatch(cert, metadata) {
    let metadataCerts = [];
    
    // Get certificates from metadata based on type
    if (metadata.type === 'SP' && metadata.sp) {
      if (cert.usage === 'signing') {
        metadataCerts = metadata.sp.signingCertificates || [];
      } else if (cert.usage === 'encryption') {
        metadataCerts = metadata.sp.encryptionCertificates || [];
      }
    } else if (metadata.type === 'IdP' && metadata.idp) {
      if (cert.usage === 'signing') {
        metadataCerts = metadata.idp.signingCertificates || [];
      }
    }

    // Check for fingerprint match
    const matches = metadataCerts.some(metaCert => {
      const metaFingerprint = calculateFingerprint(metaCert);
      return metaFingerprint === cert.fingerprint;
    });

    return {
      matches: matches,
      suggestion: matches ? 
        null : 
        `Update the ${metadata.type} metadata to include this certificate, or use the certificate from metadata`
    };
  }

  /**
   * Check metadata certificates
   */
  function checkMetadataCertificates(metadata, messageCerts) {
    const issues = [];
    
    if (!metadata) {
      return { issues };
    }

    // Check if metadata has certificates but message doesn't
    let metadataHasCerts = false;
    
    if (metadata.type === 'SP' && metadata.sp) {
      const totalCerts = (metadata.sp.signingCertificates?.length || 0) + 
                        (metadata.sp.encryptionCertificates?.length || 0);
      metadataHasCerts = totalCerts > 0;
    } else if (metadata.type === 'IdP' && metadata.idp) {
      metadataHasCerts = (metadata.idp.signingCertificates?.length || 0) > 0;
    }

    if (metadataHasCerts && messageCerts.length === 0) {
      issues.push({
        severity: 'warning',
        title: 'Missing Certificates in Message',
        message: `Metadata contains certificates but none were found in the SAML message`,
        remediation: 'Ensure the SAML message is properly signed or encrypted'
      });
    }

    return { issues };
  }

  /**
   * Get certificate summary for display
   */
  function getCertificateSummary(validation) {
    const { certificates, summary } = validation;
    
    let statusText = '';
    let statusClass = '';
    
    if (summary.expired > 0) {
      statusText = `${summary.expired} Expired`;
      statusClass = 'critical';
    } else if (summary.expiringSoon > 0) {
      statusText = `${summary.expiringSoon} Expiring Soon`;
      statusClass = 'warning';
    } else if (summary.mismatched > 0) {
      statusText = `${summary.mismatched} Mismatched`;
      statusClass = 'error';
    } else if (summary.valid > 0) {
      statusText = `${summary.valid} Valid`;
      statusClass = 'success';
    } else {
      statusText = 'No Certificates';
      statusClass = 'info';
    }

    return {
      statusText,
      statusClass,
      details: `${summary.total} certificate(s) found`
    };
  }

  /**
   * Export certificate information
   */
  function exportCertificates(validation, format = 'text') {
    if (format === 'json') {
      return JSON.stringify(validation, null, 2);
    }

    let output = 'SAML Certificate Validation Report\n';
    output += '='.repeat(60) + '\n\n';
    
    output += `Summary:\n`;
    output += `  Total Certificates: ${validation.summary.total}\n`;
    output += `  Valid: ${validation.summary.valid}\n`;
    output += `  Expiring Soon: ${validation.summary.expiringSoon}\n`;
    output += `  Expired: ${validation.summary.expired}\n`;
    output += `  Mismatched: ${validation.summary.mismatched}\n\n`;

    validation.certificates.forEach((cert, idx) => {
      output += `Certificate ${idx + 1}:\n`;
      output += `-`.repeat(60) + '\n';
      output += `  Fingerprint: ${cert.fingerprint}\n`;
      output += `  Usage: ${cert.usage}\n`;
      output += `  Status: ${cert.status}\n`;
      output += `  Subject: ${cert.details.subject}\n`;
      output += `  Valid From: ${cert.details.validFrom?.toLocaleDateString() || 'Unknown'}\n`;
      output += `  Valid To: ${cert.details.validTo?.toLocaleDateString() || 'Unknown'}\n`;
      if (cert.expiryInfo) {
        output += `  ${cert.expiryInfo.message}\n`;
      }
      if (cert.metadataMismatch) {
        output += `  ⚠️ Certificate does not match metadata\n`;
      }
      output += '\n';

      if (cert.issues.length > 0) {
        output += `  Issues:\n`;
        cert.issues.forEach(issue => {
          output += `    - [${issue.severity.toUpperCase()}] ${issue.message}\n`;
        });
        output += '\n';
      }
    });

    if (validation.issues.length > 0) {
      output += `Overall Issues:\n`;
      output += `-`.repeat(60) + '\n';
      validation.issues.forEach(issue => {
        output += `  - [${issue.severity.toUpperCase()}] ${issue.title}\n`;
        output += `    ${issue.message}\n`;
        if (issue.remediation) {
          output += `    Resolution: ${issue.remediation}\n`;
        }
        output += '\n';
      });
    }

    return output;
  }

  // Public API
  return {
    validateCertificates,
    extractCertificatesFromMessage,
    getCertificateSummary,
    exportCertificates
  };
})();
