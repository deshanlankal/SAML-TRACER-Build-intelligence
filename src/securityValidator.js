/**
 * Security Validator - Validates SAML security best practices
 */

var SecurityValidator = (function() {
  'use strict';

  // Known weak algorithms
  const WEAK_SIGNATURE_ALGORITHMS = [
    'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    'http://www.w3.org/2000/09/xmldsig#dsa-sha1'
  ];

  const WEAK_DIGEST_ALGORITHMS = [
    'http://www.w3.org/2000/09/xmldsig#sha1'
  ];

  const STRONG_SIGNATURE_ALGORITHMS = [
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'
  ];

  /**
   * Validate security of a SAML message
   */
  function validateSecurity(request) {
    const results = {
      timestamp: new Date().toISOString(),
      checks: [],
      summary: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        passed: 0
      },
      securityScore: 0
    };

    if (!request.saml) {
      return results;
    }

    const samlDoc = parseSAMLDocument(request.saml);
    if (!samlDoc) {
      return results;
    }

    const response = samlDoc.querySelector('Response');
    const assertion = response ? response.querySelector('Assertion') : samlDoc.querySelector('Assertion');
    const authnRequest = samlDoc.querySelector('AuthnRequest');

    if (response && assertion) {
      validateResponse(response, assertion, results);
    } else if (authnRequest) {
      validateAuthnRequest(authnRequest, results);
    }

    // Calculate security score
    calculateSecurityScore(results);

    return results;
  }

  /**
   * Validate SAML Response security
   */
  function validateResponse(response, assertion, results) {
    // Check Response signature
    const responseSignature = response.querySelector(':scope > Signature');
    const assertionSignature = assertion.querySelector(':scope > Signature');

    if (!responseSignature && !assertionSignature) {
      addCheck(results, 'critical', 'No Signature', 
        'Neither Response nor Assertion is signed',
        'SAML responses should be signed to prevent tampering. Configure IdP to sign either the Response or Assertion.',
        '❌');
    } else if (!responseSignature) {
      addCheck(results, 'medium', 'Response Not Signed',
        'Response is not signed (only Assertion is signed)',
        'For better security, sign both Response and Assertion.',
        '⚠️');
    } else {
      addCheck(results, 'passed', 'Response Signed',
        'Response is digitally signed',
        null,
        '✓');
    }

    // Check Assertion signature
    if (assertionSignature) {
      addCheck(results, 'passed', 'Assertion Signed',
        'Assertion is digitally signed',
        null,
        '✓');
      
      // Check signature algorithm
      validateSignatureAlgorithm(assertionSignature, results, 'Assertion');
    } else {
      addCheck(results, 'high', 'Assertion Not Signed',
        'Assertion is not signed - security risk',
        'Configure IdP to sign assertions to prevent assertion modification.',
        '❌');
    }

    if (responseSignature) {
      validateSignatureAlgorithm(responseSignature, results, 'Response');
    }

    // Check Assertion encryption
    const encryptedAssertion = response.querySelector('EncryptedAssertion');
    if (encryptedAssertion) {
      addCheck(results, 'passed', 'Assertion Encrypted',
        'Assertion is encrypted for confidentiality',
        null,
        '✓');
    } else {
      addCheck(results, 'medium', 'Assertion Not Encrypted',
        'Assertion is sent in plaintext',
        'Consider encrypting assertions when transmitting sensitive attributes.',
        '⚠️');
    }

    // Check Conditions element
    const conditions = assertion.querySelector('Conditions');
    if (conditions) {
      validateConditions(conditions, results);
    } else {
      addCheck(results, 'high', 'Missing Conditions',
        'No Conditions element found in assertion',
        'Add Conditions with NotBefore, NotOnOrAfter, and AudienceRestriction to prevent replay attacks.',
        '❌');
    }

    // Check Subject Confirmation
    const subjectConfirmation = assertion.querySelector('SubjectConfirmation');
    if (subjectConfirmation) {
      validateSubjectConfirmation(subjectConfirmation, results);
    } else {
      addCheck(results, 'high', 'Missing Subject Confirmation',
        'No SubjectConfirmation found',
        'Add SubjectConfirmation to validate the assertion recipient.',
        '❌');
    }

    // Check for AuthnStatement
    const authnStatement = assertion.querySelector('AuthnStatement');
    if (authnStatement) {
      const sessionNotOnOrAfter = authnStatement.getAttribute('SessionNotOnOrAfter');
      if (!sessionNotOnOrAfter) {
        addCheck(results, 'low', 'No Session Expiration',
          'AuthnStatement has no SessionNotOnOrAfter',
          'Set session expiration to limit session lifetime.',
          'ℹ️');
      }
    }
  }

  /**
   * Validate AuthnRequest security
   */
  function validateAuthnRequest(authnRequest, results) {
    // Check if request is signed
    const signature = authnRequest.querySelector('Signature');
    if (signature) {
      addCheck(results, 'passed', 'AuthnRequest Signed',
        'AuthnRequest is signed',
        null,
        '✓');
      validateSignatureAlgorithm(signature, results, 'AuthnRequest');
    } else {
      addCheck(results, 'low', 'AuthnRequest Not Signed',
        'AuthnRequest is not signed',
        'Signing AuthnRequests prevents tampering but is often not required.',
        'ℹ️');
    }

    // Check for ForceAuthn
    const forceAuthn = authnRequest.getAttribute('ForceAuthn');
    if (forceAuthn === 'true') {
      addCheck(results, 'passed', 'Force Authentication',
        'ForceAuthn is enabled for enhanced security',
        null,
        '✓');
    }

    // Check Issuer
    const issuer = authnRequest.querySelector('Issuer');
    if (!issuer) {
      addCheck(results, 'medium', 'Missing Issuer',
        'No Issuer element in AuthnRequest',
        'Include Issuer to identify the requesting SP.',
        '⚠️');
    }
  }

  /**
   * Validate signature algorithm strength
   */
  function validateSignatureAlgorithm(signatureElement, results, context) {
    const signatureMethod = signatureElement.querySelector('SignedInfo SignatureMethod');
    const digestMethod = signatureElement.querySelector('SignedInfo Reference DigestMethod');

    if (signatureMethod) {
      const algorithm = signatureMethod.getAttribute('Algorithm');
      
      if (WEAK_SIGNATURE_ALGORITHMS.includes(algorithm)) {
        addCheck(results, 'critical', `Weak Signature Algorithm (${context})`,
          `Using SHA-1 signature: ${algorithm}`,
          'Upgrade to SHA-256 or stronger. SHA-1 is deprecated and vulnerable to collision attacks.',
          '❌');
      } else if (STRONG_SIGNATURE_ALGORITHMS.includes(algorithm)) {
        addCheck(results, 'passed', `Strong Signature Algorithm (${context})`,
          `Using secure algorithm: ${getAlgorithmName(algorithm)}`,
          null,
          '✓');
      }
    }

    if (digestMethod) {
      const algorithm = digestMethod.getAttribute('Algorithm');
      
      if (WEAK_DIGEST_ALGORITHMS.includes(algorithm)) {
        addCheck(results, 'critical', `Weak Digest Algorithm (${context})`,
          `Using SHA-1 digest: ${algorithm}`,
          'Upgrade digest method to SHA-256 or stronger.',
          '❌');
      }
    }
  }

  /**
   * Validate Conditions element
   */
  function validateConditions(conditions, results) {
    const notBefore = conditions.getAttribute('NotBefore');
    const notOnOrAfter = conditions.getAttribute('NotOnOrAfter');
    
    if (!notBefore || !notOnOrAfter) {
      addCheck(results, 'high', 'Incomplete Conditions',
        'Missing NotBefore or NotOnOrAfter attributes',
        'Set time boundaries to prevent replay attacks.',
        '❌');
      return;
    }

    const now = new Date();
    const notBeforeDate = new Date(notBefore);
    const notOnOrAfterDate = new Date(notOnOrAfter);
    
    // Check validity window
    const validityWindow = (notOnOrAfterDate - notBeforeDate) / 1000 / 60; // minutes
    
    if (validityWindow > 60) {
      addCheck(results, 'medium', 'Long Validity Window',
        `Assertion valid for ${Math.round(validityWindow)} minutes`,
        'Consider reducing validity window to 5-15 minutes to minimize replay attack risk.',
        '⚠️');
    } else if (validityWindow <= 15) {
      addCheck(results, 'passed', 'Appropriate Validity Window',
        `Assertion valid for ${Math.round(validityWindow)} minutes`,
        null,
        '✓');
    }

    // Check clock skew
    if (now < notBeforeDate) {
      const skew = Math.round((notBeforeDate - now) / 1000);
      addCheck(results, 'critical', 'Clock Skew Detected',
        `Assertion not yet valid (${skew}s in the future)`,
        'Synchronize clocks between IdP and SP using NTP.',
        '❌');
    }

    if (now >= notOnOrAfterDate) {
      addCheck(results, 'critical', 'Assertion Expired',
        'Assertion has expired',
        'Possible clock skew or replay attack attempt.',
        '❌');
    }

    // Check AudienceRestriction
    const audience = conditions.querySelector('AudienceRestriction Audience');
    if (!audience) {
      addCheck(results, 'high', 'No Audience Restriction',
        'Assertion has no audience restriction',
        'Add AudienceRestriction to prevent assertion reuse by other SPs.',
        '❌');
    } else {
      addCheck(results, 'passed', 'Audience Restriction Present',
        'Assertion includes audience restriction',
        null,
        '✓');
    }
  }

  /**
   * Validate Subject Confirmation
   */
  function validateSubjectConfirmation(subjectConfirmation, results) {
    const method = subjectConfirmation.getAttribute('Method');
    
    if (method === 'urn:oasis:names:tc:SAML:2.0:cm:bearer') {
      addCheck(results, 'passed', 'Bearer Confirmation',
        'Using standard bearer confirmation method',
        null,
        '✓');
    }

    const confirmationData = subjectConfirmation.querySelector('SubjectConfirmationData');
    if (confirmationData) {
      const recipient = confirmationData.getAttribute('Recipient');
      const notOnOrAfter = confirmationData.getAttribute('NotOnOrAfter');
      const inResponseTo = confirmationData.getAttribute('InResponseTo');

      if (!recipient) {
        addCheck(results, 'medium', 'Missing Recipient',
          'SubjectConfirmationData has no Recipient',
          'Specify Recipient to validate assertion destination.',
          '⚠️');
      }

      if (!notOnOrAfter) {
        addCheck(results, 'medium', 'No Confirmation Expiration',
          'SubjectConfirmationData has no NotOnOrAfter',
          'Set expiration to limit confirmation validity.',
          '⚠️');
      }

      if (!inResponseTo) {
        addCheck(results, 'low', 'No InResponseTo',
          'SubjectConfirmationData has no InResponseTo',
          'Include InResponseTo to link response to request (prevents replay).',
          'ℹ️');
      } else {
        addCheck(results, 'passed', 'InResponseTo Present',
          'Response linked to original request',
          null,
          '✓');
      }
    }
  }

  /**
   * Add a security check result
   */
  function addCheck(results, severity, title, message, remediation, icon) {
    results.checks.push({
      severity: severity,
      title: title,
      message: message,
      remediation: remediation,
      icon: icon
    });

    if (severity !== 'passed') {
      results.summary[severity]++;
    } else {
      results.summary.passed++;
    }
  }

  /**
   * Calculate overall security score (0-100)
   */
  function calculateSecurityScore(results) {
    const weights = {
      critical: -25,
      high: -15,
      medium: -8,
      low: -3,
      passed: 5
    };

    let score = 50; // Start at 50%

    for (const severity in results.summary) {
      score += results.summary[severity] * weights[severity];
    }

    // Clamp between 0 and 100
    results.securityScore = Math.max(0, Math.min(100, score));
    
    // Add grade
    if (results.securityScore >= 90) {
      results.grade = 'A';
      results.gradeColor = '#4CAF50';
    } else if (results.securityScore >= 75) {
      results.grade = 'B';
      results.gradeColor = '#8BC34A';
    } else if (results.securityScore >= 60) {
      results.grade = 'C';
      results.gradeColor = '#FFC107';
    } else if (results.securityScore >= 40) {
      results.grade = 'D';
      results.gradeColor = '#FF9800';
    } else {
      results.grade = 'F';
      results.gradeColor = '#f44336';
    }
  }

  /**
   * Get friendly algorithm name
   */
  function getAlgorithmName(algorithm) {
    const names = {
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'RSA-SHA256',
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384': 'RSA-SHA384',
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': 'RSA-SHA512',
      'http://www.w3.org/2000/09/xmldsig#rsa-sha1': 'RSA-SHA1 (Weak)',
      'http://www.w3.org/2000/09/xmldsig#dsa-sha1': 'DSA-SHA1 (Weak)'
    };
    return names[algorithm] || algorithm;
  }

  /**
   * Parse SAML XML document
   */
  function parseSAMLDocument(samlString) {
    try {
      const parser = new DOMParser();
      const doc = parser.parseFromString(samlString, 'text/xml');
      
      const parserError = doc.querySelector('parsererror');
      if (parserError) {
        return null;
      }
      
      return doc;
    } catch (error) {
      console.error('Error parsing SAML document:', error);
      return null;
    }
  }

  // Public API
  return {
    validateSecurity
  };
})();
