/**
 * Diagnostic Rules Engine - Detects common SAML errors with explanations
 */

var DiagnosticRules = (function() {
  'use strict';

  /**
   * Run diagnostic rules on a SAML message
   */
  function diagnose(request, comparisonResults, securityResults) {
    const diagnostics = {
      timestamp: new Date().toISOString(),
      issues: [],
      recommendations: []
    };

    if (!request.saml) {
      return diagnostics;
    }

    const samlDoc = parseSAMLDocument(request.saml);
    if (!samlDoc) {
      return diagnostics;
    }

    // Run all diagnostic rules
    checkAudienceMismatch(samlDoc, comparisonResults, diagnostics);
    checkRecipientMismatch(samlDoc, comparisonResults, diagnostics);
    checkDestinationMismatch(samlDoc, comparisonResults, diagnostics);
    checkMissingSignature(samlDoc, diagnostics);
    checkExpiredAssertion(samlDoc, diagnostics);
    checkClockSkew(samlDoc, diagnostics);
    checkMissingInResponseTo(samlDoc, diagnostics);
    checkStatusCode(samlDoc, diagnostics);
    checkNameIDFormat(samlDoc, diagnostics);
    checkMissingAttributes(samlDoc, diagnostics);

    // Add general recommendations
    addGeneralRecommendations(diagnostics, securityResults);

    return diagnostics;
  }

  /**
   * Rule: Check for Audience mismatch
   */
  function checkAudienceMismatch(samlDoc, comparisonResults, diagnostics) {
    if (!comparisonResults || !comparisonResults.applicable) return;

    const audienceError = comparisonResults.comparisons.find(
      c => c.field === 'Audience' && c.severity === 'error'
    );

    if (audienceError) {
      addIssue(diagnostics, {
        id: 'AUDIENCE_MISMATCH',
        severity: 'error',
        title: 'Audience Restriction Mismatch',
        description: 'The audience in the SAML assertion does not match the SP Entity ID.',
        whatIsWrong: `Expected: ${audienceError.expected}\nActual: ${audienceError.actual}`,
        whyItMatters: 'The SP will reject this assertion because it is not the intended recipient. This is a security feature to prevent assertion reuse.',
        howToFix: [
          'Update IdP configuration to send the correct SP Entity ID as the audience',
          'Verify the SP Entity ID configured in the IdP matches the SP metadata',
          'Check for typos or case sensitivity differences'
        ],
        whereToFix: 'IdP Configuration',
        documentationLinks: [
          'SAML 2.0 Core Specification: AudienceRestriction'
        ]
      });
    }
  }

  /**
   * Rule: Check for Recipient mismatch
   */
  function checkRecipientMismatch(samlDoc, comparisonResults, diagnostics) {
    if (!comparisonResults || !comparisonResults.applicable) return;

    const recipientError = comparisonResults.comparisons.find(
      c => c.field === 'Recipient' && c.severity === 'error'
    );

    if (recipientError) {
      addIssue(diagnostics, {
        id: 'RECIPIENT_MISMATCH',
        severity: 'error',
        title: 'Recipient URL Mismatch',
        description: 'The Recipient in SubjectConfirmationData does not match any configured ACS URL.',
        whatIsWrong: `Expected one of: ${recipientError.expected}\nActual: ${recipientError.actual}`,
        whyItMatters: 'The SP will reject the assertion because the recipient URL does not match where the assertion was sent.',
        howToFix: [
          'Update IdP to send assertion to the correct ACS URL',
          'Add the actual recipient URL to SP metadata',
          'Ensure IdP is using the correct ACS URL from SP metadata'
        ],
        whereToFix: 'IdP ACS Configuration',
        relatedFields: ['SubjectConfirmationData/@Recipient', 'AssertionConsumerServiceURL']
      });
    }
  }

  /**
   * Rule: Check for Destination mismatch
   */
  function checkDestinationMismatch(samlDoc, comparisonResults, diagnostics) {
    if (!comparisonResults || !comparisonResults.applicable) return;

    const destinationError = comparisonResults.comparisons.find(
      c => c.field === 'Destination' && c.severity === 'error'
    );

    if (destinationError) {
      addIssue(diagnostics, {
        id: 'DESTINATION_MISMATCH',
        severity: 'error',
        title: 'Destination URL Mismatch',
        description: 'The Destination attribute in the Response does not match the ACS URL.',
        whatIsWrong: `Expected: ${destinationError.expected}\nActual: ${destinationError.actual}`,
        whyItMatters: 'This prevents man-in-the-middle attacks by ensuring the response was intended for this URL.',
        howToFix: [
          'Configure IdP to use the correct ACS URL as the destination',
          'Verify SP ACS URL is correctly registered in IdP',
          'Check for protocol mismatches (http vs https)',
          'Check for trailing slash differences'
        ],
        whereToFix: 'IdP Response Configuration'
      });
    }
  }

  /**
   * Rule: Check for missing signature
   */
  function checkMissingSignature(samlDoc, diagnostics) {
    const response = samlDoc.querySelector('Response');
    const assertion = response ? response.querySelector('Assertion') : samlDoc.querySelector('Assertion');
    
    if (response && assertion) {
      const responseSignature = response.querySelector(':scope > Signature');
      const assertionSignature = assertion.querySelector(':scope > Signature');

      if (!responseSignature && !assertionSignature) {
        addIssue(diagnostics, {
          id: 'MISSING_SIGNATURE',
          severity: 'error',
          title: 'No Signature Found',
          description: 'Neither the Response nor the Assertion is digitally signed.',
          whatIsWrong: 'The SAML message has no digital signature to verify authenticity.',
          whyItMatters: 'Without a signature, the SP cannot verify the message came from the IdP. This is a critical security vulnerability.',
          howToFix: [
            'Enable assertion signing in IdP configuration',
            'OR enable response signing in IdP configuration',
            'Recommended: Sign both for maximum security',
            'Export IdP signing certificate and import to SP'
          ],
          whereToFix: 'IdP Security Settings',
          securityImpact: 'CRITICAL - Messages can be forged'
        });
      }
    }
  }

  /**
   * Rule: Check for expired assertion
   */
  function checkExpiredAssertion(samlDoc, diagnostics) {
    const conditions = samlDoc.querySelector('Conditions');
    if (!conditions) return;

    const notOnOrAfter = conditions.getAttribute('NotOnOrAfter');
    if (!notOnOrAfter) return;

    const now = new Date();
    const expirationDate = new Date(notOnOrAfter);

    if (now >= expirationDate) {
      const secondsExpired = Math.round((now - expirationDate) / 1000);
      
      addIssue(diagnostics, {
        id: 'ASSERTION_EXPIRED',
        severity: 'error',
        title: 'Assertion Has Expired',
        description: `The assertion expired ${secondsExpired} seconds ago.`,
        whatIsWrong: `NotOnOrAfter: ${notOnOrAfter}\nCurrent time: ${now.toISOString()}`,
        whyItMatters: 'Expired assertions should not be accepted to prevent replay attacks.',
        howToFix: [
          'If this is a test/debug scenario, this is expected',
          'For live issues, check clock synchronization between IdP and SP',
          'Ensure IdP and SP are using NTP',
          'Check if assertion validity period is too short',
          'Verify timezone settings are correct'
        ],
        whereToFix: 'Clock Synchronization / IdP Assertion Validity Settings',
        possibleCauses: ['Clock skew', 'Network delay', 'Old captured message', 'Short validity window']
      });
    }
  }

  /**
   * Rule: Check for clock skew
   */
  function checkClockSkew(samlDoc, diagnostics) {
    const conditions = samlDoc.querySelector('Conditions');
    if (!conditions) return;

    const notBefore = conditions.getAttribute('NotBefore');
    if (!notBefore) return;

    const now = new Date();
    const notBeforeDate = new Date(notBefore);

    if (now < notBeforeDate) {
      const skewSeconds = Math.round((notBeforeDate - now) / 1000);
      
      addIssue(diagnostics, {
        id: 'CLOCK_SKEW',
        severity: 'error',
        title: 'Clock Skew Detected',
        description: `Assertion is not yet valid - starts ${skewSeconds} seconds in the future.`,
        whatIsWrong: `NotBefore: ${notBefore}\nCurrent time: ${now.toISOString()}\nDifference: ${skewSeconds} seconds`,
        whyItMatters: 'Clock differences between IdP and SP can cause authentication failures.',
        howToFix: [
          'Synchronize clocks using NTP on both IdP and SP servers',
          'Check timezone configuration on both systems',
          'Configure clock skew tolerance in SP (typically 60-180 seconds)',
          'Verify system time on both servers: `date` (Linux) or `Get-Date` (Windows)'
        ],
        whereToFix: 'System Configuration / SP Clock Skew Settings',
        urgency: 'Immediate action required'
      });
    }
  }

  /**
   * Rule: Check for missing InResponseTo
   */
  function checkMissingInResponseTo(samlDoc, diagnostics) {
    const response = samlDoc.querySelector('Response');
    if (!response) return;

    const inResponseTo = response.getAttribute('InResponseTo');
    const confirmationData = response.querySelector('SubjectConfirmationData');
    const confirmationInResponseTo = confirmationData ? confirmationData.getAttribute('InResponseTo') : null;

    if (!inResponseTo && !confirmationInResponseTo) {
      addIssue(diagnostics, {
        id: 'MISSING_INRESPONSETO',
        severity: 'warning',
        title: 'Missing InResponseTo',
        description: 'The Response has no InResponseTo attribute linking it to the original request.',
        whatIsWrong: 'InResponseTo attribute is missing from both Response and SubjectConfirmationData',
        whyItMatters: 'Without InResponseTo, the SP cannot verify this response is for a specific authentication request. This increases replay attack risk.',
        howToFix: [
          'Enable InResponseTo in IdP response configuration',
          'Ensure SP sends unique ID in AuthnRequest',
          'For IdP-initiated SSO, InResponseTo may not be applicable'
        ],
        whereToFix: 'IdP Response Configuration',
        note: 'Some SPs may allow this for IdP-initiated flows'
      });
    }
  }

  /**
   * Rule: Check status code for failures
   */
  function checkStatusCode(samlDoc, diagnostics) {
    const statusCode = samlDoc.querySelector('Status StatusCode');
    if (!statusCode) return;

    const value = statusCode.getAttribute('Value');
    
    if (value !== 'urn:oasis:names:tc:SAML:2.0:status:Success') {
      const statusMessage = samlDoc.querySelector('StatusMessage');
      const message = statusMessage ? statusMessage.textContent : 'No details provided';

      const errorMap = {
        'urn:oasis:names:tc:SAML:2.0:status:Requester': {
          title: 'Authentication Request Error',
          cause: 'Problem with the authentication request from SP',
          fixes: ['Check AuthnRequest format', 'Verify SP is registered with IdP', 'Check requested attributes']
        },
        'urn:oasis:names:tc:SAML:2.0:status:Responder': {
          title: 'Identity Provider Error',
          cause: 'Problem on the IdP side',
          fixes: ['Check IdP logs', 'Verify user exists in IdP', 'Check IdP configuration']
        },
        'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch': {
          title: 'SAML Version Mismatch',
          cause: 'SP and IdP using incompatible SAML versions',
          fixes: ['Ensure both use SAML 2.0', 'Check protocol version in metadata']
        },
        'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed': {
          title: 'Authentication Failed',
          cause: 'User failed to authenticate at IdP',
          fixes: ['Verify user credentials', 'Check account status', 'Review IdP authentication logs']
        },
        'urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue': {
          title: 'Invalid Attribute',
          cause: 'Problem with attribute name or value',
          fixes: ['Check attribute mapping', 'Verify attribute sources', 'Review IdP attribute release policy']
        },
        'urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy': {
          title: 'Invalid NameID Policy',
          cause: 'Requested NameID format not supported',
          fixes: ['Check NameID format in AuthnRequest', 'Verify IdP supports requested format', 'Use supported format from IdP metadata']
        },
        'urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext': {
          title: 'Authentication Context Not Met',
          cause: 'Requested authentication context not achievable',
          fixes: ['Check RequestedAuthnContext in AuthnRequest', 'Verify IdP supports requested context', 'Use lower authentication assurance level']
        },
        'urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP': {
          title: 'No Available Identity Provider',
          cause: 'No IdP available to authenticate user',
          fixes: ['Check IdP availability', 'Verify routing configuration', 'Check discovery service']
        },
        'urn:oasis:names:tc:SAML:2.0:status:NoPassive': {
          title: 'Passive Authentication Not Possible',
          cause: 'IsPassive=true but user interaction required',
          fixes: ['Remove IsPassive from AuthnRequest', 'Pre-authenticate user', 'Use different authentication flow']
        },
        'urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded': {
          title: 'Proxy Count Exceeded',
          cause: 'Too many proxy hops in authentication chain',
          fixes: ['Reduce proxy chain length', 'Check ProxyCount limit', 'Review federation architecture']
        },
        'urn:oasis:names:tc:SAML:2.0:status:RequestDenied': {
          title: 'Request Denied',
          cause: 'IdP refused to process the request',
          fixes: ['Check IdP access policies', 'Verify SP is authorized', 'Review IdP audit logs']
        },
        'urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported': {
          title: 'Request Not Supported',
          cause: 'IdP does not support this request type',
          fixes: ['Check requested features', 'Verify IdP capabilities', 'Use supported protocol features']
        },
        'urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding': {
          title: 'Unsupported Binding',
          cause: 'Requested binding not supported by IdP',
          fixes: ['Use supported binding from IdP metadata', 'Check ProtocolBinding attribute', 'Verify IdP binding configuration']
        }
      };

      const errorInfo = errorMap[value] || {
        title: 'Authentication Failed',
        cause: 'Unknown error occurred',
        fixes: ['Check IdP logs', 'Review error message']
      };

      addIssue(diagnostics, {
        id: 'STATUS_CODE_FAILURE',
        severity: 'error',
        title: errorInfo.title,
        description: `SAML Status: ${value}`,
        whatIsWrong: `Status Code: ${value}\nMessage: ${message}\nCause: ${errorInfo.cause}`,
        whyItMatters: 'The authentication request failed and user cannot sign in.',
        howToFix: errorInfo.fixes,
        whereToFix: 'IdP Configuration / User Account',
        statusMessage: message
      });
    }
  }

  /**
   * Rule: Check NameID format
   */
  function checkNameIDFormat(samlDoc, diagnostics) {
    const nameID = samlDoc.querySelector('NameID');
    if (!nameID) return;

    const format = nameID.getAttribute('Format');
    if (!format) {
      addIssue(diagnostics, {
        id: 'MISSING_NAMEID_FORMAT',
        severity: 'warning',
        title: 'NameID Format Not Specified',
        description: 'The NameID element has no Format attribute.',
        whatIsWrong: 'Format attribute missing from NameID',
        whyItMatters: 'Without explicit format, SP may misinterpret the NameID value.',
        howToFix: [
          'Configure IdP to specify NameID format',
          'Common formats: emailAddress, persistent, transient, unspecified',
          'Match format to SP requirements'
        ],
        whereToFix: 'IdP NameID Configuration'
      });
    }
  }

  /**
   * Rule: Check for missing attributes
   */
  function checkMissingAttributes(samlDoc, diagnostics) {
    const attributeStatement = samlDoc.querySelector('AttributeStatement');
    
    if (!attributeStatement) {
      addIssue(diagnostics, {
        id: 'NO_ATTRIBUTES',
        severity: 'warning',
        title: 'No Attributes in Assertion',
        description: 'The assertion contains no AttributeStatement.',
        whatIsWrong: 'AttributeStatement element is missing',
        whyItMatters: 'The SP may need user attributes for authorization or personalization.',
        howToFix: [
          'Configure IdP to release attributes to this SP',
          'Check attribute release policy',
          'Verify user has values for requested attributes',
          'Review SP attribute requirements'
        ],
        whereToFix: 'IdP Attribute Release Configuration',
        note: 'Some SPs only need authentication without attributes'
      });
    }
  }

  /**
   * Add general recommendations
   */
  function addGeneralRecommendations(diagnostics, securityResults) {
    if (securityResults && securityResults.securityScore < 70) {
      diagnostics.recommendations.push({
        category: 'Security',
        priority: 'high',
        recommendation: 'Improve security posture',
        details: 'Your SAML implementation has security weaknesses. Review the security validation results and address critical issues.'
      });
    }

    // Always include best practices
    diagnostics.recommendations.push({
      category: 'Best Practices',
      priority: 'medium',
      recommendation: 'Regular security audits',
      details: 'Periodically review SAML configuration, rotate certificates, and update to latest security standards.'
    });

    diagnostics.recommendations.push({
      category: 'Monitoring',
      priority: 'low',
      recommendation: 'Enable detailed logging',
      details: 'Configure detailed SAML logging on both SP and IdP for troubleshooting and security monitoring.'
    });
  }

  /**
   * Add an issue to diagnostics
   */
  function addIssue(diagnostics, issue) {
    diagnostics.issues.push(issue);
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
    diagnose
  };
})();
