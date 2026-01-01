/**
 * Comparison Engine - Compares live SAML messages against stored metadata
 */

var ComparisonEngine = (function() {
  'use strict';

  /**
   * Compare a SAML AuthnRequest against SP metadata
   */
  function compareAuthnRequest(request, metadata) {
    if (!metadata || metadata.type !== 'SP') {
      return {
        applicable: false,
        message: 'No SP metadata available for comparison'
      };
    }

    const results = {
      applicable: true,
      timestamp: new Date().toISOString(),
      comparisons: [],
      summary: {
        errors: 0,
        warnings: 0,
        info: 0
      }
    };

    // Parse the SAML request
    const samlDoc = parseSAMLDocument(request.saml);
    if (!samlDoc) {
      results.comparisons.push({
        field: 'document',
        severity: 'error',
        message: 'Failed to parse SAML document',
        expected: 'Valid SAML XML',
        actual: 'Parse error'
      });
      results.summary.errors++;
      return results;
    }

    const authnRequest = samlDoc.querySelector('AuthnRequest');
    if (!authnRequest) {
      results.comparisons.push({
        field: 'AuthnRequest',
        severity: 'error',
        message: 'No AuthnRequest element found',
        expected: 'AuthnRequest',
        actual: 'Not found'
      });
      results.summary.errors++;
      return results;
    }

    // Compare Issuer
    const issuer = authnRequest.querySelector('Issuer');
    if (issuer) {
      compareField(
        results,
        'Issuer',
        metadata.entityId,
        issuer.textContent.trim(),
        'Entity ID from metadata',
        'Issuer mismatch - request may be rejected by IdP'
      );
    } else {
      results.comparisons.push({
        field: 'Issuer',
        severity: 'warning',
        message: 'No Issuer element found in AuthnRequest',
        expected: metadata.entityId,
        actual: 'Missing'
      });
      results.summary.warnings++;
    }

    // Compare AssertionConsumerServiceURL
    const acsUrl = authnRequest.getAttribute('AssertionConsumerServiceURL');
    if (acsUrl) {
      const validAcsUrls = metadata.sp.assertionConsumerServices.map(acs => acs.location);
      if (!validAcsUrls.includes(acsUrl)) {
        results.comparisons.push({
          field: 'AssertionConsumerServiceURL',
          severity: 'error',
          message: 'ACS URL not found in SP metadata',
          expected: validAcsUrls.join(', '),
          actual: acsUrl,
          remediation: 'Add this ACS URL to SP metadata or use one of the configured URLs'
        });
        results.summary.errors++;
      } else {
        results.comparisons.push({
          field: 'AssertionConsumerServiceURL',
          severity: 'success',
          message: 'ACS URL matches metadata',
          expected: acsUrl,
          actual: acsUrl
        });
      }
    }

    // Compare ProtocolBinding
    const protocolBinding = authnRequest.getAttribute('ProtocolBinding');
    if (protocolBinding) {
      const supportedBindings = metadata.sp.assertionConsumerServices.map(acs => acs.binding);
      if (!supportedBindings.includes(protocolBinding)) {
        results.comparisons.push({
          field: 'ProtocolBinding',
          severity: 'warning',
          message: 'Protocol binding not found in SP metadata',
          expected: supportedBindings.join(', '),
          actual: protocolBinding
        });
        results.summary.warnings++;
      }
    }

    // Check Destination
    const destination = authnRequest.getAttribute('Destination');
    if (destination) {
      results.comparisons.push({
        field: 'Destination',
        severity: 'info',
        message: 'Destination endpoint specified',
        actual: destination,
        note: 'Should match IdP SSO endpoint'
      });
      results.summary.info++;
    }

    // Check NameIDPolicy
    const nameIDPolicy = authnRequest.querySelector('NameIDPolicy');
    if (nameIDPolicy && metadata.sp.nameIdFormats.length > 0) {
      const requestedFormat = nameIDPolicy.getAttribute('Format');
      if (requestedFormat && !metadata.sp.nameIdFormats.includes(requestedFormat)) {
        results.comparisons.push({
          field: 'NameIDPolicy/Format',
          severity: 'warning',
          message: 'Requested NameID format not in SP metadata',
          expected: metadata.sp.nameIdFormats.join(', '),
          actual: requestedFormat
        });
        results.summary.warnings++;
      }
    }

    return results;
  }

  /**
   * Compare a SAML Response against SP metadata
   */
  function compareSAMLResponse(request, metadata) {
    if (!metadata || metadata.type !== 'SP') {
      return {
        applicable: false,
        message: 'No SP metadata available for comparison'
      };
    }

    const results = {
      applicable: true,
      timestamp: new Date().toISOString(),
      comparisons: [],
      summary: {
        errors: 0,
        warnings: 0,
        info: 0
      }
    };

    // Parse the SAML response
    const samlDoc = parseSAMLDocument(request.saml);
    if (!samlDoc) {
      results.comparisons.push({
        field: 'document',
        severity: 'error',
        message: 'Failed to parse SAML document',
        expected: 'Valid SAML XML',
        actual: 'Parse error'
      });
      results.summary.errors++;
      return results;
    }

    const response = samlDoc.querySelector('Response');
    if (!response) {
      results.comparisons.push({
        field: 'Response',
        severity: 'error',
        message: 'No Response element found',
        expected: 'Response',
        actual: 'Not found'
      });
      results.summary.errors++;
      return results;
    }

    // Compare Destination
    const destination = response.getAttribute('Destination');
    if (destination) {
      const validAcsUrls = metadata.sp.assertionConsumerServices.map(acs => acs.location);
      if (!validAcsUrls.includes(destination)) {
        results.comparisons.push({
          field: 'Destination',
          severity: 'error',
          message: 'Destination does not match any ACS URL in metadata',
          expected: validAcsUrls.join(', '),
          actual: destination,
          remediation: 'IdP must send response to a valid ACS URL from SP metadata'
        });
        results.summary.errors++;
      } else {
        results.comparisons.push({
          field: 'Destination',
          severity: 'success',
          message: 'Destination matches ACS URL in metadata',
          expected: destination,
          actual: destination
        });
      }
    }

    // Check Assertion
    const assertion = response.querySelector('Assertion');
    if (assertion) {
      // Compare Audience
      const audience = assertion.querySelector('AudienceRestriction Audience');
      if (audience) {
        compareField(
          results,
          'Audience',
          metadata.entityId,
          audience.textContent.trim(),
          'Entity ID from metadata',
          'Audience mismatch - response may be rejected'
        );
      } else {
        results.comparisons.push({
          field: 'Audience',
          severity: 'warning',
          message: 'No Audience element found in assertion',
          expected: metadata.entityId,
          actual: 'Missing'
        });
        results.summary.warnings++;
      }

      // Compare Recipient
      const subjectConfirmationData = assertion.querySelector('SubjectConfirmationData');
      if (subjectConfirmationData) {
        const recipient = subjectConfirmationData.getAttribute('Recipient');
        if (recipient) {
          const validAcsUrls = metadata.sp.assertionConsumerServices.map(acs => acs.location);
          if (!validAcsUrls.includes(recipient)) {
            results.comparisons.push({
              field: 'Recipient',
              severity: 'error',
              message: 'Recipient does not match any ACS URL in metadata',
              expected: validAcsUrls.join(', '),
              actual: recipient,
              remediation: 'IdP must set Recipient to a valid ACS URL from SP metadata'
            });
            results.summary.errors++;
          } else {
            results.comparisons.push({
              field: 'Recipient',
              severity: 'success',
              message: 'Recipient matches ACS URL in metadata',
              expected: recipient,
              actual: recipient
            });
          }
        }
      }

      // Check NameID format
      const nameID = assertion.querySelector('Subject NameID');
      if (nameID && metadata.sp.nameIdFormats.length > 0) {
        const format = nameID.getAttribute('Format');
        if (format && !metadata.sp.nameIdFormats.includes(format)) {
          results.comparisons.push({
            field: 'NameID Format',
            severity: 'warning',
            message: 'NameID format not in SP metadata',
            expected: metadata.sp.nameIdFormats.join(', '),
            actual: format
          });
          results.summary.warnings++;
        } else if (format) {
          results.comparisons.push({
            field: 'NameID Format',
            severity: 'success',
            message: 'NameID format matches metadata',
            expected: format,
            actual: format
          });
        }
      }

      // Check Conditions timestamps
      const conditions = assertion.querySelector('Conditions');
      if (conditions) {
        const notBefore = conditions.getAttribute('NotBefore');
        const notOnOrAfter = conditions.getAttribute('NotOnOrAfter');
        const now = new Date();

        if (notBefore) {
          const notBeforeDate = new Date(notBefore);
          if (now < notBeforeDate) {
            const skew = Math.round((notBeforeDate - now) / 1000);
            results.comparisons.push({
              field: 'Conditions/NotBefore',
              severity: 'error',
              message: `Assertion not yet valid (clock skew: ${skew}s)`,
              expected: 'Current time after NotBefore',
              actual: notBefore,
              remediation: 'Check clock synchronization between IdP and SP'
            });
            results.summary.errors++;
          }
        }

        if (notOnOrAfter) {
          const notOnOrAfterDate = new Date(notOnOrAfter);
          if (now >= notOnOrAfterDate) {
            results.comparisons.push({
              field: 'Conditions/NotOnOrAfter',
              severity: 'error',
              message: 'Assertion has expired',
              expected: 'Current time before NotOnOrAfter',
              actual: notOnOrAfter,
              remediation: 'Assertion expired - may indicate clock skew or replay attack'
            });
            results.summary.errors++;
          }
        }
      }

      // Check signature presence
      const responseSignature = response.querySelector('Signature');
      const assertionSignature = assertion.querySelector('Signature');
      
      if (metadata.sp.wantAssertionsSigned) {
        if (!responseSignature && !assertionSignature) {
          results.comparisons.push({
            field: 'Signature',
            severity: 'error',
            message: 'No signature found but SP requires signed assertions',
            expected: 'Signed response or assertion',
            actual: 'No signature',
            remediation: 'Configure IdP to sign responses or assertions'
          });
          results.summary.errors++;
        } else {
          results.comparisons.push({
            field: 'Signature',
            severity: 'success',
            message: 'Signature present as required',
            actual: responseSignature ? 'Response signed' : 'Assertion signed'
          });
        }
      } else if (!responseSignature && !assertionSignature) {
        results.comparisons.push({
          field: 'Signature',
          severity: 'warning',
          message: 'No signature found - security risk',
          expected: 'Signed response or assertion',
          actual: 'No signature',
          remediation: 'Consider requiring signed assertions for better security'
        });
        results.summary.warnings++;
      }
    } else {
      results.comparisons.push({
        field: 'Assertion',
        severity: 'error',
        message: 'No Assertion found in Response',
        expected: 'Assertion element',
        actual: 'Missing'
      });
      results.summary.errors++;
    }

    return results;
  }

  /**
   * Helper function to compare fields
   */
  function compareField(results, field, expected, actual, context, errorMessage) {
    if (expected !== actual) {
      results.comparisons.push({
        field: field,
        severity: 'error',
        message: errorMessage || `${field} mismatch`,
        expected: expected,
        actual: actual,
        context: context
      });
      results.summary.errors++;
    } else {
      results.comparisons.push({
        field: field,
        severity: 'success',
        message: `${field} matches metadata`,
        expected: expected,
        actual: actual
      });
    }
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

  /**
   * Auto-detect appropriate metadata for a SAML message
   */
  async function findMatchingMetadata(request) {
    try {
      const allMetadata = await StorageManager.getAllMetadata();
      
      // Try to extract entity ID or domain from the SAML message
      const samlDoc = parseSAMLDocument(request.saml);
      if (!samlDoc) {
        return null;
      }

      // Look for Issuer in the SAML message
      const issuer = samlDoc.querySelector('Issuer');
      if (issuer) {
        const issuerValue = issuer.textContent.trim();
        
        // Try exact match on entity ID
        if (allMetadata[issuerValue]) {
          return allMetadata[issuerValue];
        }
      }

      // Try to match by domain
      const domain = MetadataManager.extractDomain(request.url);
      if (allMetadata[domain]) {
        return allMetadata[domain];
      }

      // Check all metadata for partial matches
      for (const key in allMetadata) {
        const metadata = allMetadata[key];
        if (metadata.entityId && issuer && metadata.entityId === issuer.textContent.trim()) {
          return metadata;
        }
      }

      return null;
    } catch (error) {
      console.error('Error finding matching metadata:', error);
      return null;
    }
  }

  /**
   * Main comparison function - automatically selects appropriate comparison
   */
  async function compareRequest(request) {
    // Find matching metadata
    const metadata = await findMatchingMetadata(request);
    
    if (!metadata) {
      return {
        applicable: false,
        message: 'No matching metadata found for this request',
        suggestion: 'Upload SP or IdP metadata to enable intelligent analysis'
      };
    }

    // Determine type of SAML message
    if (request.saml) {
      const samlDoc = parseSAMLDocument(request.saml);
      if (!samlDoc) {
        return {
          applicable: false,
          message: 'Failed to parse SAML document'
        };
      }

      if (samlDoc.querySelector('AuthnRequest')) {
        return compareAuthnRequest(request, metadata);
      } else if (samlDoc.querySelector('Response')) {
        return compareSAMLResponse(request, metadata);
      } else if (samlDoc.querySelector('LogoutRequest')) {
        return {
          applicable: true,
          message: 'LogoutRequest detected - comparison not yet implemented',
          metadata: metadata.entityId
        };
      }
    }

    return {
      applicable: false,
      message: 'Unable to determine SAML message type'
    };
  }

  // Public API
  return {
    compareRequest,
    compareAuthnRequest,
    compareSAMLResponse,
    findMatchingMetadata
  };
})();
