/**
 * Onboarding Checklist - Generates readiness assessment for SAML applications
 */

var OnboardingChecklist = (function() {
  'use strict';

  /**
   * Generate onboarding checklist for an application
   */
  async function generateChecklist(request, metadata) {
    const checklist = {
      timestamp: new Date().toISOString(),
      application: metadata ? metadata.entityId : 'Unknown',
      items: [],
      summary: {
        total: 0,
        completed: 0,
        blocked: 0,
        warnings: 0
      },
      readinessScore: 0,
      status: 'not-ready'
    };

    if (!request.saml) {
      return checklist;
    }

    const samlDoc = parseSAMLDocument(request.saml);
    if (!samlDoc) {
      return checklist;
    }

    // Check metadata configuration
    await checkMetadataConfiguration(checklist, metadata);

    // Check SAML message structure
    checkSAMLStructure(checklist, samlDoc);

    // Check authentication flow
    checkAuthenticationFlow(checklist, samlDoc, request);

    // Check attribute configuration
    checkAttributeConfiguration(checklist, samlDoc, metadata);

    // Check security configuration
    checkSecurityConfiguration(checklist, samlDoc, metadata);

    // Check certificate configuration
    checkCertificateConfiguration(checklist, samlDoc, metadata);

    // Calculate readiness score
    calculateReadinessScore(checklist);

    return checklist;
  }

  /**
   * Check metadata configuration
   */
  async function checkMetadataConfiguration(checklist, metadata) {
    if (!metadata) {
      addChecklistItem(checklist, {
        category: 'Configuration',
        item: 'Metadata uploaded',
        status: 'blocked',
        message: 'No metadata configured',
        action: 'Upload SP or IdP metadata to enable validation',
        priority: 'critical',
        blocker: true
      });
      return;
    }

    addChecklistItem(checklist, {
      category: 'Configuration',
      item: 'Metadata uploaded',
      status: 'completed',
      message: `${metadata.type} metadata configured`,
      priority: 'critical'
    });

    // Check entity ID
    if (metadata.entityId) {
      addChecklistItem(checklist, {
        category: 'Configuration',
        item: 'Entity ID configured',
        status: 'completed',
        message: metadata.entityId,
        priority: 'critical'
      });
    } else {
      addChecklistItem(checklist, {
        category: 'Configuration',
        item: 'Entity ID configured',
        status: 'blocked',
        message: 'Entity ID missing from metadata',
        action: 'Configure Entity ID in metadata',
        priority: 'critical',
        blocker: true
      });
    }

    // Check ACS URLs for SP
    if (metadata.type === 'SP' && metadata.sp) {
      if (metadata.sp.assertionConsumerServices.length > 0) {
        addChecklistItem(checklist, {
          category: 'Configuration',
          item: 'ACS URL configured',
          status: 'completed',
          message: `${metadata.sp.assertionConsumerServices.length} ACS URL(s) configured`,
          details: metadata.sp.assertionConsumerServices.map(acs => acs.location),
          priority: 'critical'
        });
      } else {
        addChecklistItem(checklist, {
          category: 'Configuration',
          item: 'ACS URL configured',
          status: 'blocked',
          message: 'No ACS URLs found in metadata',
          action: 'Add Assertion Consumer Service URLs to SP metadata',
          priority: 'critical',
          blocker: true
        });
      }

      // Check logout URLs
      if (metadata.sp.singleLogoutServices.length > 0) {
        addChecklistItem(checklist, {
          category: 'Configuration',
          item: 'Logout URL configured',
          status: 'completed',
          message: `${metadata.sp.singleLogoutServices.length} logout URL(s) configured`,
          priority: 'medium'
        });
      } else {
        addChecklistItem(checklist, {
          category: 'Configuration',
          item: 'Logout URL configured',
          status: 'warning',
          message: 'No logout URLs configured',
          action: 'Add Single Logout Service URLs for proper logout support',
          priority: 'medium'
        });
      }

      // Check NameID formats
      if (metadata.sp.nameIdFormats.length > 0) {
        addChecklistItem(checklist, {
          category: 'Configuration',
          item: 'NameID format specified',
          status: 'completed',
          message: `${metadata.sp.nameIdFormats.length} format(s) configured`,
          details: metadata.sp.nameIdFormats,
          priority: 'high'
        });
      } else {
        addChecklistItem(checklist, {
          category: 'Configuration',
          item: 'NameID format specified',
          status: 'warning',
          message: 'No NameID formats specified',
          action: 'Specify acceptable NameID formats in metadata',
          priority: 'medium'
        });
      }
    }
  }

  /**
   * Check SAML message structure
   */
  function checkSAMLStructure(checklist, samlDoc) {
    const response = samlDoc.querySelector('Response');
    const assertion = samlDoc.querySelector('Assertion');
    const authnRequest = samlDoc.querySelector('AuthnRequest');

    if (response || assertion) {
      addChecklistItem(checklist, {
        category: 'Communication',
        item: 'SAML Response received',
        status: 'completed',
        message: 'Valid SAML Response detected',
        priority: 'critical'
      });

      // Check Issuer
      const issuer = samlDoc.querySelector('Issuer');
      if (issuer) {
        addChecklistItem(checklist, {
          category: 'Communication',
          item: 'Issuer present',
          status: 'completed',
          message: issuer.textContent.trim(),
          priority: 'high'
        });
      } else {
        addChecklistItem(checklist, {
          category: 'Communication',
          item: 'Issuer present',
          status: 'warning',
          message: 'No Issuer element found',
          action: 'Configure IdP to include Issuer',
          priority: 'high'
        });
      }

      // Check Status
      const statusCode = samlDoc.querySelector('StatusCode');
      if (statusCode) {
        const value = statusCode.getAttribute('Value');
        if (value === 'urn:oasis:names:tc:SAML:2.0:status:Success') {
          addChecklistItem(checklist, {
            category: 'Communication',
            item: 'Authentication successful',
            status: 'completed',
            message: 'Status: Success',
            priority: 'critical'
          });
        } else {
          addChecklistItem(checklist, {
            category: 'Communication',
            item: 'Authentication successful',
            status: 'blocked',
            message: `Status: ${value}`,
            action: 'Resolve authentication failure',
            priority: 'critical',
            blocker: true
          });
        }
      }
    } else if (authnRequest) {
      addChecklistItem(checklist, {
        category: 'Communication',
        item: 'AuthnRequest sent',
        status: 'completed',
        message: 'SP initiated authentication',
        priority: 'high'
      });
    }
  }

  /**
   * Check authentication flow
   */
  function checkAuthenticationFlow(checklist, samlDoc, request) {
    const response = samlDoc.querySelector('Response');
    
    if (response) {
      // Check Destination
      const destination = response.getAttribute('Destination');
      if (destination) {
        addChecklistItem(checklist, {
          category: 'Authentication Flow',
          item: 'Destination specified',
          status: 'completed',
          message: destination,
          priority: 'high'
        });
      }

      // Check InResponseTo
      const inResponseTo = response.getAttribute('InResponseTo');
      const confirmationData = samlDoc.querySelector('SubjectConfirmationData');
      const confirmationInResponseTo = confirmationData ? confirmationData.getAttribute('InResponseTo') : null;
      
      if (inResponseTo || confirmationInResponseTo) {
        addChecklistItem(checklist, {
          category: 'Authentication Flow',
          item: 'Request/Response linked',
          status: 'completed',
          message: 'InResponseTo present',
          priority: 'medium'
        });
      } else {
        addChecklistItem(checklist, {
          category: 'Authentication Flow',
          item: 'Request/Response linked',
          status: 'warning',
          message: 'No InResponseTo attribute (may be IdP-initiated)',
          action: 'For SP-initiated flow, configure InResponseTo',
          priority: 'low'
        });
      }

      // Check Subject
      const subject = samlDoc.querySelector('Subject NameID');
      if (subject) {
        addChecklistItem(checklist, {
          category: 'Authentication Flow',
          item: 'User identified',
          status: 'completed',
          message: `NameID: ${subject.textContent.trim()}`,
          priority: 'critical'
        });
      } else {
        addChecklistItem(checklist, {
          category: 'Authentication Flow',
          item: 'User identified',
          status: 'blocked',
          message: 'No Subject/NameID found',
          action: 'Configure IdP to include NameID in assertion',
          priority: 'critical',
          blocker: true
        });
      }
    }
  }

  /**
   * Check attribute configuration
   */
  function checkAttributeConfiguration(checklist, samlDoc, metadata) {
    const attributeStatement = samlDoc.querySelector('AttributeStatement');
    const attributes = samlDoc.querySelectorAll('AttributeStatement Attribute');

    if (attributeStatement && attributes.length > 0) {
      addChecklistItem(checklist, {
        category: 'Attributes',
        item: 'Attributes present',
        status: 'completed',
        message: `${attributes.length} attribute(s) received`,
        priority: 'high'
      });

      // Analyze attributes
      const attrAnalysis = AttributeMapper.analyzeAttributes({ saml: new XMLSerializer().serializeToString(samlDoc) });
      
      if (attrAnalysis) {
        // Check for essential attributes
        const essentialAttributes = ['email', 'username'];
        essentialAttributes.forEach(essential => {
          if (attrAnalysis.identityAttributes[essential] && attrAnalysis.identityAttributes[essential].length > 0) {
            addChecklistItem(checklist, {
              category: 'Attributes',
              item: `${essential} attribute present`,
              status: 'completed',
              message: `Mapped from: ${attrAnalysis.identityAttributes[essential][0].name}`,
              priority: 'critical'
            });
          } else {
            addChecklistItem(checklist, {
              category: 'Attributes',
              item: `${essential} attribute present`,
              status: 'blocked',
              message: `Required ${essential} attribute missing`,
              action: `Configure IdP to release ${essential} attribute`,
              priority: 'critical',
              blocker: true
            });
          }
        });

        // Check for duplicate attributes
        if (attrAnalysis.summary.duplicates > 0) {
          addChecklistItem(checklist, {
            category: 'Attributes',
            item: 'No duplicate attributes',
            status: 'warning',
            message: `${attrAnalysis.summary.duplicates} duplicate(s) found`,
            action: 'Remove duplicate attribute mappings from IdP',
            priority: 'low'
          });
        }
      }
    } else {
      addChecklistItem(checklist, {
        category: 'Attributes',
        item: 'Attributes configured',
        status: 'warning',
        message: 'No attributes in assertion',
        action: 'Configure IdP to release user attributes',
        priority: 'medium'
      });
    }

    // Check against requested attributes in metadata
    if (metadata && metadata.type === 'SP' && metadata.sp && metadata.sp.requestedAttributes.length > 0) {
      const requestedCount = metadata.sp.requestedAttributes.length;
      const receivedCount = attributes.length;
      
      if (receivedCount >= requestedCount) {
        addChecklistItem(checklist, {
          category: 'Attributes',
          item: 'Required attributes received',
          status: 'completed',
          message: `${receivedCount}/${requestedCount} attributes received`,
          priority: 'high'
        });
      } else {
        addChecklistItem(checklist, {
          category: 'Attributes',
          item: 'Required attributes received',
          status: 'warning',
          message: `Only ${receivedCount}/${requestedCount} attributes received`,
          action: 'Configure IdP to release all requested attributes',
          priority: 'high'
        });
      }
    }
  }

  /**
   * Check security configuration
   */
  function checkSecurityConfiguration(checklist, samlDoc, metadata) {
    const response = samlDoc.querySelector('Response');
    const assertion = samlDoc.querySelector('Assertion');

    if (!response && !assertion) {
      return;
    }

    // Check signatures
    const responseSignature = response ? response.querySelector(':scope > Signature') : null;
    const assertionSignature = assertion ? assertion.querySelector(':scope > Signature') : null;

    if (responseSignature || assertionSignature) {
      addChecklistItem(checklist, {
        category: 'Security',
        item: 'Message signed',
        status: 'completed',
        message: responseSignature ? 'Response signed' : 'Assertion signed',
        priority: 'critical'
      });

      // Check signature algorithm
      const signature = responseSignature || assertionSignature;
      const signatureMethod = signature.querySelector('SignatureMethod');
      if (signatureMethod) {
        const algorithm = signatureMethod.getAttribute('Algorithm');
        if (algorithm.includes('sha1')) {
          addChecklistItem(checklist, {
            category: 'Security',
            item: 'Strong signature algorithm',
            status: 'blocked',
            message: 'Using weak SHA-1 algorithm',
            action: 'Upgrade to SHA-256 or stronger',
            priority: 'critical',
            blocker: true
          });
        } else {
          addChecklistItem(checklist, {
            category: 'Security',
            item: 'Strong signature algorithm',
            status: 'completed',
            message: 'Using SHA-256 or stronger',
            priority: 'high'
          });
        }
      }
    } else {
      addChecklistItem(checklist, {
        category: 'Security',
        item: 'Message signed',
        status: 'blocked',
        message: 'Neither Response nor Assertion is signed',
        action: 'Configure IdP to sign Response or Assertion',
        priority: 'critical',
        blocker: true
      });
    }

    // Check encryption
    const encryptedAssertion = samlDoc.querySelector('EncryptedAssertion');
    if (encryptedAssertion) {
      addChecklistItem(checklist, {
        category: 'Security',
        item: 'Assertion encrypted',
        status: 'completed',
        message: 'Assertion is encrypted',
        priority: 'medium'
      });
    } else {
      addChecklistItem(checklist, {
        category: 'Security',
        item: 'Assertion encrypted',
        status: 'warning',
        message: 'Assertion not encrypted',
        action: 'Consider enabling assertion encryption for sensitive data',
        priority: 'low'
      });
    }

    // Check Conditions
    const conditions = assertion ? assertion.querySelector('Conditions') : null;
    if (conditions) {
      const notBefore = conditions.getAttribute('NotBefore');
      const notOnOrAfter = conditions.getAttribute('NotOnOrAfter');
      
      if (notBefore && notOnOrAfter) {
        addChecklistItem(checklist, {
          category: 'Security',
          item: 'Assertion validity configured',
          status: 'completed',
          message: 'NotBefore and NotOnOrAfter present',
          priority: 'high'
        });
      } else {
        addChecklistItem(checklist, {
          category: 'Security',
          item: 'Assertion validity configured',
          status: 'warning',
          message: 'Missing validity timestamps',
          action: 'Configure assertion validity period',
          priority: 'high'
        });
      }

      // Check AudienceRestriction
      const audience = conditions.querySelector('AudienceRestriction');
      if (audience) {
        addChecklistItem(checklist, {
          category: 'Security',
          item: 'Audience restriction',
          status: 'completed',
          message: 'Audience restriction present',
          priority: 'high'
        });
      } else {
        addChecklistItem(checklist, {
          category: 'Security',
          item: 'Audience restriction',
          status: 'blocked',
          message: 'No audience restriction',
          action: 'Configure AudienceRestriction to prevent assertion reuse',
          priority: 'critical',
          blocker: true
        });
      }
    }
  }

  /**
   * Check certificate configuration
   */
  function checkCertificateConfiguration(checklist, samlDoc, metadata) {
    const certificates = samlDoc.querySelectorAll('X509Certificate');

    if (certificates.length > 0) {
      addChecklistItem(checklist, {
        category: 'Certificates',
        item: 'Certificate present in message',
        status: 'completed',
        message: `${certificates.length} certificate(s) found`,
        priority: 'high'
      });
    }

    if (metadata && metadata.type === 'SP' && metadata.sp) {
      if (metadata.sp.signingCertificates.length > 0) {
        addChecklistItem(checklist, {
          category: 'Certificates',
          item: 'Signing certificate in metadata',
          status: 'completed',
          message: `${metadata.sp.signingCertificates.length} signing certificate(s)`,
          priority: 'high'
        });
      }

      if (metadata.sp.encryptionCertificates.length > 0) {
        addChecklistItem(checklist, {
          category: 'Certificates',
          item: 'Encryption certificate in metadata',
          status: 'completed',
          message: `${metadata.sp.encryptionCertificates.length} encryption certificate(s)`,
          priority: 'medium'
        });
      } else {
        addChecklistItem(checklist, {
          category: 'Certificates',
          item: 'Encryption certificate in metadata',
          status: 'warning',
          message: 'No encryption certificates',
          action: 'Add encryption certificate to enable assertion encryption',
          priority: 'low'
        });
      }
    }
  }

  /**
   * Add item to checklist
   */
  function addChecklistItem(checklist, item) {
    checklist.items.push(item);
    checklist.summary.total++;

    if (item.status === 'completed') {
      checklist.summary.completed++;
    } else if (item.status === 'blocked') {
      checklist.summary.blocked++;
    } else if (item.status === 'warning') {
      checklist.summary.warnings++;
    }
  }

  /**
   * Calculate readiness score
   */
  function calculateReadinessScore(checklist) {
    if (checklist.summary.total === 0) {
      checklist.readinessScore = 0;
      checklist.status = 'not-ready';
      return;
    }

    // Critical blockers reduce score significantly
    const blockers = checklist.summary.blocked;
    const warnings = checklist.summary.warnings;
    const completed = checklist.summary.completed;
    const total = checklist.summary.total;

    // Calculate base score
    let score = (completed / total) * 100;

    // Penalize blockers heavily
    score -= (blockers * 15);

    // Penalize warnings moderately
    score -= (warnings * 5);

    // Clamp between 0 and 100
    checklist.readinessScore = Math.max(0, Math.min(100, Math.round(score)));

    // Determine status
    if (blockers > 0) {
      checklist.status = 'blocked';
    } else if (checklist.readinessScore >= 90) {
      checklist.status = 'ready';
    } else if (checklist.readinessScore >= 70) {
      checklist.status = 'almost-ready';
    } else {
      checklist.status = 'not-ready';
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

  // Public API
  return {
    generateChecklist
  };
})();
