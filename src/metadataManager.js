/**
 * Metadata Manager - Parses and manages SAML metadata (SP and IdP)
 */

var MetadataManager = (function() {
  'use strict';

  /**
   * Parse SAML metadata XML
   */
  function parseMetadata(xmlString) {
    try {
      const parser = new DOMParser();
      const doc = parser.parseFromString(xmlString, 'text/xml');
      
      // Check for parsing errors
      const parserError = doc.querySelector('parsererror');
      if (parserError) {
        throw new Error('XML parsing error: ' + parserError.textContent);
      }

      // Determine if this is SP or IdP metadata
      const descriptor = doc.querySelector('SPSSODescriptor') || doc.querySelector('IDPSSODescriptor');
      if (!descriptor) {
        throw new Error('No valid SAML descriptor found (SPSSODescriptor or IDPSSODescriptor)');
      }

      const isSP = descriptor.tagName === 'SPSSODescriptor';
      const entityDescriptor = doc.querySelector('EntityDescriptor');
      
      if (!entityDescriptor) {
        throw new Error('No EntityDescriptor found');
      }

      const metadata = {
        type: isSP ? 'SP' : 'IdP',
        entityId: entityDescriptor.getAttribute('entityID'),
        rawXml: xmlString,
        parsedAt: new Date().toISOString()
      };

      if (isSP) {
        metadata.sp = parseSPMetadata(descriptor, doc);
      } else {
        metadata.idp = parseIdPMetadata(descriptor, doc);
      }

      // Validate completeness
      metadata.validation = validateMetadata(metadata);

      return metadata;
    } catch (error) {
      console.error('Error parsing metadata:', error);
      throw error;
    }
  }

  /**
   * Parse SP metadata
   */
  function parseSPMetadata(descriptor, doc) {
    const sp = {
      assertionConsumerServices: [],
      singleLogoutServices: [],
      nameIdFormats: [],
      requestedAttributes: [],
      signingCertificates: [],
      encryptionCertificates: [],
      wantAssertionsSigned: descriptor.getAttribute('WantAssertionsSigned') === 'true',
      authnRequestsSigned: descriptor.getAttribute('AuthnRequestsSigned') === 'true'
    };

    // Extract ACS endpoints
    const acsElements = descriptor.querySelectorAll('AssertionConsumerService');
    acsElements.forEach(acs => {
      sp.assertionConsumerServices.push({
        binding: acs.getAttribute('Binding'),
        location: acs.getAttribute('Location'),
        index: acs.getAttribute('index'),
        isDefault: acs.getAttribute('isDefault') === 'true'
      });
    });

    // Extract Single Logout Services
    const sloElements = descriptor.querySelectorAll('SingleLogoutService');
    sloElements.forEach(slo => {
      sp.singleLogoutServices.push({
        binding: slo.getAttribute('Binding'),
        location: slo.getAttribute('Location')
      });
    });

    // Extract NameID formats
    const nameIdElements = descriptor.querySelectorAll('NameIDFormat');
    nameIdElements.forEach(nid => {
      sp.nameIdFormats.push(nid.textContent.trim());
    });

    // Extract requested attributes
    const attrElements = descriptor.querySelectorAll('AttributeConsumingService Attribute, RequestedAttribute');
    attrElements.forEach(attr => {
      sp.requestedAttributes.push({
        name: attr.getAttribute('Name'),
        friendlyName: attr.getAttribute('FriendlyName'),
        nameFormat: attr.getAttribute('NameFormat'),
        isRequired: attr.getAttribute('isRequired') === 'true'
      });
    });

    // Extract certificates
    extractCertificates(descriptor, sp);

    return sp;
  }

  /**
   * Parse IdP metadata
   */
  function parseIdPMetadata(descriptor, doc) {
    const idp = {
      singleSignOnServices: [],
      singleLogoutServices: [],
      nameIdFormats: [],
      attributes: [],
      signingCertificates: [],
      encryptionCertificates: [],
      wantAuthnRequestsSigned: descriptor.getAttribute('WantAuthnRequestsSigned') === 'true'
    };

    // Extract SSO endpoints
    const ssoElements = descriptor.querySelectorAll('SingleSignOnService');
    ssoElements.forEach(sso => {
      idp.singleSignOnServices.push({
        binding: sso.getAttribute('Binding'),
        location: sso.getAttribute('Location')
      });
    });

    // Extract Single Logout Services
    const sloElements = descriptor.querySelectorAll('SingleLogoutService');
    sloElements.forEach(slo => {
      idp.singleLogoutServices.push({
        binding: slo.getAttribute('Binding'),
        location: slo.getAttribute('Location')
      });
    });

    // Extract NameID formats
    const nameIdElements = descriptor.querySelectorAll('NameIDFormat');
    nameIdElements.forEach(nid => {
      idp.nameIdFormats.push(nid.textContent.trim());
    });

    // Extract supported attributes
    const attrElements = descriptor.querySelectorAll('Attribute');
    attrElements.forEach(attr => {
      idp.attributes.push({
        name: attr.getAttribute('Name'),
        friendlyName: attr.getAttribute('FriendlyName'),
        nameFormat: attr.getAttribute('NameFormat')
      });
    });

    // Extract certificates
    extractCertificates(descriptor, idp);

    return idp;
  }

  /**
   * Extract certificates from descriptor
   */
  function extractCertificates(descriptor, target) {
    const keyDescriptors = descriptor.querySelectorAll('KeyDescriptor');
    
    keyDescriptors.forEach(kd => {
      const use = kd.getAttribute('use') || 'both';
      const certElement = kd.querySelector('X509Certificate');
      
      if (certElement) {
        const certData = certElement.textContent.trim().replace(/\s/g, '');
        const cert = {
          certificate: certData,
          fingerprint: calculateFingerprint(certData),
          use: use
        };

        if (use === 'signing' || use === 'both') {
          target.signingCertificates.push(cert);
        }
        if (use === 'encryption' || use === 'both') {
          target.encryptionCertificates.push(cert);
        }
      }
    });
  }

  /**
   * Calculate SHA-256 fingerprint of certificate
   */
  function calculateFingerprint(certData) {
    // This is a simplified version - in production, use crypto.subtle.digest
    try {
      const decoder = new TextDecoder();
      const data = Uint8Array.from(atob(certData), c => c.charCodeAt(0));
      
      // Return a placeholder - actual fingerprint calculation requires crypto API
      return 'SHA256:' + Array.from(data.slice(0, 32))
        .map(b => b.toString(16).padStart(2, '0'))
        .join(':').toUpperCase();
    } catch (error) {
      return 'Unable to calculate fingerprint';
    }
  }

  /**
   * Validate metadata completeness
   */
  function validateMetadata(metadata) {
    const issues = [];
    const warnings = [];
    
    // Check entity ID
    if (!metadata.entityId || metadata.entityId.trim() === '') {
      issues.push({
        severity: 'error',
        field: 'entityId',
        message: 'Entity ID is missing or empty'
      });
    }

    if (metadata.type === 'SP' && metadata.sp) {
      const sp = metadata.sp;
      
      // Check ACS
      if (sp.assertionConsumerServices.length === 0) {
        issues.push({
          severity: 'error',
          field: 'assertionConsumerServices',
          message: 'No Assertion Consumer Service (ACS) endpoints found'
        });
      }

      // Check for default ACS
      const hasDefaultACS = sp.assertionConsumerServices.some(acs => acs.isDefault);
      if (sp.assertionConsumerServices.length > 1 && !hasDefaultACS) {
        warnings.push({
          severity: 'warning',
          field: 'assertionConsumerServices',
          message: 'Multiple ACS endpoints but no default specified'
        });
      }

      // Check NameID formats
      if (sp.nameIdFormats.length === 0) {
        warnings.push({
          severity: 'warning',
          field: 'nameIdFormats',
          message: 'No NameID formats specified'
        });
      }

      // Check certificates
      if (sp.wantAssertionsSigned && sp.signingCertificates.length === 0) {
        warnings.push({
          severity: 'warning',
          field: 'signingCertificates',
          message: 'WantAssertionsSigned is true but no signing certificates found'
        });
      }

      if (sp.encryptionCertificates.length === 0) {
        warnings.push({
          severity: 'info',
          field: 'encryptionCertificates',
          message: 'No encryption certificates found (assertion encryption not available)'
        });
      }

    } else if (metadata.type === 'IdP' && metadata.idp) {
      const idp = metadata.idp;
      
      // Check SSO endpoints
      if (idp.singleSignOnServices.length === 0) {
        issues.push({
          severity: 'error',
          field: 'singleSignOnServices',
          message: 'No Single Sign-On Service endpoints found'
        });
      }

      // Check certificates
      if (idp.signingCertificates.length === 0) {
        warnings.push({
          severity: 'warning',
          field: 'signingCertificates',
          message: 'No signing certificates found - responses cannot be verified'
        });
      }
    }

    return {
      isValid: issues.filter(i => i.severity === 'error').length === 0,
      errors: issues.filter(i => i.severity === 'error'),
      warnings: warnings.filter(i => i.severity === 'warning'),
      info: warnings.filter(i => i.severity === 'info'),
      allIssues: [...issues, ...warnings]
    };
  }

  /**
   * Create manual baseline when metadata is unavailable
   */
  function createManualBaseline(config) {
    const baseline = {
      type: config.type || 'SP',
      entityId: config.entityId,
      manualEntry: true,
      parsedAt: new Date().toISOString()
    };

    if (config.type === 'SP') {
      baseline.sp = {
        assertionConsumerServices: config.acsUrls ? config.acsUrls.map((url, idx) => ({
          binding: config.binding || 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
          location: url,
          index: idx.toString(),
          isDefault: idx === 0
        })) : [],
        singleLogoutServices: config.logoutUrls ? config.logoutUrls.map(url => ({
          binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
          location: url
        })) : [],
        nameIdFormats: config.nameIdFormats || [],
        requestedAttributes: config.attributes ? config.attributes.map(attr => ({
          name: attr,
          isRequired: false
        })) : [],
        signingCertificates: [],
        encryptionCertificates: [],
        wantAssertionsSigned: config.wantAssertionsSigned || false,
        authnRequestsSigned: config.authnRequestsSigned || false
      };
    }

    baseline.validation = validateMetadata(baseline);
    return baseline;
  }

  /**
   * Extract domain from URL
   */
  function extractDomain(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname;
    } catch (error) {
      return url;
    }
  }

  // Public API
  return {
    parseMetadata,
    createManualBaseline,
    validateMetadata,
    extractDomain
  };
})();
