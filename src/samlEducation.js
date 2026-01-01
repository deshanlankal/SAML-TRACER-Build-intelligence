/**
 * SAML Education Content - Educational content for learning mode
 */

var SAMLEducation = (function() {
  'use strict';

  /**
   * Educational content for SAML elements
   */
  const ELEMENT_EXPLANATIONS = {
    // Core Protocol Elements
    'samlp:AuthnRequest': {
      title: 'Authentication Request',
      description: 'Sent by the Service Provider (SP) to the Identity Provider (IdP) to request user authentication.',
      purpose: 'Initiates the SAML SSO flow by asking the IdP to authenticate a user.',
      required: true,
      learnMore: 'https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf'
    },
    'samlp:Response': {
      title: 'SAML Response',
      description: 'The IdP\'s response to an authentication request, containing assertions about the authenticated user.',
      purpose: 'Delivers authentication status and user attributes back to the SP.',
      required: true,
      learnMore: 'https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf'
    },
    'saml:Assertion': {
      title: 'SAML Assertion',
      description: 'A statement from the IdP asserting facts about the user, such as identity and attributes.',
      purpose: 'Contains the core information about the authenticated user.',
      required: true,
      learnMore: 'https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf'
    },
    'samlp:LogoutRequest': {
      title: 'Logout Request',
      description: 'Initiates Single Logout (SLO) to end the user\'s session across all participating applications.',
      purpose: 'Coordinates logout across SP and IdP to end the SSO session.',
      required: false,
      learnMore: 'https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf'
    },

    // Identifiers
    'saml:Issuer': {
      title: 'Issuer',
      description: 'Identifies who created the SAML message (SP or IdP entity ID).',
      purpose: 'Establishes trust by identifying the message sender. Must match metadata.',
      required: true,
      example: 'https://sp.example.com or https://idp.example.com'
    },
    'ID': {
      title: 'Message ID',
      description: 'Unique identifier for this SAML message.',
      purpose: 'Prevents replay attacks and allows correlation of requests and responses.',
      required: true,
      example: '_abc123def456'
    },
    'InResponseTo': {
      title: 'In Response To',
      description: 'References the ID of the AuthnRequest this response is answering.',
      purpose: 'Links the response back to the original request for security and validation.',
      required: false,
      example: '_xyz789'
    },

    // Destinations and Endpoints
    'Destination': {
      title: 'Destination URL',
      description: 'The URL where this message should be sent.',
      purpose: 'Prevents message interception by validating the intended recipient.',
      required: true,
      example: 'https://sp.example.com/acs'
    },
    'AssertionConsumerServiceURL': {
      title: 'ACS URL',
      description: 'The Service Provider endpoint that receives SAML responses.',
      purpose: 'Tells the IdP where to send the authentication response.',
      required: true,
      example: 'https://sp.example.com/saml/acs'
    },

    // Subject and Identity
    'saml:Subject': {
      title: 'Subject',
      description: 'Identifies the user this assertion is about.',
      purpose: 'Specifies who has been authenticated.',
      required: true,
      learnMore: 'Contains NameID and SubjectConfirmation'
    },
    'saml:NameID': {
      title: 'Name ID',
      description: 'The identifier for the authenticated user.',
      purpose: 'Provides the user\'s identity in a format agreed upon by SP and IdP.',
      required: true,
      example: 'user@example.com or jsmith or 12345'
    },
    'Format': {
      title: 'NameID Format',
      description: 'Specifies the format of the NameID value.',
      purpose: 'Ensures both parties interpret the user identifier correctly.',
      required: false,
      example: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
    },

    // Conditions and Timing
    'saml:Conditions': {
      title: 'Conditions',
      description: 'Constraints under which the assertion is valid.',
      purpose: 'Defines when and where the assertion can be used.',
      required: true,
      learnMore: 'Includes NotBefore, NotOnOrAfter, and AudienceRestriction'
    },
    'NotBefore': {
      title: 'Not Before Time',
      description: 'The earliest time the assertion is valid.',
      purpose: 'Prevents use of assertions before they should be valid (clock skew protection).',
      required: false,
      example: '2026-01-01T10:00:00Z'
    },
    'NotOnOrAfter': {
      title: 'Not On Or After Time',
      description: 'The latest time the assertion is valid.',
      purpose: 'Limits how long an assertion can be used (security best practice).',
      required: true,
      example: '2026-01-01T11:00:00Z'
    },
    'saml:AudienceRestriction': {
      title: 'Audience Restriction',
      description: 'Limits which Service Providers can consume this assertion.',
      purpose: 'Prevents other SPs from misusing assertions intended for a specific SP.',
      required: true,
      learnMore: 'Should contain the SP entity ID'
    },
    'saml:Audience': {
      title: 'Audience',
      description: 'The entity ID of the intended Service Provider.',
      purpose: 'Specifies who can accept this assertion. Must match SP\'s entity ID.',
      required: true,
      example: 'https://sp.example.com'
    },

    // Authentication Context
    'saml:AuthnStatement': {
      title: 'Authentication Statement',
      description: 'Describes how and when the user was authenticated.',
      purpose: 'Provides authentication method details for security decisions.',
      required: true,
      learnMore: 'Contains AuthnContext and SessionIndex'
    },
    'saml:AuthnContext': {
      title: 'Authentication Context',
      description: 'Describes the authentication method used.',
      purpose: 'Indicates authentication strength (password, MFA, certificate, etc.).',
      required: true,
      example: 'PasswordProtectedTransport'
    },
    'saml:AuthnContextClassRef': {
      title: 'Authentication Context Class',
      description: 'URI specifying the authentication method.',
      purpose: 'Standardized way to communicate authentication strength.',
      required: true,
      example: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
    },
    'SessionIndex': {
      title: 'Session Index',
      description: 'Identifier for the authentication session at the IdP.',
      purpose: 'Used for Single Logout to identify which session to terminate.',
      required: false,
      example: '_session123'
    },

    // Attributes
    'saml:AttributeStatement': {
      title: 'Attribute Statement',
      description: 'Contains user attributes (profile data) from the IdP.',
      purpose: 'Provides user information like email, name, groups, etc.',
      required: false,
      learnMore: 'Contains multiple Attribute elements'
    },
    'saml:Attribute': {
      title: 'Attribute',
      description: 'A single piece of information about the user.',
      purpose: 'Carries user profile data or group memberships.',
      required: false,
      example: 'email, firstName, groups'
    },
    'Name': {
      title: 'Attribute Name',
      description: 'The name/key of this attribute.',
      purpose: 'Identifies what this attribute represents.',
      required: true,
      example: 'email, firstName, memberOf'
    },
    'saml:AttributeValue': {
      title: 'Attribute Value',
      description: 'The actual value of the attribute.',
      purpose: 'Contains the user\'s data for this attribute.',
      required: true,
      example: 'user@example.com, John, Engineering'
    },

    // Security and Signatures
    'ds:Signature': {
      title: 'XML Signature',
      description: 'Digital signature ensuring message integrity and authenticity.',
      purpose: 'Prevents tampering and verifies the sender\'s identity.',
      required: true,
      learnMore: 'https://www.w3.org/TR/xmldsig-core/'
    },
    'ds:SignatureMethod': {
      title: 'Signature Algorithm',
      description: 'The cryptographic algorithm used for signing.',
      purpose: 'Defines how the signature was created.',
      required: true,
      example: 'RSA-SHA256 (recommended) or RSA-SHA1 (deprecated)'
    },
    'ds:DigestMethod': {
      title: 'Digest Algorithm',
      description: 'The hashing algorithm used in the signature.',
      purpose: 'Part of the signature process.',
      required: true,
      example: 'SHA256 (recommended) or SHA1 (deprecated)'
    },
    'ds:X509Certificate': {
      title: 'X.509 Certificate',
      description: 'The public certificate used to verify the signature.',
      purpose: 'Allows verification of the signature\'s authenticity.',
      required: true,
      learnMore: 'Should match certificate in metadata'
    },

    // Subject Confirmation
    'saml:SubjectConfirmation': {
      title: 'Subject Confirmation',
      description: 'Specifies how the subject (user) should be confirmed.',
      purpose: 'Defines the method and constraints for validating the user.',
      required: true,
      example: 'Bearer method is most common'
    },
    'Method': {
      title: 'Confirmation Method',
      description: 'The method used to confirm the subject.',
      purpose: 'Specifies the subject confirmation mechanism.',
      required: true,
      example: 'urn:oasis:names:tc:SAML:2.0:cm:bearer'
    },
    'saml:SubjectConfirmationData': {
      title: 'Subject Confirmation Data',
      description: 'Additional data for subject confirmation.',
      purpose: 'Contains Recipient, NotOnOrAfter, and InResponseTo for Bearer method.',
      required: true,
      learnMore: 'Critical for Bearer subject confirmation'
    },
    'Recipient': {
      title: 'Recipient URL',
      description: 'The URL where the assertion should be delivered.',
      purpose: 'Ensures the assertion is used at the correct endpoint.',
      required: true,
      example: 'https://sp.example.com/saml/acs'
    },

    // Status
    'samlp:Status': {
      title: 'Status',
      description: 'Indicates the success or failure of the authentication.',
      purpose: 'Reports whether authentication succeeded or why it failed.',
      required: true,
      learnMore: 'Contains StatusCode and optional StatusMessage'
    },
    'samlp:StatusCode': {
      title: 'Status Code',
      description: 'The result code of the authentication attempt.',
      purpose: 'Indicates success or specific error type.',
      required: true,
      example: 'Success, AuthnFailed, RequestDenied'
    },
    'samlp:StatusMessage': {
      title: 'Status Message',
      description: 'Human-readable description of the status.',
      purpose: 'Provides details about errors or failures.',
      required: false,
      example: 'Invalid credentials'
    }
  };

  /**
   * Common SAML error codes and their meanings
   */
  const ERROR_CODES = {
    'urn:oasis:names:tc:SAML:2.0:status:Success': {
      description: 'Authentication succeeded',
      meaning: 'The user was successfully authenticated',
      severity: 'success'
    },
    'urn:oasis:names:tc:SAML:2.0:status:Requester': {
      description: 'Error in the request',
      meaning: 'The SP sent an invalid or malformed request',
      severity: 'error'
    },
    'urn:oasis:names:tc:SAML:2.0:status:Responder': {
      description: 'Error in the response',
      meaning: 'The IdP encountered an error processing the request',
      severity: 'error'
    },
    'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch': {
      description: 'SAML version mismatch',
      meaning: 'The SAML version in the request is not supported',
      severity: 'error'
    },
    'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed': {
      description: 'Authentication failed',
      meaning: 'User provided invalid credentials or authentication was denied',
      severity: 'error'
    },
    'urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue': {
      description: 'Invalid attribute',
      meaning: 'An attribute name or value is invalid',
      severity: 'error'
    },
    'urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy': {
      description: 'Invalid NameID policy',
      meaning: 'The requested NameID format is not supported',
      severity: 'error'
    },
    'urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext': {
      description: 'No authentication context',
      meaning: 'The IdP cannot provide the requested authentication context',
      severity: 'error'
    },
    'urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP': {
      description: 'No available IdP',
      meaning: 'No IdP is available to authenticate the user',
      severity: 'error'
    },
    'urn:oasis:names:tc:SAML:2.0:status:NoPassive': {
      description: 'Passive authentication not possible',
      meaning: 'Cannot authenticate without user interaction',
      severity: 'warning'
    },
    'urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP': {
      description: 'No supported IdP',
      meaning: 'The IdP does not support the requested features',
      severity: 'error'
    },
    'urn:oasis:names:tc:SAML:2.0:status:PartialLogout': {
      description: 'Partial logout',
      meaning: 'Logout succeeded at some but not all participants',
      severity: 'warning'
    },
    'urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded': {
      description: 'Proxy count exceeded',
      meaning: 'Too many intermediary IdPs in the chain',
      severity: 'error'
    },
    'urn:oasis:names:tc:SAML:2.0:status:RequestDenied': {
      description: 'Request denied',
      meaning: 'The IdP refused to process the request',
      severity: 'error'
    },
    'urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported': {
      description: 'Request unsupported',
      meaning: 'The requested operation is not supported',
      severity: 'error'
    },
    'urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated': {
      description: 'Request version deprecated',
      meaning: 'The SAML version is deprecated',
      severity: 'warning'
    },
    'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh': {
      description: 'Request version too high',
      meaning: 'The SAML version is too new for the IdP',
      severity: 'error'
    },
    'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow': {
      description: 'Request version too low',
      meaning: 'The SAML version is too old',
      severity: 'error'
    },
    'urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized': {
      description: 'Resource not recognized',
      meaning: 'The requested resource is not known to the IdP',
      severity: 'error'
    },
    'urn:oasis:names:tc:SAML:2.0:status:TooManyResponses': {
      description: 'Too many responses',
      meaning: 'The response contains too many assertions',
      severity: 'error'
    },
    'urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile': {
      description: 'Unknown attribute profile',
      meaning: 'The attribute profile is not recognized',
      severity: 'error'
    },
    'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal': {
      description: 'Unknown principal',
      meaning: 'The user is not known to the IdP',
      severity: 'error'
    },
    'urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding': {
      description: 'Unsupported binding',
      meaning: 'The requested SAML binding is not supported',
      severity: 'error'
    }
  };

  /**
   * Get explanation for an element
   */
  function getExplanation(elementName) {
    // Remove namespace prefix if present
    const cleanName = elementName.includes(':') ? 
      elementName.split(':')[1] : elementName;
    
    // Try with namespace
    if (ELEMENT_EXPLANATIONS[elementName]) {
      return ELEMENT_EXPLANATIONS[elementName];
    }
    
    // Try without namespace
    for (const [key, value] of Object.entries(ELEMENT_EXPLANATIONS)) {
      if (key.endsWith(cleanName)) {
        return value;
      }
    }
    
    return null;
  }

  /**
   * Get error code explanation
   */
  function getErrorCodeExplanation(statusCode) {
    return ERROR_CODES[statusCode] || {
      description: 'Unknown status code',
      meaning: 'This status code is not in the SAML 2.0 specification',
      severity: 'unknown'
    };
  }

  /**
   * Get all explanations (for glossary)
   */
  function getAllExplanations() {
    return ELEMENT_EXPLANATIONS;
  }

  /**
   * Get all error codes (for reference)
   */
  function getAllErrorCodes() {
    return ERROR_CODES;
  }

  // Public API
  return {
    getExplanation,
    getErrorCodeExplanation,
    getAllExplanations,
    getAllErrorCodes
  };
})();
