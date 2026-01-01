/**
 * Attribute Mapping Advisor - Analyzes SAML attributes and suggests mappings
 */

var AttributeMapper = (function() {
  'use strict';

  // Common attribute mappings
  const STANDARD_MAPPINGS = {
    // Email mappings
    'email': ['mail', 'emailAddress', 'email', 'Email', 'EMAIL', 'userPrincipalName'],
    'mail': ['mail', 'emailAddress', 'email', 'Email', 'EMAIL', 'userPrincipalName'],
    'emailAddress': ['mail', 'emailAddress', 'email', 'Email', 'EMAIL', 'userPrincipalName'],
    
    // Username mappings
    'username': ['uid', 'sAMAccountName', 'userName', 'username', 'Username', 'USER_NAME'],
    'uid': ['uid', 'sAMAccountName', 'userName', 'username', 'Username', 'USER_NAME'],
    'sAMAccountName': ['uid', 'sAMAccountName', 'userName', 'username', 'Username', 'USER_NAME'],
    
    // User ID mappings
    'userId': ['employeeNumber', 'employeeID', 'uid', 'userID', 'userId', 'id'],
    'employeeNumber': ['employeeNumber', 'employeeID', 'uid', 'userID', 'userId', 'id'],
    
    // Name mappings
    'displayName': ['displayName', 'cn', 'commonName', 'fullName', 'name'],
    'cn': ['displayName', 'cn', 'commonName', 'fullName', 'name'],
    'givenName': ['givenName', 'firstName', 'fname', 'given_name'],
    'sn': ['sn', 'surname', 'lastName', 'lname', 'family_name'],
    'firstName': ['givenName', 'firstName', 'fname', 'given_name'],
    'lastName': ['sn', 'surname', 'lastName', 'lname', 'family_name'],
    
    // Group/Role mappings
    'memberOf': ['memberOf', 'groups', 'group', 'roles', 'role'],
    'groups': ['memberOf', 'groups', 'group', 'roles', 'role'],
    'role': ['memberOf', 'groups', 'group', 'roles', 'role'],
    
    // Organization mappings
    'department': ['department', 'departmentNumber', 'ou', 'organizationalUnit'],
    'company': ['company', 'o', 'organization', 'organizationName'],
    'title': ['title', 'jobTitle', 'position'],
    
    // Phone mappings
    'telephoneNumber': ['telephoneNumber', 'phone', 'phoneNumber', 'mobile', 'mobileNumber']
  };

  // Standard attribute formats
  const ATTRIBUTE_FORMATS = {
    'urn:oasis:names:tc:SAML:2.0:attrname-format:uri': 'URI Format',
    'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified': 'Unspecified',
    'urn:oasis:names:tc:SAML:2.0:attrname-format:basic': 'Basic'
  };

  /**
   * Analyze attributes from a SAML message
   */
  function analyzeAttributes(request) {
    if (!request.saml) {
      return null;
    }

    const samlDoc = parseSAMLDocument(request.saml);
    if (!samlDoc) {
      return null;
    }

    const results = {
      timestamp: new Date().toISOString(),
      attributes: [],
      identityAttributes: {},
      mappingSuggestions: [],
      issues: [],
      summary: {
        totalAttributes: 0,
        identifiedAttributes: 0,
        duplicates: 0,
        missing: 0
      }
    };

    // Extract attributes
    const attributeElements = samlDoc.querySelectorAll('AttributeStatement Attribute');
    
    attributeElements.forEach(attr => {
      const name = attr.getAttribute('Name');
      const friendlyName = attr.getAttribute('FriendlyName');
      const nameFormat = attr.getAttribute('NameFormat');
      const values = [];
      
      attr.querySelectorAll('AttributeValue').forEach(val => {
        values.push(val.textContent.trim());
      });

      const attribute = {
        name: name,
        friendlyName: friendlyName,
        nameFormat: nameFormat,
        nameFormatDescription: ATTRIBUTE_FORMATS[nameFormat] || 'Unknown',
        values: values,
        valueCount: values.length
      };

      results.attributes.push(attribute);
    });

    results.summary.totalAttributes = results.attributes.length;

    // Identify common identity attributes
    identifyIdentityAttributes(results);

    // Check for duplicates
    checkDuplicates(results);

    // Generate mapping suggestions
    generateMappingSuggestions(results);

    // Check for missing mandatory attributes
    checkMissingAttributes(results);

    return results;
  }

  /**
   * Identify common identity attributes
   */
  function identifyIdentityAttributes(results) {
    const identityTypes = {
      email: /^(mail|email|emailaddress|userprincipalname)$/i,
      username: /^(uid|samaccountname|username|user)$/i,
      userId: /^(employeenumber|employeeid|userid|id)$/i,
      displayName: /^(displayname|cn|commonname|fullname|name)$/i,
      firstName: /^(givenname|firstname|fname|given_name)$/i,
      lastName: /^(sn|surname|lastname|lname|family_name)$/i,
      groups: /^(memberof|groups?|roles?)$/i,
      department: /^(department|ou|organizationalunit)$/i,
      phone: /^(telephonenumber|phone|mobile)$/i
    };

    results.attributes.forEach(attr => {
      const name = attr.name || attr.friendlyName || '';
      
      for (const [type, pattern] of Object.entries(identityTypes)) {
        if (pattern.test(name)) {
          if (!results.identityAttributes[type]) {
            results.identityAttributes[type] = [];
          }
          results.identityAttributes[type].push({
            name: attr.name,
            friendlyName: attr.friendlyName,
            values: attr.values
          });
          results.summary.identifiedAttributes++;
          break;
        }
      }
    });
  }

  /**
   * Check for duplicate attributes
   */
  function checkDuplicates(results) {
    const seen = new Map();
    
    results.attributes.forEach(attr => {
      const key = attr.name || attr.friendlyName;
      
      if (seen.has(key)) {
        results.issues.push({
          severity: 'warning',
          type: 'duplicate',
          message: `Duplicate attribute found: ${key}`,
          attribute: key,
          occurrences: seen.get(key) + 1
        });
        seen.set(key, seen.get(key) + 1);
        results.summary.duplicates++;
      } else {
        seen.set(key, 1);
      }
    });
  }

  /**
   * Generate mapping suggestions
   */
  function generateMappingSuggestions(results) {
    results.attributes.forEach(attr => {
      const name = attr.name || attr.friendlyName || '';
      const nameLower = name.toLowerCase();
      
      // Find standard mapping
      for (const [standard, variants] of Object.entries(STANDARD_MAPPINGS)) {
        if (variants.some(v => v.toLowerCase() === nameLower)) {
          results.mappingSuggestions.push({
            attributeName: attr.name,
            friendlyName: attr.friendlyName,
            suggestedMapping: standard,
            confidence: 'high',
            reason: `Matches standard ${standard} attribute pattern`,
            example: attr.values.length > 0 ? attr.values[0] : null
          });
          break;
        }
      }
    });

    // Suggest mappings for unidentified attributes with email-like values
    results.attributes.forEach(attr => {
      if (attr.values.length > 0 && attr.values[0].includes('@')) {
        const alreadyMapped = results.mappingSuggestions.some(s => s.attributeName === attr.name);
        if (!alreadyMapped) {
          results.mappingSuggestions.push({
            attributeName: attr.name,
            friendlyName: attr.friendlyName,
            suggestedMapping: 'email',
            confidence: 'medium',
            reason: 'Value appears to be an email address',
            example: attr.values[0]
          });
        }
      }
    });
  }

  /**
   * Check for missing mandatory attributes
   */
  function checkMissingAttributes(results) {
    const mandatoryAttributes = ['email', 'username', 'userId'];
    
    mandatoryAttributes.forEach(required => {
      if (!results.identityAttributes[required] || results.identityAttributes[required].length === 0) {
        results.issues.push({
          severity: 'error',
          type: 'missing',
          message: `Mandatory attribute missing: ${required}`,
          attribute: required,
          recommendation: `Configure IdP to release ${required} attribute`,
          alternatives: STANDARD_MAPPINGS[required] || []
        });
        results.summary.missing++;
      }
    });

    // Check for optional but recommended attributes
    const recommendedAttributes = ['displayName', 'firstName', 'lastName'];
    recommendedAttributes.forEach(recommended => {
      if (!results.identityAttributes[recommended] || results.identityAttributes[recommended].length === 0) {
        results.issues.push({
          severity: 'warning',
          type: 'missing',
          message: `Recommended attribute missing: ${recommended}`,
          attribute: recommended,
          recommendation: `Consider adding ${recommended} for better user experience`
        });
      }
    });
  }

  /**
   * Generate attribute mapping configuration
   */
  function generateMappingConfig(attributeAnalysis, format = 'json') {
    if (!attributeAnalysis) {
      return null;
    }

    const config = {
      generatedAt: new Date().toISOString(),
      source: 'SAML Tracer Intelligence',
      mappings: {}
    };

    attributeAnalysis.mappingSuggestions.forEach(suggestion => {
      config.mappings[suggestion.suggestedMapping] = {
        samlAttribute: suggestion.attributeName,
        friendlyName: suggestion.friendlyName,
        confidence: suggestion.confidence,
        example: suggestion.example
      };
    });

    if (format === 'json') {
      return JSON.stringify(config, null, 2);
    } else if (format === 'yaml') {
      return generateYAML(config);
    } else if (format === 'text') {
      return generateTextMapping(config);
    }

    return config;
  }

  /**
   * Generate YAML format
   */
  function generateYAML(config) {
    let yaml = `# SAML Attribute Mapping Configuration\n`;
    yaml += `# Generated: ${config.generatedAt}\n\n`;
    yaml += `mappings:\n`;
    
    for (const [field, mapping] of Object.entries(config.mappings)) {
      yaml += `  ${field}:\n`;
      yaml += `    saml_attribute: "${mapping.samlAttribute}"\n`;
      if (mapping.friendlyName) {
        yaml += `    friendly_name: "${mapping.friendlyName}"\n`;
      }
      yaml += `    confidence: ${mapping.confidence}\n`;
      if (mapping.example) {
        yaml += `    example: "${mapping.example}"\n`;
      }
      yaml += `\n`;
    }
    
    return yaml;
  }

  /**
   * Generate text format
   */
  function generateTextMapping(config) {
    let text = `SAML Attribute Mapping Configuration\n`;
    text += `Generated: ${config.generatedAt}\n`;
    text += `${'='.repeat(60)}\n\n`;
    
    for (const [field, mapping] of Object.entries(config.mappings)) {
      text += `${field.toUpperCase()}:\n`;
      text += `  SAML Attribute: ${mapping.samlAttribute}\n`;
      if (mapping.friendlyName) {
        text += `  Friendly Name: ${mapping.friendlyName}\n`;
      }
      text += `  Confidence: ${mapping.confidence}\n`;
      if (mapping.example) {
        text += `  Example Value: ${mapping.example}\n`;
      }
      text += `\n`;
    }
    
    return text;
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
    analyzeAttributes,
    generateMappingConfig
  };
})();
