/**
 * Diff Tool - Compare two SAML messages side-by-side
 */

var DiffTool = (function() {
  'use strict';

  /**
   * Compare two SAML messages
   */
  function compareMessages(msg1, msg2) {
    const comparison = {
      metadata: {
        same: 0,
        different: 0,
        added: 0,
        removed: 0
      },
      fields: []
    };

    // Basic metadata
    compareField(comparison, 'Message Type', msg1.type, msg2.type);
    compareField(comparison, 'Direction', msg1.direction, msg2.direction);
    
    // SAML specific fields
    if (msg1.saml && msg2.saml) {
      const saml1 = msg1.saml;
      const saml2 = msg2.saml;
      
      // Core identifiers
      compareField(comparison, 'Issuer', saml1.issuer, saml2.issuer);
      compareField(comparison, 'Message ID', saml1.id, saml2.id);
      compareField(comparison, 'InResponseTo', saml1.inResponseTo, saml2.inResponseTo);
      
      // Endpoints
      compareField(comparison, 'Destination', saml1.destination, saml2.destination);
      compareField(comparison, 'ACS URL', saml1.acsUrl, saml2.acsUrl);
      
      // Subject/Identity
      compareField(comparison, 'Subject NameID', saml1.subject?.nameId, saml2.subject?.nameId);
      compareField(comparison, 'NameID Format', saml1.subject?.nameIdFormat, saml2.subject?.nameIdFormat);
      
      // Timing
      compareField(comparison, 'Issue Instant', saml1.issueInstant, saml2.issueInstant);
      compareField(comparison, 'NotBefore', saml1.notBefore, saml2.notBefore);
      compareField(comparison, 'NotOnOrAfter', saml1.notOnOrAfter, saml2.notOnOrAfter);
      
      // Conditions
      compareField(comparison, 'Audience', saml1.audience, saml2.audience);
      compareField(comparison, 'Recipient', saml1.recipient, saml2.recipient);
      
      // Authentication
      compareField(comparison, 'AuthnContext', saml1.authnContext, saml2.authnContext);
      compareField(comparison, 'Session Index', saml1.sessionIndex, saml2.sessionIndex);
      
      // Status
      compareField(comparison, 'Status Code', saml1.statusCode, saml2.statusCode);
      compareField(comparison, 'Status Message', saml1.statusMessage, saml2.statusMessage);
      
      // Binding
      compareField(comparison, 'Binding', saml1.binding, saml2.binding);
      
      // Security
      compareField(comparison, 'Signed', saml1.signed ? 'Yes' : 'No', saml2.signed ? 'Yes' : 'No');
      compareField(comparison, 'Encrypted', saml1.encrypted ? 'Yes' : 'No', saml2.encrypted ? 'Yes' : 'No');
      
      // Attributes
      const attrComparison = compareAttributes(saml1.attributes, saml2.attributes);
      comparison.attributes = attrComparison;
      
      // Update metadata counts for attributes
      comparison.metadata.same += attrComparison.same.length;
      comparison.metadata.different += attrComparison.different.length;
      comparison.metadata.added += attrComparison.added.length;
      comparison.metadata.removed += attrComparison.removed.length;
      
      // Certificates
      const certComparison = compareCertificates(msg1, msg2);
      comparison.certificates = certComparison;
    }

    return comparison;
  }

  /**
   * Compare a single field
   */
  function compareField(comparison, name, value1, value2) {
    const status = determineStatus(value1, value2);
    
    comparison.fields.push({
      name: name,
      value1: value1,
      value2: value2,
      status: status
    });
    
    comparison.metadata[status]++;
  }

  /**
   * Determine comparison status
   */
  function determineStatus(value1, value2) {
    const hasValue1 = value1 !== undefined && value1 !== null && value1 !== '';
    const hasValue2 = value2 !== undefined && value2 !== null && value2 !== '';
    
    if (!hasValue1 && !hasValue2) {
      return 'same'; // Both empty
    }
    if (!hasValue1 && hasValue2) {
      return 'added'; // Added in message 2
    }
    if (hasValue1 && !hasValue2) {
      return 'removed'; // Removed in message 2
    }
    
    // Both have values, compare
    const str1 = String(value1).trim();
    const str2 = String(value2).trim();
    
    return str1 === str2 ? 'same' : 'different';
  }

  /**
   * Compare attributes
   */
  function compareAttributes(attrs1, attrs2) {
    const comparison = {
      same: [],
      different: [],
      added: [],
      removed: []
    };
    
    if (!attrs1) attrs1 = [];
    if (!attrs2) attrs2 = [];
    
    // Create maps for easy lookup
    const map1 = {};
    const map2 = {};
    
    attrs1.forEach(attr => {
      map1[attr.name] = attr.values;
    });
    
    attrs2.forEach(attr => {
      map2[attr.name] = attr.values;
    });
    
    // Find all unique attribute names
    const allNames = new Set([...Object.keys(map1), ...Object.keys(map2)]);
    
    allNames.forEach(name => {
      const val1 = map1[name];
      const val2 = map2[name];
      
      if (val1 && val2) {
        // Both have this attribute
        const same = arraysEqual(val1, val2);
        const item = {
          name: name,
          values1: val1,
          values2: val2
        };
        
        if (same) {
          comparison.same.push(item);
        } else {
          comparison.different.push(item);
        }
      } else if (val1 && !val2) {
        comparison.removed.push({
          name: name,
          values1: val1
        });
      } else if (!val1 && val2) {
        comparison.added.push({
          name: name,
          values2: val2
        });
      }
    });
    
    return comparison;
  }

  /**
   * Compare certificates
   */
  function compareCertificates(msg1, msg2) {
    const certs1 = CertificateValidator.extractCertificatesFromMessage(msg1);
    const certs2 = CertificateValidator.extractCertificatesFromMessage(msg2);
    
    const comparison = {
      same: [],
      different: [],
      added: [],
      removed: []
    };
    
    // Compare by fingerprint
    const fingerprints1 = certs1.map(c => c.fingerprint);
    const fingerprints2 = certs2.map(c => c.fingerprint);
    
    certs1.forEach(cert => {
      if (fingerprints2.includes(cert.fingerprint)) {
        comparison.same.push({
          fingerprint: cert.fingerprint,
          usage: cert.usage
        });
      } else {
        comparison.removed.push({
          fingerprint: cert.fingerprint,
          usage: cert.usage
        });
      }
    });
    
    certs2.forEach(cert => {
      if (!fingerprints1.includes(cert.fingerprint)) {
        comparison.added.push({
          fingerprint: cert.fingerprint,
          usage: cert.usage
        });
      }
    });
    
    return comparison;
  }

  /**
   * Check if two arrays are equal
   */
  function arraysEqual(arr1, arr2) {
    if (arr1.length !== arr2.length) return false;
    
    // Sort both arrays for comparison
    const sorted1 = [...arr1].sort();
    const sorted2 = [...arr2].sort();
    
    return sorted1.every((val, idx) => val === sorted2[idx]);
  }

  /**
   * Generate HTML for diff display
   */
  function generateDiffHTML(diff, msg1, msg2) {
    let html = '';
    
    // Comparison panels
    html += '<div class="comparison-container">';
    html += generateMessagePanel('Message 1', msg1);
    html += generateMessagePanel('Message 2', msg2);
    html += '</div>';
    
    // Summary statistics
    html += '<div class="diff-summary">';
    html += '<h3>Comparison Summary</h3>';
    html += '<div class="diff-stats">';
    html += `<div class="stat-card same">
      <div class="stat-value">${diff.metadata.same}</div>
      <div class="stat-label">Same</div>
    </div>`;
    html += `<div class="stat-card different">
      <div class="stat-value">${diff.metadata.different}</div>
      <div class="stat-label">Different</div>
    </div>`;
    html += `<div class="stat-card different">
      <div class="stat-value">${diff.metadata.added}</div>
      <div class="stat-label">Added</div>
    </div>`;
    html += `<div class="stat-card different">
      <div class="stat-value">${diff.metadata.removed}</div>
      <div class="stat-label">Removed</div>
    </div>`;
    html += '</div>';
    html += '</div>';
    
    // Field differences
    const differentFields = diff.fields.filter(f => f.status !== 'same');
    if (differentFields.length > 0) {
      html += '<div class="diff-section">';
      html += '<h3>Field Differences</h3>';
      
      differentFields.forEach(field => {
        html += generateFieldDiff(field);
      });
      
      html += '</div>';
    }
    
    // Attribute differences
    if (diff.attributes) {
      const hasAttrDiffs = diff.attributes.different.length > 0 ||
                          diff.attributes.added.length > 0 ||
                          diff.attributes.removed.length > 0;
      
      if (hasAttrDiffs) {
        html += '<div class="diff-section">';
        html += '<h3>Attribute Differences</h3>';
        html += generateAttributeDiff(diff.attributes);
        html += '</div>';
      }
    }
    
    // Certificate differences
    if (diff.certificates) {
      const hasCertDiffs = diff.certificates.different.length > 0 ||
                          diff.certificates.added.length > 0 ||
                          diff.certificates.removed.length > 0;
      
      if (hasCertDiffs) {
        html += '<div class="diff-section">';
        html += '<h3>Certificate Differences</h3>';
        html += generateCertificateDiff(diff.certificates);
        html += '</div>';
      }
    }
    
    // Show message if everything is the same
    if (diff.metadata.different === 0 && diff.metadata.added === 0 && diff.metadata.removed === 0) {
      html += '<div class="diff-section" style="text-align: center; color: #27ae60;">';
      html += '<h3>✅ Messages are identical</h3>';
      html += '<p>No differences found between the two SAML messages.</p>';
      html += '</div>';
    }
    
    return html;
  }

  /**
   * Generate message panel HTML
   */
  function generateMessagePanel(title, msg) {
    let html = '<div class="message-panel">';
    html += `<div class="panel-header">${title}</div>`;
    html += '<div class="panel-content">';
    
    if (msg.saml) {
      html += '<div class="message-info">';
      html += `<div><strong>Type:</strong> ${msg.type || 'Unknown'}</div>`;
      html += `<div><strong>Direction:</strong> ${msg.direction || 'Unknown'}</div>`;
      html += `<div><strong>Issuer:</strong> ${msg.saml.issuer || 'N/A'}</div>`;
      html += `<div><strong>Timestamp:</strong> ${new Date(msg.timestamp).toLocaleString()}</div>`;
      html += '</div>';
    } else {
      html += '<div class="message-info">No SAML data available</div>';
    }
    
    html += '</div>';
    html += '</div>';
    
    return html;
  }

  /**
   * Generate field diff HTML
   */
  function generateFieldDiff(field) {
    const icons = {
      'different': '🔄',
      'added': '➕',
      'removed': '➖',
      'same': '✅'
    };
    
    let html = `<div class="diff-item ${field.status}">`;
    html += `<div class="diff-item-header">`;
    html += `<span class="diff-icon">${icons[field.status]}</span>`;
    html += `<span>${field.name}</span>`;
    html += `</div>`;
    
    if (field.status === 'different' || field.status === 'removed' || field.status === 'added') {
      html += '<div class="diff-values">';
      html += '<div>';
      html += '<div class="value-label">Message 1:</div>';
      html += `<div class="value-box">${formatValue(field.value1)}</div>`;
      html += '</div>';
      html += '<div>';
      html += '<div class="value-label">Message 2:</div>';
      html += `<div class="value-box">${formatValue(field.value2)}</div>`;
      html += '</div>';
      html += '</div>';
    }
    
    html += '</div>';
    return html;
  }

  /**
   * Generate attribute diff HTML
   */
  function generateAttributeDiff(attrComparison) {
    let html = '<div class="attributes-diff">';
    
    // Different attributes
    if (attrComparison.different.length > 0) {
      html += '<h4>Modified Attributes</h4>';
      attrComparison.different.forEach(attr => {
        html += '<div class="diff-item different">';
        html += `<div class="diff-item-header">`;
        html += `<span class="diff-icon">🔄</span>`;
        html += `<span>${attr.name}</span>`;
        html += `</div>`;
        html += '<div class="diff-values">';
        html += '<div>';
        html += '<div class="value-label">Message 1:</div>';
        html += `<div class="value-box">${attr.values1.join(', ')}</div>`;
        html += '</div>';
        html += '<div>';
        html += '<div class="value-label">Message 2:</div>';
        html += `<div class="value-box">${attr.values2.join(', ')}</div>`;
        html += '</div>';
        html += '</div>';
        html += '</div>';
      });
    }
    
    // Added attributes
    if (attrComparison.added.length > 0) {
      html += '<h4>Added Attributes</h4>';
      attrComparison.added.forEach(attr => {
        html += '<div class="diff-item added">';
        html += `<div class="diff-item-header">`;
        html += `<span class="diff-icon">➕</span>`;
        html += `<span>${attr.name}</span>`;
        html += `</div>`;
        html += `<div class="value-box">${attr.values2.join(', ')}</div>`;
        html += '</div>';
      });
    }
    
    // Removed attributes
    if (attrComparison.removed.length > 0) {
      html += '<h4>Removed Attributes</h4>';
      attrComparison.removed.forEach(attr => {
        html += '<div class="diff-item removed">';
        html += `<div class="diff-item-header">`;
        html += `<span class="diff-icon">➖</span>`;
        html += `<span>${attr.name}</span>`;
        html += `</div>`;
        html += `<div class="value-box">${attr.values1.join(', ')}</div>`;
        html += '</div>';
      });
    }
    
    html += '</div>';
    return html;
  }

  /**
   * Generate certificate diff HTML
   */
  function generateCertificateDiff(certComparison) {
    let html = '<div class="certificates-diff">';
    
    // Different/Removed/Added certificates
    ['removed', 'added'].forEach(type => {
      if (certComparison[type].length > 0) {
        const label = type === 'removed' ? 'Removed Certificates' : 'Added Certificates';
        const icon = type === 'removed' ? '➖' : '➕';
        
        html += `<h4>${label}</h4>`;
        certComparison[type].forEach(cert => {
          html += `<div class="diff-item ${type}">`;
          html += `<div class="diff-item-header">`;
          html += `<span class="diff-icon">${icon}</span>`;
          html += `<span>Certificate (${cert.usage})</span>`;
          html += `</div>`;
          html += `<div class="value-box">Fingerprint: ${cert.fingerprint}</div>`;
          html += '</div>';
        });
      }
    });
    
    html += '</div>';
    return html;
  }

  /**
   * Format value for display
   */
  function formatValue(value) {
    if (value === undefined || value === null || value === '') {
      return '<em style="color: #999;">(empty)</em>';
    }
    return escapeHtml(String(value));
  }

  /**
   * Escape HTML
   */
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  /**
   * Open diff dialog
   */
  function openDiffDialog(msg1, msg2) {
    const width = 1200;
    const height = 800;
    const left = (screen.width - width) / 2;
    const top = (screen.height - height) / 2;
    
    const diffWindow = window.open(
      'diffDialog.html',
      'SAML Diff',
      `width=${width},height=${height},left=${left},top=${top},resizable=yes,scrollbars=yes`
    );
    
    // Send data when window is ready
    window.addEventListener('message', function handler(event) {
      if (event.data.type === 'diff-ready' && event.source === diffWindow) {
        diffWindow.postMessage({
          type: 'compare-messages',
          message1: msg1,
          message2: msg2
        }, '*');
        window.removeEventListener('message', handler);
      }
    });
  }

  // Public API
  return {
    compareMessages,
    generateDiffHTML,
    openDiffDialog
  };
})();
