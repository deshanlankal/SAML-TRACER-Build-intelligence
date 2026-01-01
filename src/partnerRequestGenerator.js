/**
 * Partner Request Generator - Generates communication for missing configuration
 */

var PartnerRequestGenerator = (function() {
  'use strict';

  /**
   * Generate partner request based on analysis results
   */
  function generateRequest(request, metadata, analysisResults) {
    const missingItems = [];
    const issues = [];

    // Analyze what's missing or misconfigured
    if (analysisResults) {
      // From comparison results
      if (analysisResults.comparison && analysisResults.comparison.applicable) {
        analysisResults.comparison.comparisons.forEach(comp => {
          if (comp.severity === 'error' || comp.severity === 'warning') {
            issues.push({
              type: 'configuration',
              field: comp.field,
              issue: comp.message,
              expected: comp.expected,
              actual: comp.actual
            });
          }
        });
      }

      // From security results
      if (analysisResults.security) {
        analysisResults.security.checks.forEach(check => {
          if (check.severity === 'critical' || check.severity === 'high') {
            issues.push({
              type: 'security',
              field: check.title,
              issue: check.message,
              remediation: check.remediation
            });
          }
        });
      }

      // From diagnostics
      if (analysisResults.diagnostics) {
        analysisResults.diagnostics.issues.forEach(issue => {
          if (issue.severity === 'error') {
            issues.push({
              type: 'diagnostic',
              field: issue.title,
              issue: issue.description,
              howToFix: issue.howToFix
            });
          }
        });
      }

      // From attribute analysis
      if (analysisResults.attributes) {
        analysisResults.attributes.issues.forEach(issue => {
          if (issue.type === 'missing' && issue.severity === 'error') {
            missingItems.push({
              category: 'Attribute',
              item: issue.attribute,
              reason: issue.message,
              alternatives: issue.alternatives
            });
          }
        });
      }

      // From checklist
      if (analysisResults.checklist) {
        analysisResults.checklist.items.forEach(item => {
          if (item.status === 'blocked') {
            missingItems.push({
              category: item.category,
              item: item.item,
              reason: item.message,
              action: item.action
            });
          }
        });
      }
    }

    // Check certificates
    if (metadata && metadata.type === 'SP' && metadata.sp) {
      if (metadata.sp.encryptionCertificates.length === 0) {
        missingItems.push({
          category: 'Certificate',
          item: 'Encryption Certificate',
          reason: 'No encryption certificate found in SP metadata',
          action: 'Provide encryption certificate for assertion encryption'
        });
      }
    }

    return {
      timestamp: new Date().toISOString(),
      application: metadata ? metadata.entityId : 'Unknown Application',
      missingItems: missingItems,
      issues: issues,
      hasBlockers: missingItems.length > 0 || issues.length > 0
    };
  }

  /**
   * Format as professional email
   */
  function formatAsEmail(requestData, partnerType = 'IdP') {
    const partnerName = partnerType === 'IdP' ? 'Identity Provider' : 'Service Provider';
    
    let email = `Subject: SAML Configuration - Required Information for ${requestData.application}\n\n`;
    email += `Dear ${partnerName} Team,\n\n`;
    email += `We are in the process of configuring SAML SSO integration for ${requestData.application}. `;
    email += `To complete the setup, we need the following information from your side:\n\n`;

    if (requestData.missingItems.length > 0) {
      email += `REQUIRED CONFIGURATION:\n`;
      email += `${'='.repeat(60)}\n\n`;

      const grouped = groupByCategory(requestData.missingItems);
      
      for (const [category, items] of Object.entries(grouped)) {
        email += `${category}:\n`;
        items.forEach((item, idx) => {
          email += `  ${idx + 1}. ${item.item}\n`;
          email += `     Reason: ${item.reason}\n`;
          if (item.action) {
            email += `     Action: ${item.action}\n`;
          }
          if (item.alternatives && item.alternatives.length > 0) {
            email += `     Alternatives: ${item.alternatives.join(', ')}\n`;
          }
          email += `\n`;
        });
        email += `\n`;
      }
    }

    if (requestData.issues.length > 0) {
      email += `\nCONFIGURATION ISSUES TO RESOLVE:\n`;
      email += `${'='.repeat(60)}\n\n`;

      requestData.issues.forEach((issue, idx) => {
        email += `${idx + 1}. ${issue.field}\n`;
        email += `   Issue: ${issue.issue}\n`;
        if (issue.expected) {
          email += `   Expected: ${issue.expected}\n`;
        }
        if (issue.actual) {
          email += `   Current: ${issue.actual}\n`;
        }
        if (issue.remediation) {
          email += `   Resolution: ${issue.remediation}\n`;
        }
        if (issue.howToFix && issue.howToFix.length > 0) {
          email += `   How to Fix:\n`;
          issue.howToFix.forEach(fix => {
            email += `     - ${fix}\n`;
          });
        }
        email += `\n`;
      });
    }

    email += `\nNEXT STEPS:\n`;
    email += `${'='.repeat(60)}\n`;
    email += `1. Please review the requirements above\n`;
    email += `2. Provide the requested information/configuration\n`;
    email += `3. We will validate the integration and confirm successful setup\n\n`;

    email += `Please let us know if you have any questions or need clarification on any of these items.\n\n`;
    email += `Thank you for your cooperation.\n\n`;
    email += `Best regards\n`;
    email += `\n---\n`;
    email += `Generated by SAML Tracer Intelligence\n`;
    email += `Date: ${new Date().toLocaleString()}\n`;

    return email;
  }

  /**
   * Format as ticket description
   */
  function formatAsTicket(requestData, ticketType = 'support') {
    let ticket = `SAML Integration Configuration Request\n`;
    ticket += `Application: ${requestData.application}\n`;
    ticket += `Generated: ${new Date().toLocaleString()}\n`;
    ticket += `${'='.repeat(70)}\n\n`;

    ticket += `SUMMARY:\n`;
    if (requestData.hasBlockers) {
      ticket += `❌ Configuration incomplete - ${requestData.missingItems.length} missing items, `;
      ticket += `${requestData.issues.length} issues found\n\n`;
    } else {
      ticket += `✅ Configuration appears complete\n\n`;
    }

    if (requestData.missingItems.length > 0) {
      ticket += `MISSING CONFIGURATION (${requestData.missingItems.length}):\n`;
      ticket += `${'-'.repeat(70)}\n`;

      const grouped = groupByCategory(requestData.missingItems);
      
      for (const [category, items] of Object.entries(grouped)) {
        ticket += `\n[${category}]\n`;
        items.forEach((item, idx) => {
          ticket += `${idx + 1}. ${item.item}\n`;
          ticket += `   ${item.reason}\n`;
          if (item.action) {
            ticket += `   Action Required: ${item.action}\n`;
          }
        });
      }
      ticket += `\n`;
    }

    if (requestData.issues.length > 0) {
      ticket += `\nISSUES TO RESOLVE (${requestData.issues.length}):\n`;
      ticket += `${'-'.repeat(70)}\n`;

      requestData.issues.forEach((issue, idx) => {
        ticket += `\n${idx + 1}. ${issue.field}\n`;
        ticket += `   Problem: ${issue.issue}\n`;
        if (issue.expected && issue.actual) {
          ticket += `   Expected: ${issue.expected}\n`;
          ticket += `   Actual: ${issue.actual}\n`;
        }
        if (issue.remediation) {
          ticket += `   Solution: ${issue.remediation}\n`;
        }
      });
      ticket += `\n`;
    }

    ticket += `\nACCEPTANCE CRITERIA:\n`;
    ticket += `${'-'.repeat(70)}\n`;
    ticket += `[ ] All required configuration items provided\n`;
    ticket += `[ ] All issues resolved\n`;
    ticket += `[ ] SAML authentication successful\n`;
    ticket += `[ ] User attributes correctly mapped\n`;
    ticket += `[ ] Logout flow working (if applicable)\n\n`;

    ticket += `PRIORITY: ${requestData.hasBlockers ? 'HIGH' : 'MEDIUM'}\n`;
    ticket += `CATEGORY: SAML Integration\n`;
    ticket += `COMPONENT: ${partnerType === 'IdP' ? 'Identity Provider' : 'Service Provider'}\n`;

    return ticket;
  }

  /**
   * Format as JSON
   */
  function formatAsJSON(requestData) {
    return JSON.stringify(requestData, null, 2);
  }

  /**
   * Format as markdown
   */
  function formatAsMarkdown(requestData) {
    let md = `# SAML Configuration Request\n\n`;
    md += `**Application:** ${requestData.application}  \n`;
    md += `**Generated:** ${new Date().toLocaleString()}  \n\n`;

    if (requestData.hasBlockers) {
      md += `## ⚠️ Status: Configuration Incomplete\n\n`;
      md += `- ${requestData.missingItems.length} missing configuration items\n`;
      md += `- ${requestData.issues.length} issues to resolve\n\n`;
    } else {
      md += `## ✅ Status: Configuration Complete\n\n`;
    }

    if (requestData.missingItems.length > 0) {
      md += `## Required Configuration\n\n`;

      const grouped = groupByCategory(requestData.missingItems);
      
      for (const [category, items] of Object.entries(grouped)) {
        md += `### ${category}\n\n`;
        items.forEach(item => {
          md += `#### ${item.item}\n\n`;
          md += `- **Reason:** ${item.reason}\n`;
          if (item.action) {
            md += `- **Action:** ${item.action}\n`;
          }
          if (item.alternatives && item.alternatives.length > 0) {
            md += `- **Alternatives:** ${item.alternatives.join(', ')}\n`;
          }
          md += `\n`;
        });
      }
    }

    if (requestData.issues.length > 0) {
      md += `## Issues to Resolve\n\n`;

      requestData.issues.forEach((issue, idx) => {
        md += `### ${idx + 1}. ${issue.field}\n\n`;
        md += `- **Issue:** ${issue.issue}\n`;
        if (issue.expected) {
          md += `- **Expected:** \`${issue.expected}\`\n`;
        }
        if (issue.actual) {
          md += `- **Current:** \`${issue.actual}\`\n`;
        }
        if (issue.remediation) {
          md += `- **Resolution:** ${issue.remediation}\n`;
        }
        if (issue.howToFix && issue.howToFix.length > 0) {
          md += `- **How to Fix:**\n`;
          issue.howToFix.forEach(fix => {
            md += `  - ${fix}\n`;
          });
        }
        md += `\n`;
      });
    }

    md += `## Next Steps\n\n`;
    md += `1. Review the requirements above\n`;
    md += `2. Provide the requested information/configuration\n`;
    md += `3. Validate the integration\n`;
    md += `4. Confirm successful setup\n\n`;

    md += `---\n`;
    md += `*Generated by SAML Tracer Intelligence*\n`;

    return md;
  }

  /**
   * Group items by category
   */
  function groupByCategory(items) {
    const grouped = {};
    items.forEach(item => {
      if (!grouped[item.category]) {
        grouped[item.category] = [];
      }
      grouped[item.category].push(item);
    });
    return grouped;
  }

  /**
   * Generate complete partner request package
   */
  function generatePackage(request, metadata, analysisResults, format = 'email') {
    const requestData = generateRequest(request, metadata, analysisResults);
    
    let formatted;
    switch (format) {
      case 'email':
        formatted = formatAsEmail(requestData);
        break;
      case 'ticket':
        formatted = formatAsTicket(requestData);
        break;
      case 'markdown':
        formatted = formatAsMarkdown(requestData);
        break;
      case 'json':
        formatted = formatAsJSON(requestData);
        break;
      default:
        formatted = formatAsEmail(requestData);
    }

    return {
      raw: requestData,
      formatted: formatted,
      format: format,
      copyable: true
    };
  }

  // Public API
  return {
    generateRequest,
    generatePackage,
    formatAsEmail,
    formatAsTicket,
    formatAsMarkdown,
    formatAsJSON
  };
})();
