/**
 * Analysis Tab - Displays SAML intelligence and validation results
 */

var AnalysisTab = (function() {
  'use strict';

  /**
   * Generate analysis tab content for a request
   */
  async function generateAnalysisContent(request) {
    if (!request.saml) {
      return '<div class="analysis-empty">No SAML message to analyze</div>';
    }

    let html = '<div class="analysis-container">';

    // Run all analyses
    const comparisonResults = await ComparisonEngine.compareRequest(request);
    const securityResults = SecurityValidator.validateSecurity(request);
    const diagnosticResults = DiagnosticRules.diagnose(request, comparisonResults, securityResults);
    
    // Run Phase 3 analyses
    const attributeResults = AttributeMapper.analyzeAttributes(request);
    const checklistResults = OnboardingChecklist.generateChecklist(request, comparisonResults, securityResults);
    
    // Prepare all results for partner request generator
    const allResults = {
      comparison: comparisonResults,
      security: securityResults,
      diagnostics: diagnosticResults,
      attributes: attributeResults,
      checklist: checklistResults
    };

    // Summary Card
    html += generateSummaryCard(comparisonResults, securityResults, diagnosticResults);

    // Security Score
    if (securityResults.securityScore !== undefined) {
      html += generateSecurityScoreCard(securityResults);
    }

    // Onboarding Readiness Checklist
    if (checklistResults) {
      html += generateChecklistSection(checklistResults);
    }

    // Attribute Mapping
    if (attributeResults && attributeResults.attributes.length > 0) {
      html += generateAttributeMappingSection(attributeResults);
    }

    // Comparison Results
    if (comparisonResults.applicable) {
      html += generateComparisonSection(comparisonResults);
    } else {
      html += generateNoMetadataPrompt();
    }

    // Diagnostic Issues
    if (diagnosticResults.issues.length > 0) {
      html += generateDiagnosticsSection(diagnosticResults);
    }

    // Security Checks
    if (securityResults.checks.length > 0) {
      html += generateSecuritySection(securityResults);
    }

    // Recommendations
    if (diagnosticResults.recommendations.length > 0) {
      html += generateRecommendationsSection(diagnosticResults);
    }

    // Partner Request Generator
    html += generatePartnerRequestSection(request, comparisonResults.metadata, allResults);

    html += '</div>';

    return html;
  }

  /**
   * Generate summary card
   */
  function generateSummaryCard(comparisonResults, securityResults, diagnosticResults) {
    const totalErrors = (comparisonResults.summary?.errors || 0) + 
                       (securityResults.summary?.critical || 0) + 
                       (securityResults.summary?.high || 0);
    
    const totalWarnings = (comparisonResults.summary?.warnings || 0) + 
                         (securityResults.summary?.medium || 0);

    const status = totalErrors > 0 ? 'error' : (totalWarnings > 0 ? 'warning' : 'success');
    const statusText = totalErrors > 0 ? 'Issues Found' : (totalWarnings > 0 ? 'Warnings Found' : 'Looks Good');
    const statusIcon = totalErrors > 0 ? '❌' : (totalWarnings > 0 ? '⚠️' : '✅');

    let html = `
      <div class="analysis-summary ${status}">
        <div class="summary-icon">${statusIcon}</div>
        <div class="summary-content">
          <h3>${statusText}</h3>
          <div class="summary-stats">
            ${totalErrors > 0 ? `<span class="stat-error">${totalErrors} Errors</span>` : ''}
            ${totalWarnings > 0 ? `<span class="stat-warning">${totalWarnings} Warnings</span>` : ''}
            ${totalErrors === 0 && totalWarnings === 0 ? '<span class="stat-success">No issues detected</span>' : ''}
          </div>
        </div>
      </div>
    `;

    return html;
  }

  /**
   * Generate security score card
   */
  function generateSecurityScoreCard(securityResults) {
    const score = securityResults.securityScore;
    const grade = securityResults.grade;
    const color = securityResults.gradeColor;

    return `
      <div class="security-score-card">
        <div class="score-header">
          <h3>Security Score</h3>
        </div>
        <div class="score-content">
          <div class="score-circle" style="border-color: ${color}">
            <div class="score-value" style="color: ${color}">${Math.round(score)}</div>
            <div class="score-grade" style="color: ${color}">${grade}</div>
          </div>
          <div class="score-breakdown">
            <div class="score-item">
              <span class="score-label">Critical:</span>
              <span class="score-count critical">${securityResults.summary.critical}</span>
            </div>
            <div class="score-item">
              <span class="score-label">High:</span>
              <span class="score-count high">${securityResults.summary.high}</span>
            </div>
            <div class="score-item">
              <span class="score-label">Medium:</span>
              <span class="score-count medium">${securityResults.summary.medium}</span>
            </div>
            <div class="score-item">
              <span class="score-label">Low:</span>
              <span class="score-count low">${securityResults.summary.low}</span>
            </div>
            <div class="score-item">
              <span class="score-label">Passed:</span>
              <span class="score-count passed">${securityResults.summary.passed}</span>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  /**
   * Generate comparison section
   */
  function generateComparisonSection(comparisonResults) {
    let html = '<div class="analysis-section"><h3>📋 Metadata Comparison</h3>';

    if (comparisonResults.comparisons.length === 0) {
      html += '<p class="section-note">No comparison checks performed</p>';
    } else {
      html += '<div class="comparison-list">';
      
      comparisonResults.comparisons.forEach(comparison => {
        const icon = getSeverityIcon(comparison.severity);
        const severityClass = comparison.severity;
        
        html += `
          <div class="comparison-item ${severityClass}">
            <div class="comparison-icon">${icon}</div>
            <div class="comparison-content">
              <div class="comparison-header">
                <strong>${comparison.field}</strong>
                <span class="comparison-severity">${comparison.severity}</span>
              </div>
              <div class="comparison-message">${escapeHtml(comparison.message)}</div>
              ${comparison.expected ? `<div class="comparison-detail"><strong>Expected:</strong> ${escapeHtml(comparison.expected)}</div>` : ''}
              ${comparison.actual ? `<div class="comparison-detail"><strong>Actual:</strong> ${escapeHtml(comparison.actual)}</div>` : ''}
              ${comparison.remediation ? `<div class="comparison-remediation">💡 ${escapeHtml(comparison.remediation)}</div>` : ''}
            </div>
          </div>
        `;
      });
      
      html += '</div>';
    }

    html += '</div>';
    return html;
  }

  /**
   * Generate security section
   */
  function generateSecuritySection(securityResults) {
    let html = '<div class="analysis-section"><h3>🔒 Security Validation</h3>';

    html += '<div class="security-checks">';
    
    securityResults.checks.forEach(check => {
      const severityClass = check.severity;
      
      html += `
        <div class="security-check ${severityClass}">
          <div class="check-icon">${check.icon}</div>
          <div class="check-content">
            <div class="check-title">${escapeHtml(check.title)}</div>
            <div class="check-message">${escapeHtml(check.message)}</div>
            ${check.remediation ? `<div class="check-remediation">💡 ${escapeHtml(check.remediation)}</div>` : ''}
          </div>
        </div>
      `;
    });

    html += '</div></div>';
    return html;
  }

  /**
   * Generate diagnostics section
   */
  function generateDiagnosticsSection(diagnosticResults) {
    let html = '<div class="analysis-section"><h3>🔍 Diagnostic Analysis</h3>';

    html += '<div class="diagnostic-issues">';
    
    diagnosticResults.issues.forEach(issue => {
      const severityClass = issue.severity;
      const icon = getSeverityIcon(issue.severity);
      
      html += `
        <div class="diagnostic-issue ${severityClass}">
          <div class="issue-header">
            <span class="issue-icon">${icon}</span>
            <span class="issue-title">${escapeHtml(issue.title)}</span>
            <span class="issue-severity">${issue.severity}</span>
          </div>
          <div class="issue-description">${escapeHtml(issue.description)}</div>
          
          ${issue.whatIsWrong ? `
            <div class="issue-section">
              <strong>What's Wrong:</strong>
              <pre class="issue-detail">${escapeHtml(issue.whatIsWrong)}</pre>
            </div>
          ` : ''}
          
          ${issue.whyItMatters ? `
            <div class="issue-section">
              <strong>Why It Matters:</strong>
              <div>${escapeHtml(issue.whyItMatters)}</div>
            </div>
          ` : ''}
          
          ${issue.howToFix && issue.howToFix.length > 0 ? `
            <div class="issue-section">
              <strong>How To Fix:</strong>
              <ul class="fix-list">
                ${issue.howToFix.map(fix => `<li>${escapeHtml(fix)}</li>`).join('')}
              </ul>
            </div>
          ` : ''}
          
          ${issue.whereToFix ? `
            <div class="issue-section">
              <strong>Where To Fix:</strong> <span class="where-to-fix">${escapeHtml(issue.whereToFix)}</span>
            </div>
          ` : ''}
        </div>
      `;
    });

    html += '</div></div>';
    return html;
  }

  /**
   * Generate recommendations section
   */
  function generateRecommendationsSection(diagnosticResults) {
    let html = '<div class="analysis-section"><h3>💡 Recommendations</h3>';

    html += '<div class="recommendations-list">';
    
    diagnosticResults.recommendations.forEach(rec => {
      const priorityClass = rec.priority;
      
      html += `
        <div class="recommendation-item ${priorityClass}">
          <div class="rec-header">
            <strong>${escapeHtml(rec.recommendation)}</strong>
            <span class="rec-priority">${rec.priority} priority</span>
          </div>
          <div class="rec-details">${escapeHtml(rec.details)}</div>
          <div class="rec-category">${rec.category}</div>
        </div>
      `;
    });

    html += '</div></div>';
    return html;
  }

  /**
   * Generate prompt when no metadata available
   */
  function generateNoMetadataPrompt() {
    return `
      <div class="analysis-section no-metadata-prompt">
        <div class="prompt-icon">📋</div>
        <h3>No Metadata Available</h3>
        <p>Upload SP or IdP metadata to enable intelligent comparison and validation.</p>
        <button class="btn-open-metadata" onclick="document.getElementById('button-metadata').click()">
          Upload Metadata
        </button>
      </div>
    `;
  }

  /**
   * Get severity icon
   */
  function getSeverityIcon(severity) {
    const icons = {
      'error': '❌',
      'critical': '❌',
      'high': '❌',
      'warning': '⚠️',
      'medium': '⚠️',
      'low': 'ℹ️',
      'info': 'ℹ️',
      'success': '✅',
      'passed': '✅'
    };
    return icons[severity] || 'ℹ️';
  }

  /**
   * Escape HTML to prevent XSS
   */
  function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  /**
   * Generate onboarding checklist section
   */
  function generateChecklistSection(checklistResults) {
    const { readinessScore, status, items, summary } = checklistResults;
    
    const statusColors = {
      'ready': '#10b981',
      'almost-ready': '#3b82f6',
      'not-ready': '#f59e0b',
      'blocked': '#ef4444'
    };
    
    const statusLabels = {
      'ready': '✅ Ready for Production',
      'almost-ready': '🔄 Almost Ready',
      'not-ready': '⚠️ Not Ready',
      'blocked': '❌ Blocked'
    };

    let html = `
      <div class="analysis-section checklist-section">
        <div class="section-header">
          <h3>🎯 Onboarding Readiness Checklist</h3>
          <div class="readiness-score" style="background-color: ${statusColors[status]}">
            ${readinessScore}%
          </div>
        </div>
        <div class="section-content">
          <div class="readiness-status" style="border-color: ${statusColors[status]}">
            <strong>${statusLabels[status]}</strong>
          </div>

          <div class="checklist-summary">
            <div class="summary-item">
              <span class="summary-label">Completed:</span>
              <span class="summary-value">${summary.completed}</span>
            </div>
            <div class="summary-item">
              <span class="summary-label">Warnings:</span>
              <span class="summary-value">${summary.warnings}</span>
            </div>
            <div class="summary-item">
              <span class="summary-label">Blockers:</span>
              <span class="summary-value">${summary.blockers}</span>
            </div>
          </div>

          <div class="checklist-items">
    `;

    // Group by category
    const grouped = {};
    items.forEach(item => {
      if (!grouped[item.category]) {
        grouped[item.category] = [];
      }
      grouped[item.category].push(item);
    });

    for (const [category, categoryItems] of Object.entries(grouped)) {
      html += `<div class="checklist-category"><h4>${category}</h4>`;
      
      categoryItems.forEach(item => {
        const icon = item.status === 'completed' ? '✅' : 
                    item.status === 'blocked' ? '❌' : 
                    item.status === 'warning' ? '⚠️' : '⭕';
        
        html += `
          <div class="checklist-item ${item.status}">
            <div class="item-header">
              <span class="item-icon">${icon}</span>
              <span class="item-title">${escapeHtml(item.item)}</span>
            </div>
            ${item.message ? `<div class="item-message">${escapeHtml(item.message)}</div>` : ''}
            ${item.action ? `<div class="item-action"><strong>Action:</strong> ${escapeHtml(item.action)}</div>` : ''}
          </div>
        `;
      });
      
      html += '</div>';
    }

    html += '</div></div></div>';
    return html;
  }

  /**
   * Generate attribute mapping section
   */
  function generateAttributeMappingSection(attributeResults) {
    const { attributes, identityAttribute, issues, suggestions } = attributeResults;
    
    let html = `
      <div class="analysis-section attribute-section">
        <div class="section-header">
          <h3>🏷️ Attribute Mapping Analysis</h3>
          <button class="btn-export" onclick="exportAttributeMapping()">Export Mapping</button>
        </div>
        <div class="section-content">
    `;

    if (identityAttribute) {
      html += `
        <div class="identity-attribute">
          <strong>Identity Attribute:</strong> ${escapeHtml(identityAttribute.name)}
          ${identityAttribute.value ? ` = <code>${escapeHtml(identityAttribute.value)}</code>` : ''}
        </div>
      `;
    }

    if (issues.length > 0) {
      html += '<div class="attribute-issues"><h4>Issues</h4>';
      issues.forEach(issue => {
        html += `
          <div class="attribute-issue ${issue.severity}">
            ${getSeverityIcon(issue.severity)}
            <strong>${issue.type}:</strong> ${escapeHtml(issue.message)}
            ${issue.alternatives ? `<div class="alternatives">Consider: ${issue.alternatives.join(', ')}</div>` : ''}
          </div>
        `;
      });
      html += '</div>';
    }

    if (suggestions.length > 0) {
      html += '<div class="mapping-suggestions"><h4>Suggested Mappings</h4>';
      html += '<table class="mapping-table">';
      html += '<tr><th>SAML Attribute</th><th>Standard Field</th><th>Confidence</th></tr>';
      
      suggestions.forEach(suggestion => {
        html += `
          <tr>
            <td><code>${escapeHtml(suggestion.samlAttribute)}</code></td>
            <td>${escapeHtml(suggestion.standardField)}</td>
            <td class="confidence-${suggestion.confidence}">${suggestion.confidence}</td>
          </tr>
        `;
      });
      
      html += '</table></div>';
    }

    html += '</div></div>';

    // Store attribute results for export
    html += `<script>window._attributeResults = ${JSON.stringify(attributeResults)};</script>`;

    return html;
  }

  /**
   * Generate partner request section
   */
  function generatePartnerRequestSection(request, metadata, allResults) {
    let html = `
      <div class="analysis-section partner-request-section">
        <div class="section-header">
          <h3>📧 Partner Request Generator</h3>
          <select id="partner-format-select" class="format-select">
            <option value="email">Email</option>
            <option value="ticket">Ticket</option>
            <option value="markdown">Markdown</option>
            <option value="json">JSON</option>
          </select>
        </div>
        <div class="section-content">
          <p class="section-description">
            Generate ready-to-send communication for your partner (IdP or SP) based on 
            missing configuration and detected issues.
          </p>
          <button class="btn-generate" onclick="generatePartnerRequest()">
            Generate Partner Request
          </button>
          <div id="partner-request-output" class="partner-request-output"></div>
        </div>
      </div>
    `;

    // Store data for partner request generation
    html += `<script>
      window._partnerRequestData = {
        request: ${JSON.stringify(request.saml)},
        metadata: ${JSON.stringify(metadata)},
        results: ${JSON.stringify(allResults)}
      };
    </script>`;

    return html;
  }

  // Public API
  return {
    generateAnalysisContent
  };
})();

// Global helper functions for UI interactions
function exportAttributeMapping() {
  if (!window._attributeResults) return;
  
  const format = prompt('Export format (json/yaml/text):', 'json');
  if (!format) return;
  
  const config = AttributeMapper.generateMappingConfig(
    window._attributeResults.suggestions,
    format
  );
  
  // Copy to clipboard
  navigator.clipboard.writeText(config).then(() => {
    alert('Attribute mapping copied to clipboard!');
  });
}

function generatePartnerRequest() {
  if (!window._partnerRequestData) return;
  
  const format = document.getElementById('partner-format-select').value;
  const { request, metadata, results } = window._partnerRequestData;
  
  const package = PartnerRequestGenerator.generatePackage(
    { saml: request },
    metadata,
    results,
    format
  );
  
  const output = document.getElementById('partner-request-output');
  output.innerHTML = `
    <div class="request-preview">
      <div class="preview-header">
        <strong>Generated ${format.toUpperCase()}</strong>
        <button onclick="copyPartnerRequest()">Copy to Clipboard</button>
      </div>
      <pre class="request-content">${escapeHtmlGlobal(package.formatted)}</pre>
    </div>
  `;
  
  window._currentPartnerRequest = package.formatted;
}

function copyPartnerRequest() {
  if (!window._currentPartnerRequest) return;
  
  navigator.clipboard.writeText(window._currentPartnerRequest).then(() => {
    alert('Partner request copied to clipboard!');
  });
}

function escapeHtmlGlobal(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
