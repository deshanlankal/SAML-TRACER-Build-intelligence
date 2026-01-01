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

    // Summary Card
    html += generateSummaryCard(comparisonResults, securityResults, diagnosticResults);

    // Security Score
    if (securityResults.securityScore !== undefined) {
      html += generateSecurityScoreCard(securityResults);
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

  // Public API
  return {
    generateAnalysisContent
  };
})();
