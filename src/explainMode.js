/**
 * Explain Mode - Interactive SAML learning mode
 */

var ExplainMode = (function() {
  'use strict';

  let isActive = false;
  let tooltipElement = null;

  /**
   * Toggle explain mode
   */
  function toggle() {
    isActive = !isActive;
    
    if (isActive) {
      activate();
    } else {
      deactivate();
    }
    
    return isActive;
  }

  /**
   * Activate explain mode
   */
  function activate() {
    isActive = true;
    createTooltip();
    attachEventListeners();
    highlightExplainableElements();
  }

  /**
   * Deactivate explain mode
   */
  function deactivate() {
    isActive = false;
    removeTooltip();
    removeEventListeners();
    removeHighlights();
  }

  /**
   * Create tooltip element
   */
  function createTooltip() {
    if (tooltipElement) return;
    
    tooltipElement = document.createElement('div');
    tooltipElement.className = 'explain-tooltip';
    tooltipElement.style.cssText = `
      position: absolute;
      display: none;
      max-width: 400px;
      background: #2c3e50;
      color: white;
      padding: 15px;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      z-index: 10000;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 13px;
      line-height: 1.5;
      pointer-events: none;
    `;
    document.body.appendChild(tooltipElement);
  }

  /**
   * Remove tooltip element
   */
  function removeTooltip() {
    if (tooltipElement) {
      tooltipElement.remove();
      tooltipElement = null;
    }
  }

  /**
   * Attach event listeners to XML elements
   */
  function attachEventListeners() {
    const xmlContent = document.querySelector('#requestdump');
    if (!xmlContent) return;
    
    xmlContent.addEventListener('mouseover', handleMouseOver);
    xmlContent.addEventListener('mouseout', handleMouseOut);
    xmlContent.addEventListener('mousemove', handleMouseMove);
  }

  /**
   * Remove event listeners
   */
  function removeEventListeners() {
    const xmlContent = document.querySelector('#requestdump');
    if (!xmlContent) return;
    
    xmlContent.removeEventListener('mouseover', handleMouseOver);
    xmlContent.removeEventListener('mouseout', handleMouseOut);
    xmlContent.removeEventListener('mousemove', handleMouseMove);
  }

  /**
   * Highlight explainable elements
   */
  function highlightExplainableElements() {
    const xmlContent = document.querySelector('#requestdump');
    if (!xmlContent) return;
    
    // Find all XML tags
    const tags = xmlContent.querySelectorAll('.hljs-tag .hljs-name');
    tags.forEach(tag => {
      const explanation = SAMLEducation.getExplanation(tag.textContent);
      if (explanation) {
        tag.classList.add('explainable');
        tag.style.cursor = 'help';
        tag.style.textDecoration = 'underline';
        tag.style.textDecorationStyle = 'dotted';
      }
    });
  }

  /**
   * Remove highlights
   */
  function removeHighlights() {
    const tags = document.querySelectorAll('.explainable');
    tags.forEach(tag => {
      tag.classList.remove('explainable');
      tag.style.cursor = '';
      tag.style.textDecoration = '';
      tag.style.textDecorationStyle = '';
    });
  }

  /**
   * Handle mouseover on XML elements
   */
  function handleMouseOver(event) {
    if (!isActive) return;
    
    const target = event.target;
    
    // Check if hovering over an XML tag name
    if (target.classList.contains('hljs-name') && target.closest('.hljs-tag')) {
      const tagName = target.textContent;
      const explanation = SAMLEducation.getExplanation(tagName);
      
      if (explanation) {
        showTooltip(explanation);
      }
    }
    
    // Check for attribute names
    if (target.classList.contains('hljs-attr')) {
      const attrName = target.textContent;
      const explanation = SAMLEducation.getExplanation(attrName);
      
      if (explanation) {
        showTooltip(explanation);
      }
    }
  }

  /**
   * Handle mouseout
   */
  function handleMouseOut(event) {
    if (!isActive) return;
    
    const target = event.target;
    if (target.classList.contains('hljs-name') || target.classList.contains('hljs-attr')) {
      hideTooltip();
    }
  }

  /**
   * Handle mouse move
   */
  function handleMouseMove(event) {
    if (!isActive || !tooltipElement) return;
    
    if (tooltipElement.style.display === 'block') {
      positionTooltip(event.clientX, event.clientY);
    }
  }

  /**
   * Show tooltip with explanation
   */
  function showTooltip(explanation) {
    if (!tooltipElement) return;
    
    let html = `<div class="tooltip-header">${explanation.title}</div>`;
    html += `<div class="tooltip-content">`;
    html += `<p><strong>Description:</strong> ${explanation.description}</p>`;
    
    if (explanation.purpose) {
      html += `<p><strong>Purpose:</strong> ${explanation.purpose}</p>`;
    }
    
    if (explanation.example) {
      html += `<p><strong>Example:</strong> <code>${explanation.example}</code></p>`;
    }
    
    if (explanation.required !== undefined) {
      html += `<p><strong>Required:</strong> ${explanation.required ? 'Yes' : 'No'}</p>`;
    }
    
    if (explanation.learnMore) {
      if (explanation.learnMore.startsWith('http')) {
        html += `<p><a href="${explanation.learnMore}" target="_blank" style="color: #3498db;">Learn More →</a></p>`;
      } else {
        html += `<p><em>${explanation.learnMore}</em></p>`;
      }
    }
    
    html += `</div>`;
    
    tooltipElement.innerHTML = html;
    tooltipElement.style.display = 'block';
  }

  /**
   * Hide tooltip
   */
  function hideTooltip() {
    if (tooltipElement) {
      tooltipElement.style.display = 'none';
    }
  }

  /**
   * Position tooltip near cursor
   */
  function positionTooltip(x, y) {
    if (!tooltipElement) return;
    
    const offset = 20;
    let left = x + offset;
    let top = y + offset;
    
    // Adjust if tooltip would go off screen
    const rect = tooltipElement.getBoundingClientRect();
    if (left + rect.width > window.innerWidth) {
      left = x - rect.width - offset;
    }
    if (top + rect.height > window.innerHeight) {
      top = y - rect.height - offset;
    }
    
    tooltipElement.style.left = left + 'px';
    tooltipElement.style.top = top + 'px';
  }

  /**
   * Show glossary of all SAML elements
   */
  function showGlossary() {
    const allExplanations = SAMLEducation.getAllExplanations();
    const errorCodes = SAMLEducation.getAllErrorCodes();
    
    let html = '<div class="saml-glossary">';
    html += '<h2>📚 SAML Element Glossary</h2>';
    
    // Group by category
    const categories = {
      'Protocol Elements': ['samlp:AuthnRequest', 'samlp:Response', 'saml:Assertion', 'samlp:LogoutRequest'],
      'Identity & Subject': ['saml:Issuer', 'saml:Subject', 'saml:NameID', 'saml:SubjectConfirmation'],
      'Timing & Conditions': ['saml:Conditions', 'NotBefore', 'NotOnOrAfter', 'saml:AudienceRestriction', 'saml:Audience'],
      'Authentication': ['saml:AuthnStatement', 'saml:AuthnContext', 'saml:AuthnContextClassRef', 'SessionIndex'],
      'Attributes': ['saml:AttributeStatement', 'saml:Attribute', 'saml:AttributeValue'],
      'Security': ['ds:Signature', 'ds:SignatureMethod', 'ds:DigestMethod', 'ds:X509Certificate'],
      'Status': ['samlp:Status', 'samlp:StatusCode', 'samlp:StatusMessage']
    };
    
    for (const [category, elements] of Object.entries(categories)) {
      html += `<div class="glossary-category">`;
      html += `<h3>${category}</h3>`;
      
      elements.forEach(elementName => {
        const explanation = allExplanations[elementName];
        if (explanation) {
          html += `<div class="glossary-item">`;
          html += `<h4><code>${elementName}</code> - ${explanation.title}</h4>`;
          html += `<p>${explanation.description}</p>`;
          if (explanation.purpose) {
            html += `<p><strong>Purpose:</strong> ${explanation.purpose}</p>`;
          }
          html += `</div>`;
        }
      });
      
      html += `</div>`;
    }
    
    // Error codes
    html += `<div class="glossary-category">`;
    html += `<h3>Status Codes</h3>`;
    
    for (const [code, info] of Object.entries(errorCodes)) {
      html += `<div class="glossary-item ${info.severity}">`;
      html += `<h4><code>${code.split(':').pop()}</code></h4>`;
      html += `<p><strong>${info.description}:</strong> ${info.meaning}</p>`;
      html += `</div>`;
    }
    
    html += `</div>`;
    html += '</div>';
    
    // Create modal
    const modal = document.createElement('div');
    modal.className = 'glossary-modal';
    modal.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0,0,0,0.7);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 10001;
      padding: 20px;
    `;
    
    const content = document.createElement('div');
    content.style.cssText = `
      background: white;
      border-radius: 12px;
      max-width: 900px;
      max-height: 90vh;
      overflow-y: auto;
      padding: 30px;
      box-shadow: 0 10px 40px rgba(0,0,0,0.3);
    `;
    content.innerHTML = html;
    
    const closeBtn = document.createElement('button');
    closeBtn.textContent = '× Close';
    closeBtn.style.cssText = `
      position: sticky;
      top: 0;
      float: right;
      padding: 8px 16px;
      background: #e74c3c;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 14px;
      margin-bottom: 10px;
    `;
    closeBtn.onclick = () => modal.remove();
    
    content.insertBefore(closeBtn, content.firstChild);
    modal.appendChild(content);
    document.body.appendChild(modal);
    
    // Close on background click
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        modal.remove();
      }
    });
  }

  /**
   * Get current state
   */
  function isEnabled() {
    return isActive;
  }

  // Public API
  return {
    toggle,
    activate,
    deactivate,
    showGlossary,
    isEnabled
  };
})();

// Add CSS for glossary
const glossaryStyle = document.createElement('style');
glossaryStyle.textContent = `
  .saml-glossary h2 {
    margin: 0 0 30px 0;
    color: #2c3e50;
    font-size: 24px;
  }
  
  .glossary-category {
    margin-bottom: 30px;
  }
  
  .glossary-category h3 {
    margin: 0 0 15px 0;
    padding: 10px;
    background: #3498db;
    color: white;
    border-radius: 4px;
    font-size: 18px;
  }
  
  .glossary-item {
    margin-bottom: 20px;
    padding: 15px;
    background: #f8f9fa;
    border-left: 4px solid #3498db;
    border-radius: 4px;
  }
  
  .glossary-item.success {
    border-color: #27ae60;
    background: #e8f8f5;
  }
  
  .glossary-item.error {
    border-color: #e74c3c;
    background: #fadbd8;
  }
  
  .glossary-item.warning {
    border-color: #f39c12;
    background: #fef5e7;
  }
  
  .glossary-item h4 {
    margin: 0 0 10px 0;
    color: #2c3e50;
    font-size: 16px;
  }
  
  .glossary-item code {
    background: #34495e;
    color: #ecf0f1;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: monospace;
  }
  
  .glossary-item p {
    margin: 8px 0;
    color: #555;
    line-height: 1.6;
  }
  
  .tooltip-header {
    font-weight: bold;
    font-size: 15px;
    margin-bottom: 10px;
    padding-bottom: 8px;
    border-bottom: 1px solid rgba(255,255,255,0.3);
  }
  
  .tooltip-content p {
    margin: 8px 0;
  }
  
  .tooltip-content code {
    background: rgba(255,255,255,0.2);
    padding: 2px 6px;
    border-radius: 3px;
    font-family: monospace;
  }
  
  .tooltip-content a {
    color: #3498db;
    text-decoration: none;
  }
  
  .tooltip-content a:hover {
    text-decoration: underline;
  }
`;
document.head.appendChild(glossaryStyle);
