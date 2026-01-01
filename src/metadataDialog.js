/**
 * Metadata Dialog UI Controller
 */

var ui = {
  currentMetadata: null,

  init: function() {
    this.bindTabs();
    this.bindUploadTab();
    this.bindManualTab();
    this.bindStoredTab();
    this.loadStoredMetadata();
  },

  bindTabs: function() {
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
      tab.addEventListener('click', (e) => {
        const targetTab = e.target.dataset.tab;
        
        // Update active tab
        tabs.forEach(t => t.classList.remove('active'));
        e.target.classList.add('active');
        
        // Show corresponding content
        document.querySelectorAll('.tab-content').forEach(content => {
          content.classList.remove('active');
        });
        document.getElementById(targetTab + '-tab').classList.add('active');

        // Refresh stored list when switching to that tab
        if (targetTab === 'stored') {
          this.loadStoredMetadata();
        }
      });
    });
  },

  bindUploadTab: function() {
    // File upload handler
    document.getElementById('metadataFile').addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = (event) => {
          document.getElementById('metadataXml').value = event.target.result;
        };
        reader.readAsText(file);
      }
    });

    // Parse button
    document.getElementById('btnParseMetadata').addEventListener('click', () => {
      this.parseMetadata();
    });

    // Save button
    document.getElementById('btnSaveMetadata').addEventListener('click', () => {
      this.saveMetadata();
    });

    // Clear button
    document.getElementById('btnClearForm').addEventListener('click', () => {
      this.clearUploadForm();
    });
  },

  bindManualTab: function() {
    document.getElementById('btnSaveManual').addEventListener('click', () => {
      this.saveManualBaseline();
    });

    document.getElementById('btnClearManual').addEventListener('click', () => {
      this.clearManualForm();
    });
  },

  bindStoredTab: function() {
    document.getElementById('btnRefreshList').addEventListener('click', () => {
      this.loadStoredMetadata();
    });

    document.getElementById('btnClearAll').addEventListener('click', () => {
      if (confirm('Are you sure you want to delete all stored metadata? This cannot be undone.')) {
        this.clearAllMetadata();
      }
    });
  },

  parseMetadata: function() {
    const xmlString = document.getElementById('metadataXml').value.trim();
    
    if (!xmlString) {
      this.showStatus('Please provide metadata XML', 'error');
      return;
    }

    try {
      this.currentMetadata = MetadataManager.parseMetadata(xmlString);
      this.showValidationResults(this.currentMetadata);
      document.getElementById('btnSaveMetadata').style.display = 'inline-block';
      
      // Auto-fill domain if empty
      if (!document.getElementById('metadataDomain').value && this.currentMetadata.entityId) {
        const domain = MetadataManager.extractDomain(this.currentMetadata.entityId);
        document.getElementById('metadataDomain').value = domain;
      }

      this.showStatus('Metadata parsed successfully!', 'success');
    } catch (error) {
      this.showStatus('Error parsing metadata: ' + error.message, 'error');
      console.error('Parse error:', error);
    }
  },

  saveMetadata: async function() {
    if (!this.currentMetadata) {
      this.showStatus('Please parse metadata first', 'error');
      return;
    }

    let domain = document.getElementById('metadataDomain').value.trim();
    if (!domain) {
      domain = this.currentMetadata.entityId;
    }

    const success = await StorageManager.saveMetadata(domain, this.currentMetadata);
    
    if (success) {
      this.showStatus('Metadata saved successfully!', 'success');
      this.clearUploadForm();
      setTimeout(() => {
        // Switch to stored tab
        document.querySelector('.tab[data-tab="stored"]').click();
      }, 1000);
    } else {
      this.showStatus('Error saving metadata', 'error');
    }
  },

  saveManualBaseline: async function() {
    const entityId = document.getElementById('manualEntityId').value.trim();
    const type = document.getElementById('manualType').value;
    
    if (!entityId) {
      this.showStatus('Entity ID is required', 'error');
      return;
    }

    const acsUrlsText = document.getElementById('manualAcsUrls').value.trim();
    const acsUrls = acsUrlsText ? acsUrlsText.split('\n').map(u => u.trim()).filter(u => u) : [];

    const logoutUrlsText = document.getElementById('manualLogoutUrls').value.trim();
    const logoutUrls = logoutUrlsText ? logoutUrlsText.split('\n').map(u => u.trim()).filter(u => u) : [];

    const nameIdFormatsText = document.getElementById('manualNameIdFormats').value.trim();
    const nameIdFormats = nameIdFormatsText ? nameIdFormatsText.split('\n').map(f => f.trim()).filter(f => f) : [];

    const config = {
      type: type,
      entityId: entityId,
      acsUrls: acsUrls,
      logoutUrls: logoutUrls,
      nameIdFormats: nameIdFormats
    };

    try {
      const baseline = MetadataManager.createManualBaseline(config);
      const domain = MetadataManager.extractDomain(entityId);
      
      const success = await StorageManager.saveMetadata(domain, baseline);
      
      if (success) {
        this.showStatus('Baseline saved successfully!', 'success');
        this.clearManualForm();
        setTimeout(() => {
          document.querySelector('.tab[data-tab="stored"]').click();
        }, 1000);
      } else {
        this.showStatus('Error saving baseline', 'error');
      }
    } catch (error) {
      this.showStatus('Error creating baseline: ' + error.message, 'error');
    }
  },

  loadStoredMetadata: async function() {
    const allMetadata = await StorageManager.getAllMetadata();
    const container = document.getElementById('storedMetadataList');
    
    if (Object.keys(allMetadata).length === 0) {
      container.innerHTML = '<div class="empty-state">No metadata stored yet. Upload metadata to get started.</div>';
      return;
    }

    let html = '<div class="stored-metadata">';
    
    for (const domain in allMetadata) {
      const metadata = allMetadata[domain];
      const date = new Date(metadata.lastUpdated).toLocaleString();
      const isManual = metadata.manualEntry ? ' (Manual)' : '';
      
      html += `
        <div class="metadata-item">
          <div class="metadata-info">
            <div>
              <span class="metadata-type">${metadata.type}</span>
              <span class="metadata-domain">${domain}${isManual}</span>
            </div>
            <div class="metadata-entity">Entity ID: ${metadata.entityId}</div>
            <div class="metadata-date">Last updated: ${date}</div>
          </div>
          <div class="metadata-actions">
            <button class="btn btn-secondary btn-small" onclick="ui.viewMetadata('${domain}')">View</button>
            <button class="btn btn-danger btn-small" onclick="ui.deleteMetadata('${domain}')">Delete</button>
          </div>
        </div>
      `;
    }
    
    html += '</div>';
    container.innerHTML = html;
  },

  viewMetadata: async function(domain) {
    const metadata = await StorageManager.getMetadata(domain);
    if (!metadata) {
      alert('Metadata not found');
      return;
    }

    // Switch to upload tab and populate
    document.querySelector('.tab[data-tab="upload"]').click();
    document.getElementById('metadataXml').value = metadata.rawXml || 'Manual entry - no XML available';
    document.getElementById('metadataDomain').value = domain;
    
    this.currentMetadata = metadata;
    this.showValidationResults(metadata);
  },

  deleteMetadata: async function(domain) {
    if (!confirm(`Delete metadata for ${domain}?`)) {
      return;
    }

    const success = await StorageManager.deleteMetadata(domain);
    if (success) {
      this.showStatus('Metadata deleted', 'success');
      this.loadStoredMetadata();
    } else {
      this.showStatus('Error deleting metadata', 'error');
    }
  },

  clearAllMetadata: async function() {
    const success = await StorageManager.clearAllMetadata();
    if (success) {
      this.showStatus('All metadata cleared', 'success');
      this.loadStoredMetadata();
    } else {
      this.showStatus('Error clearing metadata', 'error');
    }
  },

  showValidationResults: function(metadata) {
    const container = document.getElementById('validationResults');
    const content = document.getElementById('validationContent');
    
    if (!metadata.validation) {
      container.style.display = 'none';
      return;
    }

    container.style.display = 'block';
    
    let html = '';
    
    if (metadata.validation.isValid) {
      html += '<div class="validation-item success">✓ Metadata is valid and complete</div>';
    }

    metadata.validation.allIssues.forEach(issue => {
      html += `
        <div class="validation-item ${issue.severity}">
          <strong>${issue.field}:</strong> ${issue.message}
        </div>
      `;
    });

    // Show summary
    const summary = metadata.validation;
    html += `
      <div style="margin-top: 15px; padding: 10px; background: #f0f0f0; border-radius: 4px;">
        <strong>Summary:</strong> 
        ${summary.errors.length} errors, 
        ${summary.warnings.length} warnings, 
        ${summary.info.length} info
      </div>
    `;

    content.innerHTML = html;
  },

  showStatus: function(message, type) {
    const statusEl = document.getElementById('statusMessage');
    statusEl.textContent = message;
    statusEl.className = 'status-message ' + type;
    statusEl.style.display = 'block';

    setTimeout(() => {
      statusEl.style.display = 'none';
    }, 5000);
  },

  clearUploadForm: function() {
    document.getElementById('metadataFile').value = '';
    document.getElementById('metadataXml').value = '';
    document.getElementById('metadataDomain').value = '';
    document.getElementById('validationResults').style.display = 'none';
    document.getElementById('btnSaveMetadata').style.display = 'none';
    this.currentMetadata = null;
  },

  clearManualForm: function() {
    document.getElementById('manualEntityId').value = '';
    document.getElementById('manualType').value = 'SP';
    document.getElementById('manualAcsUrls').value = '';
    document.getElementById('manualLogoutUrls').value = '';
    document.getElementById('manualNameIdFormats').value = '';
  }
};

// Initialize when DOM is loaded
window.addEventListener('load', () => {
  ui.init();
});
