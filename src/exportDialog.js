window.top.addEventListener("load", e => {
  ui.bindButtons();
}, true);

ui = {
  requests: null,
  exportResult: null,

  bindButtons: () => {
    // bind radio buttons and checkboxes
    let radioButtons = document.querySelectorAll('input[type="radio"]');
    Array.from(radioButtons).map(rb => rb.onchange = e => ui.createExportResult());
    
    let checkboxes = document.querySelectorAll('input[type="checkbox"]');
    Array.from(checkboxes).map(cb => cb.onchange = e => ui.createExportResult());

    // bind export button
    document.getElementById("button-export").addEventListener("click", async e => {
      e.preventDefault();
      
      let io = new SAMLTraceIO();
      const format = document.querySelector('input[name="export-format"]:checked').value;
      
      let content, mimeType, fileExtension;
      
      if (format === 'text') {
        content = io.exportAsTextReport(ui.exportResult);
        mimeType = 'text/plain';
        fileExtension = 'txt';
      } else {
        content = io.serialize(ui.exportResult);
        mimeType = 'application/json';
        fileExtension = 'json';
      }
      
      let encodedExportResult = encodeURIComponent(content);
      e.target.href = `data:${mimeType};charset=utf-8,` + encodedExportResult;
      
      const timestamp = ui.exportResult.timestamp || new Date().toISOString();
      e.target.download = `SAML-tracer-export-${timestamp}.${fileExtension}`;

      // hide dialog after export
      window.parent.ui.hideDialogs();
    }, true);
  },

  setupContent: (httpRequests, hideResources, showProtocolRequestsOnly) => {
    // remember the currently captured (and filtered) requests
    filteredRequests = httpRequests?.filter(req => req.isVisible && req.isVisible(hideResources, showProtocolRequestsOnly)).map(req => req.parsed);
    ui.requests = filteredRequests;

    const displayExportableRequestCount = () => {
      let requestCount = document.getElementById("request-count");
      requestCount.innerText = ui.requests.length;
    };

    const resetFilterOptions = () => {
      let defaultFilterOption = document.querySelector('input[type="radio"][value="2"]');
      defaultFilterOption.checked = true;
    };

    const maybeDisableExportButton = () => {
      let button = document.getElementById("button-export");
      if (ui.requests.length === 0) {
        button.classList.add("inactive");
      } else {
        button.classList.remove("inactive");
      }
    };

    displayExportableRequestCount();
    resetFilterOptions();
    maybeDisableExportButton();
    ui.createExportResult();
  },

  createExportResult: async () => {
    let io = new SAMLTraceIO();
    let cookieProfile = document.querySelector('input[name="cookie-filter-profile"]:checked').value;
    let includeAnalysis = document.getElementById('include-analysis').checked;
    
    if (includeAnalysis) {
      // Show loading indicator
      const button = document.getElementById("button-export");
      button.textContent = 'Generating Analysis...';
      button.classList.add("inactive");
      
      ui.exportResult = await io.exportRequests(ui.requests, cookieProfile, true);
      
      // Reset button
      button.textContent = 'Export';
      button.classList.remove("inactive");
    } else {
      ui.exportResult = await io.exportRequests(ui.requests, cookieProfile, false);
    }
  }
};
