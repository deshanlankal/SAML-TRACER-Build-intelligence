/**
 * Storage Manager - Handles secure local storage for metadata and configuration
 * Privacy-focused: All data stored locally, domain-scoped isolation
 */

var StorageManager = (function() {
  'use strict';

  const STORAGE_PREFIX = 'saml_tracer_';
  const METADATA_KEY = STORAGE_PREFIX + 'metadata';
  const SETTINGS_KEY = STORAGE_PREFIX + 'settings';

  /**
   * Get all stored metadata
   */
  async function getAllMetadata() {
    try {
      const result = await browser.storage.local.get(METADATA_KEY);
      return result[METADATA_KEY] || {};
    } catch (error) {
      console.error('Error retrieving metadata:', error);
      return {};
    }
  }

  /**
   * Get metadata for a specific domain or entity ID
   */
  async function getMetadata(domainOrEntityId) {
    const allMetadata = await getAllMetadata();
    return allMetadata[domainOrEntityId] || null;
  }

  /**
   * Save metadata for a domain or entity ID
   */
  async function saveMetadata(domainOrEntityId, metadata) {
    try {
      const allMetadata = await getAllMetadata();
      
      // Add timestamp
      metadata.lastUpdated = new Date().toISOString();
      metadata.domain = domainOrEntityId;
      
      allMetadata[domainOrEntityId] = metadata;
      
      await browser.storage.local.set({
        [METADATA_KEY]: allMetadata
      });
      
      return true;
    } catch (error) {
      console.error('Error saving metadata:', error);
      return false;
    }
  }

  /**
   * Delete metadata for a specific domain
   */
  async function deleteMetadata(domainOrEntityId) {
    try {
      const allMetadata = await getAllMetadata();
      delete allMetadata[domainOrEntityId];
      
      await browser.storage.local.set({
        [METADATA_KEY]: allMetadata
      });
      
      return true;
    } catch (error) {
      console.error('Error deleting metadata:', error);
      return false;
    }
  }

  /**
   * Clear all stored metadata
   */
  async function clearAllMetadata() {
    try {
      await browser.storage.local.remove(METADATA_KEY);
      return true;
    } catch (error) {
      console.error('Error clearing metadata:', error);
      return false;
    }
  }

  /**
   * Get settings
   */
  async function getSettings() {
    try {
      const result = await browser.storage.local.get(SETTINGS_KEY);
      return result[SETTINGS_KEY] || {
        autoValidate: true,
        showSecurityWarnings: true,
        explainModeEnabled: false
      };
    } catch (error) {
      console.error('Error retrieving settings:', error);
      return {};
    }
  }

  /**
   * Save settings
   */
  async function saveSettings(settings) {
    try {
      await browser.storage.local.set({
        [SETTINGS_KEY]: settings
      });
      return true;
    } catch (error) {
      console.error('Error saving settings:', error);
      return false;
    }
  }

  /**
   * Get storage usage statistics
   */
  async function getStorageStats() {
    try {
      const allMetadata = await getAllMetadata();
      const domains = Object.keys(allMetadata);
      
      return {
        totalDomains: domains.length,
        domains: domains,
        lastUpdated: domains.length > 0 
          ? Math.max(...domains.map(d => new Date(allMetadata[d].lastUpdated).getTime()))
          : null
      };
    } catch (error) {
      console.error('Error getting storage stats:', error);
      return { totalDomains: 0, domains: [] };
    }
  }

  /**
   * Export all metadata as JSON
   */
  async function exportMetadata() {
    const allMetadata = await getAllMetadata();
    const settings = await getSettings();
    
    return {
      version: '1.0',
      exportDate: new Date().toISOString(),
      metadata: allMetadata,
      settings: settings
    };
  }

  /**
   * Import metadata from JSON
   */
  async function importMetadata(data) {
    try {
      if (!data.metadata) {
        throw new Error('Invalid import data: missing metadata');
      }
      
      await browser.storage.local.set({
        [METADATA_KEY]: data.metadata
      });
      
      if (data.settings) {
        await saveSettings(data.settings);
      }
      
      return true;
    } catch (error) {
      console.error('Error importing metadata:', error);
      return false;
    }
  }

  // Public API
  return {
    getAllMetadata,
    getMetadata,
    saveMetadata,
    deleteMetadata,
    clearAllMetadata,
    getSettings,
    saveSettings,
    getStorageStats,
    exportMetadata,
    importMetadata
  };
})();
