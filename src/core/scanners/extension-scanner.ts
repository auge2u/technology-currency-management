import path from 'path';
import fs from 'fs/promises';
import { glob } from 'glob';
import axios from 'axios';
import { log } from '../../utils/logging';
import config from '../../config';
import { OutdatedExtension } from '../../types/scanning';
import { createScanResult, updateScanResult } from '../services/scan-result-service';
import { notifyOutdatedExtensions } from '../services/notification-service';

// Supported browsers
type Browser = 'chrome' | 'firefox' | 'safari' | 'edge';

/**
 * Runs a scan for outdated browser extensions
 */
export async function runExtensionScan(): Promise<OutdatedExtension[]> {
  try {
    log.info('Starting browser extension scan');
    
    // Create a new scan result record
    const scanId = await createScanResult('extension');
    
    const outdatedExtensions: OutdatedExtension[] = [];
    
    // Scan each configured browser if enabled
    if (config.scanning.extension.chrome.enabled) {
      const chromeResults = await scanChromeExtensions();
      outdatedExtensions.push(...chromeResults);
    }
    
    if (config.scanning.extension.firefox.enabled) {
      const firefoxResults = await scanFirefoxExtensions();
      outdatedExtensions.push(...firefoxResults);
    }
    
    if (config.scanning.extension.safari.enabled) {
      const safariResults = await scanSafariExtensions();
      outdatedExtensions.push(...safariResults);
    }
    
    if (config.scanning.extension.edge.enabled) {
      const edgeResults = await scanEdgeExtensions();
      outdatedExtensions.push(...edgeResults);
    }
    
    // Update scan result with findings
    await updateScanResult(scanId, {
      completedAt: new Date(),
      findings: outdatedExtensions.length,
      scanStatus: 'completed'
    });
    
    // Send notifications if there are findings
    if (outdatedExtensions.length > 0) {
      await notifyOutdatedExtensions(outdatedExtensions);
    }
    
    log.info(`Browser extension scan completed with ${outdatedExtensions.length} findings`);
    return outdatedExtensions;
    
  } catch (error) {
    log.error('Error during browser extension scan', { error });
    throw error;
  }
}

/**
 * Scans Chrome extensions for outdated versions
 */
async function scanChromeExtensions(): Promise<OutdatedExtension[]> {
  try {
    log.info('Scanning Chrome extensions');
    
    // Get installed extensions
    const chromeExtensionDir = config.scanning.extension.chrome.extensionDir;
    if (!chromeExtensionDir) {
      log.warn('Chrome extension directory not configured');
      return [];
    }
    
    return scanExtensionsInDirectory(chromeExtensionDir, 'chrome');
  } catch (error) {
    log.error('Error scanning Chrome extensions', { error });
    return [];
  }
}

/**
 * Scans Firefox extensions for outdated versions
 */
async function scanFirefoxExtensions(): Promise<OutdatedExtension[]> {
  try {
    log.info('Scanning Firefox extensions');
    
    // Get installed extensions
    const firefoxExtensionDir = config.scanning.extension.firefox.extensionDir;
    if (!firefoxExtensionDir) {
      log.warn('Firefox extension directory not configured');
      return [];
    }
    
    return scanExtensionsInDirectory(firefoxExtensionDir, 'firefox');
  } catch (error) {
    log.error('Error scanning Firefox extensions', { error });
    return [];
  }
}

/**
 * Scans Safari extensions for outdated versions
 */
async function scanSafariExtensions(): Promise<OutdatedExtension[]> {
  try {
    log.info('Scanning Safari extensions');
    
    // Get installed extensions
    const safariExtensionDir = config.scanning.extension.safari.extensionDir;
    if (!safariExtensionDir) {
      log.warn('Safari extension directory not configured');
      return [];
    }
    
    return scanExtensionsInDirectory(safariExtensionDir, 'safari');
  } catch (error) {
    log.error('Error scanning Safari extensions', { error });
    return [];
  }
}

/**
 * Scans Edge extensions for outdated versions
 */
async function scanEdgeExtensions(): Promise<OutdatedExtension[]> {
  try {
    log.info('Scanning Edge extensions');
    
    // Get installed extensions
    const edgeExtensionDir = config.scanning.extension.edge.extensionDir;
    if (!edgeExtensionDir) {
      log.warn('Edge extension directory not configured');
      return [];
    }
    
    return scanExtensionsInDirectory(edgeExtensionDir, 'edge');
  } catch (error) {
    log.error('Error scanning Edge extensions', { error });
    return [];
  }
}

/**
 * Scans extensions in a directory for outdated versions
 */
async function scanExtensionsInDirectory(dirPath: string, browser: Browser): Promise<OutdatedExtension[]> {
  try {
    log.debug(`Scanning extensions in ${dirPath} for ${browser}`);
    
    // Find all manifest.json files
    const manifestFiles = await glob(path.join(dirPath, '**', 'manifest.json'), { nodir: true });
    log.debug(`Found ${manifestFiles.length} manifest files in ${browser} directory`);
    
    const outdatedExtensions: OutdatedExtension[] = [];
    
    for (const manifestFile of manifestFiles) {
      try {
        // Read and parse manifest
        const content = await fs.readFile(manifestFile, 'utf-8');
        const manifest = JSON.parse(content);
        
        // Extract extension info
        const extId = manifest.key || manifest.id || path.basename(path.dirname(manifestFile));
        const extName = manifest.name || 'Unknown Extension';
        const extVersion = manifest.version || '0.0.0';
        
        // Check if extension is outdated
        const isOutdated = await isExtensionOutdated(extId, extVersion, browser);
        
        if (isOutdated.outdated) {
          // Determine severity based on how far behind it is
          const severity = determineSeverity(extVersion, isOutdated.latestVersion || '');
          
          outdatedExtensions.push({
            id: extId,
            name: extName,
            currentVersion: extVersion,
            latestVersion: isOutdated.latestVersion || 'Unknown',
            browser,
            manifestPath: manifestFile,
            severity,
            hasSecurityIssues: isOutdated.hasSecurityIssues || false,
            hasCompatibilityIssues: isOutdated.hasCompatibilityIssues || false,
            isDeprecated: isOutdated.isDeprecated || false,
            updateUrl: isOutdated.updateUrl,
            detectedAt: new Date()
          });
        }
      } catch (manifestError) {
        log.warn(`Error processing manifest ${manifestFile}`, { error: manifestError });
      }
    }
    
    return outdatedExtensions;
  } catch (error) {
    log.error(`Error scanning ${browser} extensions directory`, { error });
    return [];
  }
}

/**
 * Checks if an extension is outdated
 */
async function isExtensionOutdated(
  extensionId: string,
  currentVersion: string,
  browser: Browser
): Promise<{
  outdated: boolean;
  latestVersion?: string;
  hasSecurityIssues?: boolean;
  hasCompatibilityIssues?: boolean;
  isDeprecated?: boolean;
  updateUrl?: string;
}> {
  try {
    // Choose the appropriate store API based on browser
    let storeUrl = '';
    let parseResponse: (data: any) => any;
    
    if (browser === 'chrome') {
      // Chrome Web Store API
      storeUrl = `https://chrome.google.com/webstore/detail/${extensionId}`;
      parseResponse = (data) => {
        // In a real implementation, you would parse the Chrome Web Store response
        // For this example, we'll just simulate an outdated extension
        return {
          outdated: Math.random() > 0.5,
          latestVersion: '2.0.0',
          hasSecurityIssues: Math.random() > 0.7,
          updateUrl: `https://chrome.google.com/webstore/detail/${extensionId}`
        };
      };
    } else if (browser === 'firefox') {
      // Firefox Add-ons API
      storeUrl = `https://addons.mozilla.org/api/v5/addons/addon/${extensionId}/`;
      parseResponse = (data) => {
        return {
          outdated: data.current_version.version !== currentVersion,
          latestVersion: data.current_version.version,
          hasSecurityIssues: data.current_version.flags?.length > 0,
          isDeprecated: data.status === 'deprecated',
          updateUrl: data.url
        };
      };
    } else if (browser === 'safari') {
      // For Safari, we can check the App Store - though there's no official API
      // In a real implementation, you might need to scrape the App Store page
      return {
        outdated: Math.random() > 0.5,
        latestVersion: '3.0.0',
        hasCompatibilityIssues: Math.random() > 0.6,
      };
    } else if (browser === 'edge') {
      // Microsoft Edge Add-ons (Chrome-compatible extensions mostly)
      storeUrl = `https://microsoftedge.microsoft.com/addons/detail/${extensionId}`;
      parseResponse = (data) => {
        // In a real implementation, you would parse the Edge Add-ons response
        // For this example, we'll just simulate an outdated extension
        return {
          outdated: Math.random() > 0.5,
          latestVersion: '1.5.0',
          hasCompatibilityIssues: Math.random() > 0.8,
          updateUrl: storeUrl
        };
      };
    } else {
      return { outdated: false };
    }
    
    // In a real implementation, you would make an HTTP request to the store API
    // For this example, we'll simulate the result for most browsers
    if (browser === 'firefox' && storeUrl) {
      try {
        const response = await axios.get(storeUrl);
        return parseResponse(response.data);
      } catch (apiError) {
        log.warn(`Error checking Firefox add-on ${extensionId}`, { error: apiError });
        return { outdated: false };
      }
    } else {
      // Simulate results for other browsers
      return parseResponse({});
    }
  } catch (error) {
    log.warn(`Error checking if extension ${extensionId} is outdated`, { error });
    return { outdated: false };
  }
}

/**
 * Determines the severity of an outdated extension
 */
function determineSeverity(currentVersion: string, latestVersion: string): 'low' | 'medium' | 'high' | 'critical' {
  try {
    // Parse versions into components
    const current = currentVersion.split('.').map(Number);
    const latest = latestVersion.split('.').map(Number);
    
    // Major version difference is high or critical
    if (latest[0] - current[0] > 1) {
      return 'critical';
    } else if (latest[0] - current[0] === 1) {
      return 'high';
    }
    
    // Minor version difference
    if (latest[1] - current[1] > 5) {
      return 'high';
    } else if (latest[1] - current[1] > 2) {
      return 'medium';
    }
    
    // Patch version difference
    return 'low';
  } catch (error) {
    // If version parsing fails, default to medium
    return 'medium';
  }
}
