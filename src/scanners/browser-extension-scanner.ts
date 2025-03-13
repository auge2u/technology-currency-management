import * as fs from 'fs';
import * as path from 'path';
import axios from 'axios';
import { BrowserExtensionIssue } from '../types/scanning';
import { log } from '../utils/logging';

/**
 * Scanner to identify problematic browser extensions across the organization's ecosystem
 */
export async function scanBrowserExtensions(extensionInventoryPath?: string): Promise<BrowserExtensionIssue[]> {
  try {
    log.info('Starting browser extension scanning');
    
    // If an inventory file path was provided, use it; otherwise check dummy inventory
    const extensions = extensionInventoryPath && fs.existsSync(extensionInventoryPath)
      ? JSON.parse(fs.readFileSync(extensionInventoryPath, 'utf8'))
      : getSampleExtensionInventory();
      
    const results: BrowserExtensionIssue[] = [];
    
    // Process each extension in inventory
    for (const extension of extensions) {
      try {
        // Multiple checks for extension issues
        await checkExtensionForIssues(extension, results);
      } catch (extensionError) {
        log.warn(`Error processing extension ${extension.name}`, { error: extensionError });
      }
    }
    
    log.info(`Browser extension scanning completed. Found ${results.length} problematic extensions`);
    
    return results;
  } catch (error) {
    log.error('Error during browser extension scanning', { error });
    return [];
  }
}

/**
 * Check a browser extension for various issues
 */
async function checkExtensionForIssues(
  extension: {
    id: string;
    name: string;
    version: string;
    browsers: Array<'Chrome' | 'Firefox' | 'Safari' | 'Edge'>;
    description?: string;
    permissions?: string[];
  },
  results: BrowserExtensionIssue[]
): Promise<void> {
  // Check if extension is outdated
  const latestVersion = await getLatestExtensionVersion(extension.id, extension.browsers[0]);
  
  if (latestVersion && compareVersions(extension.version, latestVersion) < 0) {
    // Extension is outdated
    results.push({
      id: `outdated-${extension.id}`,
      extensionName: extension.name,
      currentVersion: extension.version,
      latestVersion,
      browsers: extension.browsers,
      issueType: 'outdated',
      severity: determineOutdatedSeverity(extension.version, latestVersion),
      description: `Extension is using version ${extension.version} but ${latestVersion} is available`,
      remediationSteps: `Update the extension to version ${latestVersion} through the respective browser stores`,
      detectedAt: new Date()
    });
  }
  
  // Check if extension is deprecated
  const isDeprecated = await checkIfExtensionDeprecated(extension.id, extension.browsers[0]);
  
  if (isDeprecated) {
    results.push({
      id: `deprecated-${extension.id}`,
      extensionName: extension.name,
      currentVersion: extension.version,
      latestVersion: extension.version, // Same as current since it's deprecated
      browsers: extension.browsers,
      issueType: 'deprecated',
      severity: 'high',
      description: `Extension has been deprecated or removed from the store`,
      remediationSteps: `Find an alternative extension with similar functionality or contact the vendor for information`,
      detectedAt: new Date()
    });
  }
  
  // Check for known security issues
  const securityIssues = await checkExtensionSecurityIssues(extension.id, extension.version, extension.browsers[0]);
  
  if (securityIssues.hasIssues) {
    results.push({
      id: `security-${extension.id}`,
      extensionName: extension.name,
      currentVersion: extension.version,
      latestVersion: securityIssues.fixedInVersion || 'unknown',
      browsers: extension.browsers,
      issueType: 'security',
      severity: 'critical',
      description: securityIssues.description || 'Extension has known security vulnerabilities',
      remediationSteps: securityIssues.fixedInVersion 
        ? `Update to version ${securityIssues.fixedInVersion} or newer`
        : 'Consider removing this extension or finding a secure alternative',
      detectedAt: new Date()
    });
  }
  
  // Check for compatibility issues
  const compatibilityIssues = await checkBrowserCompatibility(extension.id, extension.browsers);
  
  if (compatibilityIssues.hasIssues) {
    results.push({
      id: `compatibility-${extension.id}`,
      extensionName: extension.name,
      currentVersion: extension.version,
      latestVersion: extension.version, // Use current as there's no newer version to fix it
      browsers: compatibilityIssues.problematicBrowsers || extension.browsers,
      issueType: 'compatibility',
      severity: 'medium',
      description: compatibilityIssues.description || 'Extension has compatibility issues with current browser versions',
      remediationSteps: 'Find a compatible alternative or contact the extension developer',
      detectedAt: new Date()
    });
  }
  
  // Check for permission issues (extensions requesting excessive permissions)
  if (extension.permissions && hasExcessivePermissions(extension.permissions)) {
    results.push({
      id: `permissions-${extension.id}`,
      extensionName: extension.name,
      currentVersion: extension.version,
      latestVersion: extension.version, // Use current as there's no specific version to fix
      browsers: extension.browsers,
      issueType: 'security',
      severity: 'medium',
      description: 'Extension requests excessive permissions which could pose a security risk',
      remediationSteps: 'Review if this extension is necessary or find an alternative with fewer permissions',
      detectedAt: new Date()
    });
  }
}

/**
 * Get the latest version of a browser extension
 * In a real implementation, this would query browser extension stores
 */
async function getLatestExtensionVersion(
  extensionId: string,
  browser: 'Chrome' | 'Firefox' | 'Safari' | 'Edge'
): Promise<string | null> {
  // This is a mock implementation
  // In reality, this would call each browser's extension store API
  
  // For example, for Chrome extensions:
  // https://chrome.google.com/webstore/detail/[extension-id]
  // And parse the version from the page or use their API
  
  // For Firefox:
  // https://addons.mozilla.org/api/v4/addons/addon/{extension-id}/
  
  // For demonstration purposes, we'll return mock data
  return new Promise((resolve) => {
    setTimeout(() => {
      // Mock extension database with latest versions
      const extensionVersions: Record<string, string> = {
        'aapbdbdomjkkjkaonfhkkikfgjllcleb': '2.0.10', // Google Translate
        'gcbommkclmclpchllfjekcdonpmejbdp': '2022.7.15.1', // HTTPS Everywhere
        'jlhmfgmfgeifomenelglieieghnjghma': '4.6.0', // Adblock Plus
        'aeddcgcebmpenjdkfnlhfloaifogidjc': '20.4.1.1', // Securelink Phishing Protection
        'cjpalhdlnbpafiamejdnhcphjbkeiagm': '1.44.4', // uBlock Origin
        'fmkadmapgofadopljbjfkapdkoienihi': '4.28.0', // React Developer Tools
        'dbepggeogbaibhgnhhndojpepiihcmeb': '1.0.0', // Vimium
        'lckanjgmijmafbedllaakclkaicjfmnk': '2.3.0', // ClearURLs
        'iodihamcpbpeioajjeobimgagajmlibd': '12.0.1', // Extension with security issues
        'onbkopaoemachfglhlpgpkbdnfmppmgm': '3.2.1' // Extension with compatibility issues
      };
      
      resolve(extensionVersions[extensionId] || null);
    }, 100);
  });
}

/**
 * Check if an extension has been deprecated
 */
async function checkIfExtensionDeprecated(
  extensionId: string,
  browser: 'Chrome' | 'Firefox' | 'Safari' | 'Edge'
): Promise<boolean> {
  // Mock implementation
  return new Promise((resolve) => {
    setTimeout(() => {
      // List of mock deprecated extensions
      const deprecatedExtensions = [
        'gcbommkclmclpchllfjekcdonpmejbdp', // HTTPS Everywhere (now built into browsers)
        'aeddcgcebmpenjdkfnlhfloaifogidjc', // Imaginary deprecated extension
        'kbfnbcaeplbcioakkpcpgfkobkghlhen', // Grammarly Lite (replaced by Grammarly)
        'cmeakgjggjdlcpncigglobpjbkabhmjl' // Another imaginary deprecated extension
      ];
      
      resolve(deprecatedExtensions.includes(extensionId));
    }, 50);
  });
}

/**
 * Check if an extension has known security issues
 */
async function checkExtensionSecurityIssues(
  extensionId: string,
  version: string,
  browser: 'Chrome' | 'Firefox' | 'Safari' | 'Edge'
): Promise<{
  hasIssues: boolean;
  description?: string;
  fixedInVersion?: string;
}> {
  // Mock implementation
  return new Promise((resolve) => {
    setTimeout(() => {
      // Mock database of extensions with security issues
      const securityIssues: Record<string, {
        affectedVersions: string;
        description: string;
        fixedInVersion: string;
      }> = {
        'iodihamcpbpeioajjeobimgagajmlibd': {
          affectedVersions: '<12.0.0',
          description: 'Data exfiltration vulnerability allowing unauthorized access to clipboard data',
          fixedInVersion: '12.0.0'
        },
        'fheoggkfdfchfphceeifdbepaooicaho': {
          affectedVersions: '<2.1.0',
          description: 'Remote code execution vulnerability through message passing API',
          fixedInVersion: '2.1.0'
        },
        'aapbdbdomjkkjkaonfhkkikfgjllcleb': {
          affectedVersions: '<2.0.8',
          description: 'Cross-site scripting vulnerability in extension popup',
          fixedInVersion: '2.0.8'
        }
      };
      
      const issue = securityIssues[extensionId];
      
      if (issue && isVersionInRange(version, issue.affectedVersions)) {
        resolve({
          hasIssues: true,
          description: issue.description,
          fixedInVersion: issue.fixedInVersion
        });
      } else {
        resolve({ hasIssues: false });
      }
    }, 75);
  });
}

/**
 * Check if an extension has compatibility issues with certain browsers
 */
async function checkBrowserCompatibility(
  extensionId: string,
  browsers: Array<'Chrome' | 'Firefox' | 'Safari' | 'Edge'>
): Promise<{
  hasIssues: boolean;
  problematicBrowsers?: Array<'Chrome' | 'Firefox' | 'Safari' | 'Edge'>;
  description?: string;
}> {
  // Mock implementation
  return new Promise((resolve) => {
    setTimeout(() => {
      // Mock database of extension compatibility issues
      const compatibilityIssues: Record<string, {
        browsers: Array<'Chrome' | 'Firefox' | 'Safari' | 'Edge'>;
        description: string;
      }> = {
        'onbkopaoemachfglhlpgpkbdnfmppmgm': {
          browsers: ['Safari', 'Firefox'],
          description: 'Extension uses Manifest V3 APIs incompatible with Firefox and has performance issues on Safari'
        },
        'dbepggeogbaibhgnhhndojpepiihcmeb': {
          browsers: ['Safari'],
          description: 'Extension uses keyboard shortcuts that conflict with Safari default shortcuts'
        },
        'lckanjgmijmafbedllaakclkaicjfmnk': {
          browsers: ['Edge'],
          description: 'Extension functionality broken in latest Edge updates due to new security policies'
        }
      };
      
      const issue = compatibilityIssues[extensionId];
      
      if (issue) {
        // Check if any of the browsers the extension is installed on have compatibility issues
        const problematicBrowsers = browsers.filter(browser => issue.browsers.includes(browser));
        
        if (problematicBrowsers.length > 0) {
          resolve({
            hasIssues: true,
            problematicBrowsers,
            description: issue.description
          });
          return;
        }
      }
      
      resolve({ hasIssues: false });
    }, 60);
  });
}

/**
 * Check if an extension requests excessive permissions
 */
function hasExcessivePermissions(permissions: string[]): boolean {
  const highRiskPermissions = [
    'tabs',
    'webNavigation',
    'webRequest',
    'webRequestBlocking',
    'browsingData',
    'downloads',
    'history',
    'management',
    'privacy',
    'proxy',
    'system.storage',
    '<all_urls>',
    'http://*/*',
    'https://*/*',
    'clipboardRead',
    'clipboardWrite',
    'cookies'
  ];
  
  // Check how many high-risk permissions this extension requests
  const highRiskCount = permissions.filter(p => highRiskPermissions.includes(p)).length;
  
  // If the extension requests 3 or more high-risk permissions, flag it
  return highRiskCount >= 3;
}

/**
 * Compare two version strings
 * Returns:
 * - Negative if version1 is older than version2
 * - 0 if versions are equal
 * - Positive if version1 is newer than version2
 */
function compareVersions(version1: string, version2: string): number {
  const parts1 = version1.split('.').map(Number);
  const parts2 = version2.split('.').map(Number);
  
  const maxLength = Math.max(parts1.length, parts2.length);
  
  for (let i = 0; i < maxLength; i++) {
    const part1 = i < parts1.length ? parts1[i] : 0;
    const part2 = i < parts2.length ? parts2[i] : 0;
    
    if (part1 !== part2) {
      return part1 - part2;
    }
  }
  
  return 0;
}

/**
 * Determine severity based on how outdated a version is
 */
function determineOutdatedSeverity(currentVersion: string, latestVersion: string): 'low' | 'medium' | 'high' | 'critical' {
  const diff = compareVersions(latestVersion, currentVersion);
  
  // Parse versions to get major.minor parts
  const current = currentVersion.split('.').map(Number);
  const latest = latestVersion.split('.').map(Number);
  
  // Calculate major version difference
  const majorDiff = (latest[0] || 0) - (current[0] || 0);
  
  if (majorDiff >= 2) return 'critical';
  if (majorDiff === 1) return 'high';
  
  // Calculate minor version difference if same major version
  if (majorDiff === 0) {
    const minorDiff = (latest[1] || 0) - (current[1] || 0);
    if (minorDiff >= 5) return 'high';
    if (minorDiff >= 2) return 'medium';
  }
  
  return 'low';
}

/**
 * Check if a version string is in a specified range
 * Simplified implementation supporting only '<' operator
 */
function isVersionInRange(version: string, range: string): boolean {
  if (range.startsWith('<')) {
    const targetVersion = range.substring(1);
    return compareVersions(version, targetVersion) < 0;
  }
  return false;
}

/**
 * Get a sample inventory of browser extensions for demo purposes
 * In a real organization, this would come from an inventory database or IT management system
 */
function getSampleExtensionInventory(): Array<{
  id: string;
  name: string;
  version: string;
  browsers: Array<'Chrome' | 'Firefox' | 'Safari' | 'Edge'>;
  permissions?: string[];
}> {
  return [
    {
      id: 'aapbdbdomjkkjkaonfhkkikfgjllcleb',
      name: 'Google Translate',
      version: '2.0.7',
      browsers: ['Chrome', 'Edge'],
      permissions: ['activeTab', 'storage', 'contextMenus']
    },
    {
      id: 'gcbommkclmclpchllfjekcdonpmejbdp',
      name: 'HTTPS Everywhere',
      version: '2021.7.13',
      browsers: ['Firefox'],
      permissions: ['webRequest', 'webRequestBlocking', 'http://*/*', 'https://*/*']
    },
    {
      id: 'jlhmfgmfgeifomenelglieieghnjghma',
      name: 'Adblock Plus',
      version: '4.6.0',
      browsers: ['Chrome', 'Firefox', 'Edge'],
      permissions: ['<all_urls>', 'tabs', 'webRequest', 'webRequestBlocking', 'webNavigation']
    },
    {
      id: 'aeddcgcebmpenjdkfnlhfloaifogidjc',
      name: 'Securelink Phishing Protection',
      version: '19.4.1.1',
      browsers: ['Chrome'],
      permissions: ['webRequest', 'storage', 'tabs', 'http://*/*', 'https://*/*']
    },
    {
      id: 'cjpalhdlnbpafiamejdnhcphjbkeiagm',
      name: 'uBlock Origin',
      version: '1.38.6',
      browsers: ['Chrome', 'Firefox'],
      permissions: ['webRequest', 'webRequestBlocking', 'http://*/*', 'https://*/*', 'privacy']
    },
    {
      id: 'fmkadmapgofadopljbjfkapdkoienihi',
      name: 'React Developer Tools',
      version: '4.13.5',
      browsers: ['Chrome', 'Edge'],
      permissions: ['file://*/*', 'http://*/*', 'https://*/*']
    },
    {
      id: 'dbepggeogbaibhgnhhndojpepiihcmeb',
      name: 'Vimium',
      version: '1.0.0',
      browsers: ['Chrome', 'Safari'],
      permissions: ['tabs', 'bookmarks', 'history', 'clipboardRead', 'clipboardWrite']
    },
    {
      id: 'lckanjgmijmafbedllaakclkaicjfmnk',
      name: 'ClearURLs',
      version: '1.21.0',
      browsers: ['Firefox', 'Edge'],
      permissions: ['webRequest', 'webRequestBlocking', 'http://*/*', 'https://*/*']
    },
    {
      id: 'iodihamcpbpeioajjeobimgagajmlibd',
      name: 'Security Extension Pro',
      version: '11.5.3',
      browsers: ['Chrome', 'Edge'],
      permissions: ['tabs', 'webRequest', 'webRequestBlocking', 'http://*/*', 'https://*/*']
    },
    {
      id: 'onbkopaoemachfglhlpgpkbdnfmppmgm',
      name: 'Cross Browser Helper',
      version: '3.2.1',
      browsers: ['Chrome', 'Firefox', 'Safari'],
      permissions: ['tabs', 'storage']
    }
  ];
}
