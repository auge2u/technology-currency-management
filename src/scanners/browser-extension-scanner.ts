import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { promisify } from 'util';
import { exec } from 'child_process';
import { BrowserExtensionIssue, VulnerabilityInfo } from '../types/scanning';
import { compareVersions } from '../utils/scanner-utils';
import { log } from '../utils/logging';

const execAsync = promisify(exec);

/**
 * Configuration for browser extension scanning
 */
export interface BrowserExtensionScannerConfig {
  // Which browsers to scan extensions for
  browsers: Array<'chrome' | 'firefox' | 'safari' | 'edge' | 'opera'>;
  
  // Whether to check for security vulnerabilities
  checkVulnerabilities: boolean;
  
  // Whether to check for browser compatibility issues
  checkCompatibility: boolean;
  
  // Specific users to scan for (if not specified, uses current user)
  users?: string[];
  
  // Skip extensions with specific IDs
  ignoreExtensions?: string[];
  
  // Skip extensions matching specific patterns
  ignorePatterns?: string[];
  
  // API timeout in milliseconds
  apiTimeoutMs: number;
}

/**
 * Extension information structure
 */
interface ExtensionInfo {
  id: string;
  name: string;
  version: string;
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera';
  installLocation: string;
  storeUrl?: string;
  isEnabled?: boolean;
}

/**
 * Scan browsers for outdated extensions
 */
export async function scanBrowserExtensions(
  config: BrowserExtensionScannerConfig
): Promise<BrowserExtensionIssue[]> {
  try {
    log.info('Starting browser extension scanner');
    
    const issues: BrowserExtensionIssue[] = [];
    const detectedExtensions: ExtensionInfo[] = [];
    
    // For each browser, detect installed extensions
    for (const browser of config.browsers) {
      try {
        log.info(`Scanning ${browser} extensions`);
        const extensions = await detectBrowserExtensions(browser, config.users);
        detectedExtensions.push(...extensions);
        log.info(`Detected ${extensions.length} extensions for ${browser}`);
      } catch (browserError) {
        log.warn(`Error scanning ${browser} extensions`, { error: browserError });
      }
    }
    
    log.info(`Total detected extensions: ${detectedExtensions.length}`);
    
    // Check each extension for issues
    for (const extension of detectedExtensions) {
      try {
        // Skip ignored extensions
        if (config.ignoreExtensions && config.ignoreExtensions.includes(extension.id)) {
          continue;
        }
        
        // Skip extensions matching ignore patterns
        if (config.ignorePatterns && 
            config.ignorePatterns.some(pattern => new RegExp(pattern).test(extension.name))) {
          continue;
        }
        
        // Get the latest version
        const latestVersion = await getLatestExtensionVersion(extension.id, extension.browser);
        
        if (!latestVersion) {
          continue; // Skip if we can't determine the latest version
        }
        
        const isOutdated = compareVersions(extension.version, latestVersion) < 0;
        let isRemovedFromStore = false;
        
        // Check if extension has been removed from store
        if (extension.storeUrl) {
          isRemovedFromStore = await checkExtensionRemovedFromStore(extension.storeUrl, config.apiTimeoutMs);
        }
        
        let vulnerabilities: VulnerabilityInfo[] = [];
        
        // Check for vulnerabilities if enabled
        if (config.checkVulnerabilities) {
          vulnerabilities = await getExtensionVulnerabilities(
            extension.id, 
            extension.version,
            extension.browser
          );
        }
        
        let compatibilityIssues: VulnerabilityInfo[] = [];
        
        // Check for compatibility issues if enabled
        if (config.checkCompatibility) {
          compatibilityIssues = await getExtensionCompatibilityIssues(
            extension.id,
            extension.version,
            extension.browser
          );
          
          // Add compatibility issues to vulnerabilities with "low" severity
          vulnerabilities.push(...compatibilityIssues.map(issue => ({
            ...issue,
            severity: 'low' as const
          })));
        }
        
        // Create the issue if outdated, has vulnerabilities, or removed from store
        if (isOutdated || vulnerabilities.length > 0 || isRemovedFromStore) {
          const issue: BrowserExtensionIssue = {
            id: extension.id,
            name: extension.name,
            browser: extension.browser,
            currentVersion: extension.version,
            latestVersion,
            isOutdated,
            isRemovedFromStore,
            hasSecurityIssues: vulnerabilities.some(v => 
              v.severity === 'high' || v.severity === 'critical'),
            vulnerabilities,
            storeUrl: extension.storeUrl || getBrowserStoreUrl(extension.browser, extension.id),
            detectedAt: new Date()
          };
          
          issues.push(issue);
        }
      } catch (extensionError) {
        log.warn(`Error checking extension ${extension.name}@${extension.version}`, { error: extensionError });
      }
    }
    
    log.info(`Completed browser extension scanning. Found ${issues.length} issues`);
    return issues;
  } catch (error) {
    log.error('Error during browser extension scanning', { error });
    return [];
  }
}

/**
 * Detect installed browser extensions
 */
async function detectBrowserExtensions(
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera',
  users?: string[]
): Promise<ExtensionInfo[]> {
  const extensions: ExtensionInfo[] = [];
  const platform = os.platform();
  
  // If no users specified, use current user
  if (!users || users.length === 0) {
    const homeDir = os.homedir();
    users = [path.basename(homeDir)];
  }
  
  for (const user of users) {
    try {
      let extensionDir = '';
      
      // Find extension directory based on platform and browser
      switch (platform) {
        case 'win32':
          extensionDir = getWindowsExtensionDir(browser, user);
          break;
        case 'darwin':
          extensionDir = getMacExtensionDir(browser, user);
          break;
        case 'linux':
          extensionDir = getLinuxExtensionDir(browser, user);
          break;
        default:
          log.warn(`Unsupported platform for browser extension scanning: ${platform}`);
          continue;
      }
      
      if (!extensionDir || !fs.existsSync(extensionDir)) {
        log.info(`Extension directory not found for ${browser} and user ${user}`);
        continue;
      }
      
      // List extensions in directory
      const extensionFolders = fs.readdirSync(extensionDir);
      
      for (const extensionFolder of extensionFolders) {
        const extensionPath = path.join(extensionDir, extensionFolder);
        
        // Skip if not a directory
        if (!fs.statSync(extensionPath).isDirectory()) {
          continue;
        }
        
        try {
          // Look for manifest.json file (Web Extensions standard)
          const manifestPath = path.join(extensionPath, 'manifest.json');
          
          if (fs.existsSync(manifestPath)) {
            const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
            
            const extension: ExtensionInfo = {
              id: extensionFolder,
              name: manifest.name || extensionFolder,
              version: manifest.version || '0.0.0',
              browser,
              installLocation: extensionPath,
              storeUrl: getBrowserStoreUrl(browser, extensionFolder)
            };
            
            extensions.push(extension);
          }
        } catch (manifestError) {
          log.warn(`Error parsing manifest for extension in ${extensionPath}`, { error: manifestError });
        }
      }
    } catch (userError) {
      log.warn(`Error scanning extensions for user ${user}`, { error: userError });
    }
  }
  
  return extensions;
}

/**
 * Get the extension directory for Windows
 */
function getWindowsExtensionDir(
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera',
  user: string
): string {
  const appData = path.join('C:', 'Users', user, 'AppData');
  
  switch (browser) {
    case 'chrome':
      return path.join(appData, 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Extensions');
    case 'firefox':
      return path.join(appData, 'Roaming', 'Mozilla', 'Firefox', 'Profiles');
    case 'edge':
      return path.join(appData, 'Local', 'Microsoft', 'Edge', 'User Data', 'Default', 'Extensions');
    case 'opera':
      return path.join(appData, 'Roaming', 'Opera Software', 'Opera Stable', 'Extensions');
    default:
      return '';
  }
}

/**
 * Get the extension directory for macOS
 */
function getMacExtensionDir(
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera',
  user: string
): string {
  const homeDir = path.join('/Users', user);
  
  switch (browser) {
    case 'chrome':
      return path.join(homeDir, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Extensions');
    case 'firefox':
      return path.join(homeDir, 'Library', 'Application Support', 'Firefox', 'Profiles');
    case 'safari':
      return path.join(homeDir, 'Library', 'Safari', 'Extensions');
    case 'edge':
      return path.join(homeDir, 'Library', 'Application Support', 'Microsoft Edge', 'Default', 'Extensions');
    case 'opera':
      return path.join(homeDir, 'Library', 'Application Support', 'com.operasoftware.Opera', 'Extensions');
    default:
      return '';
  }
}

/**
 * Get the extension directory for Linux
 */
function getLinuxExtensionDir(
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera',
  user: string
): string {
  const homeDir = path.join('/home', user);
  
  switch (browser) {
    case 'chrome':
      return path.join(homeDir, '.config', 'google-chrome', 'Default', 'Extensions');
    case 'firefox':
      return path.join(homeDir, '.mozilla', 'firefox');
    case 'edge':
      return path.join(homeDir, '.config', 'microsoft-edge', 'Default', 'Extensions');
    case 'opera':
      return path.join(homeDir, '.config', 'opera', 'Extensions');
    default:
      return '';
  }
}

/**
 * Get the URL to the extension in the browser's store
 */
function getBrowserStoreUrl(
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera',
  extensionId: string
): string {
  switch (browser) {
    case 'chrome':
      return `https://chrome.google.com/webstore/detail/${extensionId}`;
    case 'firefox':
      return `https://addons.mozilla.org/en-US/firefox/addon/${extensionId}/`;
    case 'safari':
      return `https://apps.apple.com/us/app/${extensionId}`;
    case 'edge':
      return `https://microsoftedge.microsoft.com/addons/detail/${extensionId}`;
    case 'opera':
      return `https://addons.opera.com/en/extensions/details/${extensionId}/`;
    default:
      return '';
  }
}

/**
 * Get the latest version of a browser extension
 */
async function getLatestExtensionVersion(
  extensionId: string,
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera'
): Promise<string | null> {
  // In a real implementation, this would query the appropriate extension stores
  // For this example, we'll return mock data
  return '2.0.0'; // Mock version for demonstration
}

/**
 * Check if an extension has been removed from the store
 */
async function checkExtensionRemovedFromStore(
  storeUrl: string,
  timeoutMs: number
): Promise<boolean> {
  // In a real implementation, this would make a request to the store URL
  // and check for 404 or other indicators that the extension was removed
  return false; // Mock result for demonstration
}

/**
 * Get vulnerabilities for a browser extension
 */
async function getExtensionVulnerabilities(
  extensionId: string,
  version: string,
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera'
): Promise<VulnerabilityInfo[]> {
  // In a real implementation, this would query security advisories
  // For this example, we'll return mock data for a specific extension
  if (browser === 'chrome' && extensionId === 'mafpmfcccpbjnhfhjnllmmalhifmlcie') {
    return [{
      id: 'EXT-2023-001',
      severity: 'high',
      title: 'Data Exfiltration Vulnerability',
      description: 'This extension version contains a vulnerability that could allow malicious websites to access sensitive data.',
      infoUrl: 'https://example.com/advisories/EXT-2023-001',
      publishedDate: new Date('2023-06-15'),
      affectedVersions: '< 1.5.0',
      patchedVersions: '>= 1.5.0',
      recommendation: 'Update to version 1.5.0 or later.'
    }];
  }
  
  return [];
}

/**
 * Get compatibility issues for a browser extension
 */
async function getExtensionCompatibilityIssues(
  extensionId: string,
  version: string,
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera'
): Promise<VulnerabilityInfo[]> {
  // In a real implementation, this would check if the extension is compatible with the latest browser version
  // For this example, we'll return mock data for a specific extension
  if (browser === 'firefox' && extensionId === 'some-legacy-extension') {
    return [{
      id: 'COMPAT-2023-001',
      severity: 'medium',
      title: 'Manifest V3 Compatibility Issue',
      description: 'This extension uses APIs that are deprecated in the latest browser version.',
      infoUrl: 'https://example.com/compatibility-issues/COMPAT-2023-001',
      publishedDate: new Date('2023-03-10'),
      affectedVersions: '< 2.0.0',
      patchedVersions: '>= 2.0.0',
      recommendation: 'Update to version 2.0.0 or later which supports Manifest V3.'
    }];
  }
  
  return [];
}
