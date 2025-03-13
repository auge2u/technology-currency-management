import * as fs from 'fs';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import axios from 'axios';
import { ExtensionIssue } from '../types/scanning';
import { log } from '../utils/logging';

const execAsync = promisify(exec);

/**
 * Scanner to detect browser extension issues across Chrome, Firefox, Safari, and Edge
 */
export async function scanBrowserExtensions(options: {
  firefoxProfilePath?: string;
  chromeProfilePath?: string;
  edgeProfilePath?: string;
  safariExtensionPath?: string;
}): Promise<ExtensionIssue[]> {
  try {
    log.info('Starting browser extension scanning');
    
    const results: ExtensionIssue[] = [];
    
    // Scan extensions for each browser
    if (options.chromeProfilePath) {
      const chromeResults = await scanChromeExtensions(options.chromeProfilePath);
      results.push(...chromeResults);
    }
    
    if (options.firefoxProfilePath) {
      const firefoxResults = await scanFirefoxExtensions(options.firefoxProfilePath);
      results.push(...firefoxResults);
    }
    
    if (options.edgeProfilePath) {
      const edgeResults = await scanEdgeExtensions(options.edgeProfilePath);
      results.push(...edgeResults);
    }
    
    if (options.safariExtensionPath) {
      const safariResults = await scanSafariExtensions(options.safariExtensionPath);
      results.push(...safariResults);
    }
    
    log.info(`Browser extension scanning completed. Found ${results.length} issues`);
    
    return results;
  } catch (error) {
    log.error('Error during browser extension scanning', { error });
    return [];
  }
}

/**
 * Scan Chrome extensions for issues
 */
async function scanChromeExtensions(profilePath: string): Promise<ExtensionIssue[]> {
  try {
    log.info(`Scanning Chrome extensions in profile: ${profilePath}`);
    
    // Chrome extensions location in profile
    const extensionsPath = path.join(profilePath, 'Extensions');
    
    if (!fs.existsSync(extensionsPath)) {
      log.warn(`Chrome extensions directory not found: ${extensionsPath}`);
      return [];
    }
    
    const results: ExtensionIssue[] = [];
    const extensionIds = fs.readdirSync(extensionsPath);
    
    for (const extensionId of extensionIds) {
      try {
        const extensionDir = path.join(extensionsPath, extensionId);
        const versionDirs = fs.readdirSync(extensionDir);
        
        // Get the latest version directory
        const latestVersion = versionDirs.sort(compareVersions).pop();
        
        if (!latestVersion) continue;
        
        const manifestPath = path.join(extensionDir, latestVersion, 'manifest.json');
        
        if (fs.existsSync(manifestPath)) {
          const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
          const extensionName = manifest.name || 'Unknown Extension';
          const extensionVersion = manifest.version || 'Unknown Version';
          const manifestVersion = manifest.manifest_version || 2;
          
          // Check for manifest version issues
          if (manifestVersion < 3) {
            results.push({
              id: `chrome-manifest-${extensionId}`,
              browser: 'Chrome',
              extensionId,
              extensionName,
              extensionVersion,
              issueType: 'deprecated-api',
              title: 'Deprecated Manifest Version',
              description: 'Manifest Version 2 is being deprecated by Chrome. Extensions should migrate to Manifest V3.',
              severity: 'high',
              remediationSteps: 'Update the extension to use Manifest V3 format.',
              detectedAt: new Date()
            });
          }
          
          // Check for known vulnerable extensions
          const vulnerabilities = await checkExtensionVulnerabilities('chrome', extensionId, extensionVersion);
          
          for (const vuln of vulnerabilities) {
            results.push({
              id: `chrome-vuln-${extensionId}-${vuln.id}`,
              browser: 'Chrome',
              extensionId,
              extensionName,
              extensionVersion,
              issueType: 'security-vulnerability',
              title: vuln.title,
              description: vuln.description,
              severity: vuln.severity,
              remediationSteps: vuln.fixedInVersion 
                ? `Update to version ${vuln.fixedInVersion} or later.` 
                : 'Consider removing this extension.',
              detectedAt: new Date()
            });
          }
          
          // Check for deprecated APIs
          const deprecatedApis = checkForDeprecatedApis(manifest, 'chrome');
          
          for (const api of deprecatedApis) {
            results.push({
              id: `chrome-api-${extensionId}-${api.name}`,
              browser: 'Chrome',
              extensionId,
              extensionName,
              extensionVersion,
              issueType: 'deprecated-api',
              title: `Deprecated API: ${api.name}`,
              description: api.description,
              severity: api.severity,
              remediationSteps: api.alternative 
                ? `Replace with ${api.alternative}` 
                : 'Update the extension to use modern APIs.',
              detectedAt: new Date()
            });
          }
          
          // Check for compatibility issues
          const compatIssues = checkBrowserCompatibility(manifest, 'chrome');
          
          for (const issue of compatIssues) {
            results.push({
              id: `chrome-compat-${extensionId}-${issue.feature}`,
              browser: 'Chrome',
              extensionId,
              extensionName,
              extensionVersion,
              issueType: 'compatibility',
              title: `Compatibility Issue: ${issue.feature}`,
              description: issue.description,
              severity: issue.severity,
              remediationSteps: issue.solution,
              detectedAt: new Date()
            });
          }
        }
      } catch (extError) {
        log.warn(`Error processing Chrome extension ${extensionId}`, { error: extError });
      }
    }
    
    return results;
  } catch (error) {
    log.error('Error scanning Chrome extensions', { error });
    return [];
  }
}

/**
 * Scan Firefox extensions for issues
 */
async function scanFirefoxExtensions(profilePath: string): Promise<ExtensionIssue[]> {
  try {
    log.info(`Scanning Firefox extensions in profile: ${profilePath}`);
    
    // Firefox extensions are located in the "extensions" folder of the profile
    const extensionsPath = path.join(profilePath, 'extensions');
    
    if (!fs.existsSync(extensionsPath)) {
      log.warn(`Firefox extensions directory not found: ${extensionsPath}`);
      return [];
    }
    
    const results: ExtensionIssue[] = [];
    const extensionFiles = fs.readdirSync(extensionsPath);
    
    for (const extensionFile of extensionFiles) {
      try {
        // Firefox extensions are either directories or .xpi files
        const extensionPath = path.join(extensionsPath, extensionFile);
        const stats = fs.statSync(extensionPath);
        
        if (stats.isDirectory()) {
          // For directory-based extensions
          const manifestPath = path.join(extensionPath, 'manifest.json');
          
          if (fs.existsSync(manifestPath)) {
            const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
            processFirefoxExtensionManifest(manifest, extensionFile, results);
          }
        } else if (extensionFile.endsWith('.xpi')) {
          // For .xpi files, we'd need to extract them to access the manifest
          // This is simplified for the purpose of this example
          log.info(`Firefox extension in .xpi format: ${extensionFile}`);
          // In a real implementation, we would extract the .xpi and read the manifest
        }
      } catch (extError) {
        log.warn(`Error processing Firefox extension ${extensionFile}`, { error: extError });
      }
    }
    
    return results;
  } catch (error) {
    log.error('Error scanning Firefox extensions', { error });
    return [];
  }
}

/**
 * Process a Firefox extension manifest for issues
 */
function processFirefoxExtensionManifest(
  manifest: any,
  extensionId: string,
  results: ExtensionIssue[]
): void {
  const extensionName = manifest.name || 'Unknown Extension';
  const extensionVersion = manifest.version || 'Unknown Version';
  
  // Check for deprecated APIs
  const deprecatedApis = checkForDeprecatedApis(manifest, 'firefox');
  
  for (const api of deprecatedApis) {
    results.push({
      id: `firefox-api-${extensionId}-${api.name}`,
      browser: 'Firefox',
      extensionId,
      extensionName,
      extensionVersion,
      issueType: 'deprecated-api',
      title: `Deprecated API: ${api.name}`,
      description: api.description,
      severity: api.severity,
      remediationSteps: api.alternative 
        ? `Replace with ${api.alternative}` 
        : 'Update the extension to use modern APIs.',
      detectedAt: new Date()
    });
  }
  
  // Check for compatibility issues
  const compatIssues = checkBrowserCompatibility(manifest, 'firefox');
  
  for (const issue of compatIssues) {
    results.push({
      id: `firefox-compat-${extensionId}-${issue.feature}`,
      browser: 'Firefox',
      extensionId,
      extensionName,
      extensionVersion,
      issueType: 'compatibility',
      title: `Compatibility Issue: ${issue.feature}`,
      description: issue.description,
      severity: issue.severity,
      remediationSteps: issue.solution,
      detectedAt: new Date()
    });
  }
}

/**
 * Scan Edge extensions for issues
 */
async function scanEdgeExtensions(profilePath: string): Promise<ExtensionIssue[]> {
  // Edge uses the same extension format as Chrome
  return scanChromeExtensions(profilePath);
}

/**
 * Scan Safari extensions for issues
 */
async function scanSafariExtensions(extensionPath: string): Promise<ExtensionIssue[]> {
  try {
    log.info(`Scanning Safari extensions in path: ${extensionPath}`);
    
    if (!fs.existsSync(extensionPath)) {
      log.warn(`Safari extensions directory not found: ${extensionPath}`);
      return [];
    }
    
    const results: ExtensionIssue[] = [];
    
    // Safari extensions have different formats
    // This is a simplified version and would need more detailed implementation
    
    // For example, finding Info.plist files in .appex directories
    const { stdout } = await execAsync(`find ${extensionPath} -name "Info.plist" -path "*.appex/*"`);
    const plistFiles = stdout.trim().split('\n').filter(Boolean);
    
    for (const plistFile of plistFiles) {
      try {
        // In a real implementation, we would parse the plist file to extract information
        log.info(`Found Safari extension plist: ${plistFile}`);
        
        // Simulate finding information
        const extensionId = path.basename(path.dirname(plistFile));
        const extensionName = `Safari Extension ${extensionId}`;
        const extensionVersion = '1.0'; // This would come from the plist
        
        // Check for known vulnerable extensions
        const vulnerabilities = await checkExtensionVulnerabilities('safari', extensionId, extensionVersion);
        
        for (const vuln of vulnerabilities) {
          results.push({
            id: `safari-vuln-${extensionId}-${vuln.id}`,
            browser: 'Safari',
            extensionId,
            extensionName,
            extensionVersion,
            issueType: 'security-vulnerability',
            title: vuln.title,
            description: vuln.description,
            severity: vuln.severity,
            remediationSteps: vuln.fixedInVersion 
              ? `Update to version ${vuln.fixedInVersion} or later.` 
              : 'Consider removing this extension.',
            detectedAt: new Date()
          });
        }
      } catch (extError) {
        log.warn(`Error processing Safari extension plist ${plistFile}`, { error: extError });
      }
    }
    
    return results;
  } catch (error) {
    log.error('Error scanning Safari extensions', { error });
    return [];
  }
}

/**
 * Check for known security vulnerabilities in a browser extension
 */
async function checkExtensionVulnerabilities(
  browser: 'chrome' | 'firefox' | 'safari' | 'edge',
  extensionId: string,
  version: string
): Promise<Array<{
  id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  fixedInVersion?: string;
}>> {
  // In a real implementation, this would query a vulnerability database
  // For simulation, we'll use a mock database
  return new Promise(resolve => {
    setTimeout(() => {
      // Mock vulnerability database
      const knownVulnerabilities: Record<string, Record<string, Array<{
        id: string;
        title: string;
        description: string;
        severity: 'low' | 'medium' | 'high' | 'critical';
        affectedVersions: string;
        fixedInVersion?: string;
      }>>> = {
        chrome: {
          'aapbdbdomjkkjkaonfhkkikfgjllcleb': [ // Google Translate extension
            {
              id: 'EXT-2023-01',
              title: 'Data Exfiltration Vulnerability',
              description: 'Versions prior to 2.0.10 could allow attackers to exfiltrate translated text.',
              severity: 'medium',
              affectedVersions: '<2.0.10',
              fixedInVersion: '2.0.10'
            }
          ],
          'hdokiejnpimakedhajhdlcegeplioahd': [ // LastPass
            {
              id: 'EXT-2022-07',
              title: 'Side-Channel Attack Vulnerability',
              description: 'Versions prior to 4.60.0 are vulnerable to side-channel attacks that could expose password length.',
              severity: 'high',
              affectedVersions: '<4.60.0',
              fixedInVersion: '4.60.0'
            }
          ]
        },
        firefox: {
          'ublock-origin@mozilla.org': [
            {
              id: 'EXT-2023-05',
              title: 'Filter Bypass Vulnerability',
              description: 'Versions prior to 1.42.0 could allow certain tracking scripts to bypass filters.',
              severity: 'medium',
              affectedVersions: '<1.42.0',
              fixedInVersion: '1.42.0'
            }
          ]
        },
        safari: {
          // Safari extension vulnerabilities would be listed here
        },
        edge: {
          // Edge uses Chrome store IDs for most extensions
          'hdokiejnpimakedhajhdlcegeplioahd': [ // LastPass
            {
              id: 'EXT-2022-07',
              title: 'Side-Channel Attack Vulnerability',
              description: 'Versions prior to 4.60.0 are vulnerable to side-channel attacks that could expose password length.',
              severity: 'high',
              affectedVersions: '<4.60.0',
              fixedInVersion: '4.60.0'
            }
          ]
        }
      };
      
      // Check if browser and extension ID have known vulnerabilities
      const browserVulns = knownVulnerabilities[browser] || {};
      const extensionVulns = browserVulns[extensionId] || [];
      
      // Filter vulnerabilities that affect the current version
      const affectingVulns = extensionVulns.filter(vuln => {
        return isVersionAffected(version, vuln.affectedVersions);
      });
      
      resolve(affectingVulns);
    }, 100);
  });
}

/**
 * Check for deprecated APIs in extension manifest
 */
function checkForDeprecatedApis(
  manifest: any,
  browser: 'chrome' | 'firefox' | 'safari' | 'edge'
): Array<{
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high';
  alternative?: string;
}> {
  const results: Array<{
    name: string;
    description: string;
    severity: 'low' | 'medium' | 'high';
    alternative?: string;
  }> = [];
  
  // Check manifest version
  if (browser === 'chrome' || browser === 'edge') {
    if (manifest.manifest_version === 2) {
      results.push({
        name: 'Manifest V2',
        description: 'Manifest V2 is being deprecated. Chrome will stop supporting V2 extensions.',
        severity: 'high',
        alternative: 'Manifest V3'
      });
    }
  }
  
  // Check for deprecated permissions
  const deprecatedPermissions: Record<string, Record<string, {
    description: string;
    severity: 'low' | 'medium' | 'high';
    alternative?: string;
  }>> = {
    chrome: {
      'webRequest': {
        description: 'The webRequest API is deprecated in Manifest V3 and will be removed.',
        severity: 'high',
        alternative: 'declarativeNetRequest API'
      },
      'background': {
        description: 'Background pages are deprecated in Manifest V3.',
        severity: 'high',
        alternative: 'Service Workers'
      }
    },
    firefox: {
      // Firefox specific deprecated APIs
    },
    safari: {
      // Safari specific deprecated APIs
    },
    edge: {
      // Same as Chrome
      'webRequest': {
        description: 'The webRequest API is deprecated in Manifest V3 and will be removed.',
        severity: 'high',
        alternative: 'declarativeNetRequest API'
      },
      'background': {
        description: 'Background pages are deprecated in Manifest V3.',
        severity: 'high',
        alternative: 'Service Workers'
      }
    }
  };
  
  // Check for deprecated permissions
  if (manifest.permissions && Array.isArray(manifest.permissions)) {
    for (const permission of manifest.permissions) {
      if (typeof permission === 'string' && deprecatedPermissions[browser]?.[permission]) {
        const depInfo = deprecatedPermissions[browser][permission];
        results.push({
          name: permission,
          description: depInfo.description,
          severity: depInfo.severity,
          alternative: depInfo.alternative
        });
      }
    }
  }
  
  // Check for background page (deprecated in Manifest V3)
  if (browser === 'chrome' || browser === 'edge') {
    if (manifest.background && manifest.background.page) {
      results.push({
        name: 'background.page',
        description: 'Background pages are deprecated in Manifest V3.',
        severity: 'high',
        alternative: 'background.service_worker'
      });
    }
  }
  
  return results;
}

/**
 * Check for browser compatibility issues
 */
function checkBrowserCompatibility(
  manifest: any,
  browser: 'chrome' | 'firefox' | 'safari' | 'edge'
): Array<{
  feature: string;
  description: string;
  severity: 'low' | 'medium' | 'high';
  solution: string;
}> {
  const results: Array<{
    feature: string;
    description: string;
    severity: 'low' | 'medium' | 'high';
    solution: string;
  }> = [];
  
  // Chrome-specific compatibility issues
  if (browser === 'chrome' && manifest.minimum_chrome_version) {
    const minVersion = manifest.minimum_chrome_version;
    
    // Check if minimum version is too old
    if (compareVersions(minVersion, '80.0.0') < 0) {
      results.push({
        feature: 'minimum_chrome_version',
        description: `Extension specifies compatibility with very old Chrome version (${minVersion}). Modern Chrome security features may not be utilized.`,
        severity: 'medium',
        solution: 'Update minimum_chrome_version to at least 80.0.0'
      });
    }
  }
  
  // Firefox-specific compatibility issues
  if (browser === 'firefox' && manifest.applications?.gecko?.strict_min_version) {
    const minVersion = manifest.applications.gecko.strict_min_version;
    
    // Check if minimum version is too old
    if (compareVersions(minVersion, '78.0') < 0) {
      results.push({
        feature: 'strict_min_version',
        description: `Extension specifies compatibility with very old Firefox version (${minVersion}). Modern Firefox security features may not be utilized.`,
        severity: 'medium',
        solution: 'Update strict_min_version to at least 78.0'
      });
    }
  }
  
  return results;
}

/**
 * Check if a version is affected by vulnerability
 */
function isVersionAffected(version: string, affectedVersionsSpec: string): boolean {
  // For simplicity, we're only handling '<X.Y.Z' format
  if (affectedVersionsSpec.startsWith('<')) {
    const maxVersion = affectedVersionsSpec.substring(1);
    return compareVersions(version, maxVersion) < 0;
  }
  
  // For simplicity, we're only handling '<=X.Y.Z' format
  if (affectedVersionsSpec.startsWith('<=')) {
    const maxVersion = affectedVersionsSpec.substring(2);
    return compareVersions(version, maxVersion) <= 0;
  }
  
  return false;
}

/**
 * Compare two version strings
 */
function compareVersions(a: string, b: string): number {
  const partsA = a.split('.').map(Number);
  const partsB = b.split('.').map(Number);
  
  const len = Math.max(partsA.length, partsB.length);
  
  for (let i = 0; i < len; i++) {
    const partA = i < partsA.length ? partsA[i] : 0;
    const partB = i < partsB.length ? partsB[i] : 0;
    
    if (partA !== partB) {
      return partA - partB;
    }
  }
  
  return 0;
}
