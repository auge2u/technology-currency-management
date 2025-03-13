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
  // Which browsers to scan
  browsers: Array<'chrome' | 'firefox' | 'safari' | 'edge' | 'opera'>;
  
  // Whether to scan for security issues
  checkSecurityIssues: boolean;
  
  // Whether to check for extensions removed from store
  checkRemovedFromStore: boolean;
  
  // Whether to scan for deprecation notices
  checkDeprecation: boolean;
  
  // Whether to check for updates to extensions
  checkForUpdates: boolean;
  
  // Extensions to ignore (by ID)
  ignoreExtensions?: string[];
  
  // Extensions to ignore (by name pattern)
  ignorePatterns?: string[];
  
  // User profiles to scan (optional, auto-detected if not specified)
  browserProfiles?: Record<string, string[]>;
  
  // Custom manifest locations
  customManifestLocations?: Record<string, string[]>;
  
  // API timeout in milliseconds
  apiTimeoutMs: number;
}

/**
 * Browser extension profile information
 */
interface BrowserProfile {
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera';
  profilePath: string;
  extensions: ExtensionInfo[];
}

/**
 * Basic extension information
 */
interface ExtensionInfo {
  id: string;
  name: string;
  version: string;
  description?: string;
  manifestPath: string;
  manifestVersion: number;
  enabled: boolean;
}

/**
 * Scan browser extensions for issues
 */
export async function scanBrowserExtensions(
  config: BrowserExtensionScannerConfig
): Promise<BrowserExtensionIssue[]> {
  try {
    log.info('Starting browser extension scanner');
    
    const issues: BrowserExtensionIssue[] = [];
    
    // Find browser profiles with extensions
    const browserProfiles = await findBrowserProfiles(config);
    log.info(`Found ${browserProfiles.length} browser profiles to scan`);
    
    // Process each browser profile
    for (const profile of browserProfiles) {
      try {
        const profileIssues = await scanBrowserProfile(profile, config);
        issues.push(...profileIssues);
      } catch (profileError) {
        log.warn(`Error scanning browser profile at ${profile.profilePath}`, { error: profileError });
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
 * Find browser profiles with extensions installed
 */
async function findBrowserProfiles(
  config: BrowserExtensionScannerConfig
): Promise<BrowserProfile[]> {
  const profiles: BrowserProfile[] = [];
  
  for (const browser of config.browsers) {
    try {
      log.info(`Looking for ${browser} profiles`);
      
      // If profiles were provided in config, use those
      if (config.browserProfiles && config.browserProfiles[browser]) {
        for (const profilePath of config.browserProfiles[browser]) {
          if (fs.existsSync(profilePath)) {
            const extensions = await findBrowserExtensions(browser, profilePath, config);
            if (extensions.length > 0) {
              profiles.push({
                browser,
                profilePath,
                extensions
              });
            }
          } else {
            log.warn(`Configured profile path does not exist: ${profilePath}`);
          }
        }
      } else {
        // Auto-detect profiles
        const detectedProfiles = await detectBrowserProfiles(browser);
        log.info(`Found ${detectedProfiles.length} ${browser} profiles`);
        
        for (const profilePath of detectedProfiles) {
          const extensions = await findBrowserExtensions(browser, profilePath, config);
          if (extensions.length > 0) {
            profiles.push({
              browser,
              profilePath,
              extensions
            });
          }
        }
      }
    } catch (browserError) {
      log.warn(`Error finding ${browser} profiles`, { error: browserError });
    }
  }
  
  return profiles;
}

/**
 * Detect browser profile locations based on operating system
 */
async function detectBrowserProfiles(browser: string): Promise<string[]> {
  const platform = os.platform();
  const profiles: string[] = [];
  
  try {
    switch (platform) {
      case 'win32':
        return detectWindowsBrowserProfiles(browser);
      case 'darwin':
        return detectMacBrowserProfiles(browser);
      case 'linux':
        return detectLinuxBrowserProfiles(browser);
      default:
        log.warn(`Unsupported platform: ${platform}`);
        return [];
    }
  } catch (error) {
    log.warn(`Error detecting ${browser} profiles on ${platform}`, { error });
    return [];
  }
}

/**
 * Detect browser profiles on Windows
 */
async function detectWindowsBrowserProfiles(browser: string): Promise<string[]> {
  const userHome = os.homedir();
  const profiles: string[] = [];
  
  switch (browser) {
    case 'chrome':
      profiles.push(path.join(userHome, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default'));
      // Check for numbered profiles
      for (let i = 1; i <= 5; i++) {
        const profilePath = path.join(userHome, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', `Profile ${i}`);
        if (fs.existsSync(profilePath)) {
          profiles.push(profilePath);
        }
      }
      break;
      
    case 'firefox':
      // Find Firefox profiles.ini
      const firefoxProfilesDir = path.join(userHome, 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles');
      if (fs.existsSync(firefoxProfilesDir)) {
        const items = fs.readdirSync(firefoxProfilesDir);
        for (const item of items) {
          if (item.endsWith('.default') || item.endsWith('.default-release')) {
            profiles.push(path.join(firefoxProfilesDir, item));
          }
        }
      }
      break;
      
    case 'edge':
      profiles.push(path.join(userHome, 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default'));
      // Check for numbered profiles
      for (let i = 1; i <= 5; i++) {
        const profilePath = path.join(userHome, 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', `Profile ${i}`);
        if (fs.existsSync(profilePath)) {
          profiles.push(profilePath);
        }
      }
      break;
      
    case 'opera':
      profiles.push(path.join(userHome, 'AppData', 'Roaming', 'Opera Software', 'Opera Stable'));
      break;
      
    default:
      log.warn(`Unsupported browser for Windows: ${browser}`);
  }
  
  return profiles;
}

/**
 * Detect browser profiles on macOS
 */
async function detectMacBrowserProfiles(browser: string): Promise<string[]> {
  const userHome = os.homedir();
  const profiles: string[] = [];
  
  switch (browser) {
    case 'chrome':
      profiles.push(path.join(userHome, 'Library', 'Application Support', 'Google', 'Chrome', 'Default'));
      // Check for numbered profiles
      for (let i = 1; i <= 5; i++) {
        const profilePath = path.join(userHome, 'Library', 'Application Support', 'Google', 'Chrome', `Profile ${i}`);
        if (fs.existsSync(profilePath)) {
          profiles.push(profilePath);
        }
      }
      break;
      
    case 'firefox':
      // Find Firefox profiles directory
      const firefoxProfilesDir = path.join(userHome, 'Library', 'Application Support', 'Firefox', 'Profiles');
      if (fs.existsSync(firefoxProfilesDir)) {
        const items = fs.readdirSync(firefoxProfilesDir);
        for (const item of items) {
          if (item.endsWith('.default') || item.endsWith('.default-release')) {
            profiles.push(path.join(firefoxProfilesDir, item));
          }
        }
      }
      break;
      
    case 'safari':
      // Safari extensions are in a different location
      const safariExtDir = path.join(userHome, 'Library', 'Safari', 'Extensions');
      if (fs.existsSync(safariExtDir)) {
        profiles.push(safariExtDir);
      }
      break;
      
    case 'edge':
      profiles.push(path.join(userHome, 'Library', 'Application Support', 'Microsoft Edge', 'Default'));
      // Check for numbered profiles
      for (let i = 1; i <= 5; i++) {
        const profilePath = path.join(userHome, 'Library', 'Application Support', 'Microsoft Edge', `Profile ${i}`);
        if (fs.existsSync(profilePath)) {
          profiles.push(profilePath);
        }
      }
      break;
      
    case 'opera':
      profiles.push(path.join(userHome, 'Library', 'Application Support', 'com.operasoftware.Opera'));
      break;
      
    default:
      log.warn(`Unsupported browser for macOS: ${browser}`);
  }
  
  return profiles;
}

/**
 * Detect browser profiles on Linux
 */
async function detectLinuxBrowserProfiles(browser: string): Promise<string[]> {
  const userHome = os.homedir();
  const profiles: string[] = [];
  
  switch (browser) {
    case 'chrome':
      profiles.push(path.join(userHome, '.config', 'google-chrome', 'Default'));
      // Check for numbered profiles
      for (let i = 1; i <= 5; i++) {
        const profilePath = path.join(userHome, '.config', 'google-chrome', `Profile ${i}`);
        if (fs.existsSync(profilePath)) {
          profiles.push(profilePath);
        }
      }
      break;
      
    case 'firefox':
      // Find Firefox profiles directory
      const firefoxProfilesDir = path.join(userHome, '.mozilla', 'firefox');
      if (fs.existsSync(firefoxProfilesDir)) {
        const items = fs.readdirSync(firefoxProfilesDir);
        for (const item of items) {
          if (item.endsWith('.default') || item.endsWith('.default-release')) {
            profiles.push(path.join(firefoxProfilesDir, item));
          }
        }
      }
      break;
      
    case 'opera':
      profiles.push(path.join(userHome, '.config', 'opera'));
      break;
      
    default:
      log.warn(`Unsupported browser for Linux: ${browser}`);
  }
  
  return profiles;
}

/**
 * Find browser extensions in a profile
 */
async function findBrowserExtensions(
  browser: string,
  profilePath: string,
  config: BrowserExtensionScannerConfig
): Promise<ExtensionInfo[]> {
  try {
    switch (browser) {
      case 'chrome':
      case 'edge':
      case 'opera':
        // These browsers use the same extension format
        return findChromeBasedExtensions(profilePath, config);
      case 'firefox':
        return findFirefoxExtensions(profilePath, config);
      case 'safari':
        return findSafariExtensions(profilePath, config);
      default:
        log.warn(`Unsupported browser: ${browser}`);
        return [];
    }
  } catch (error) {
    log.warn(`Error finding extensions for ${browser} at ${profilePath}`, { error });
    return [];
  }
}

/**
 * Find extensions for Chromium-based browsers
 */
async function findChromeBasedExtensions(
  profilePath: string,
  config: BrowserExtensionScannerConfig
): Promise<ExtensionInfo[]> {
  const extensions: ExtensionInfo[] = [];
  const extensionsDir = path.join(profilePath, 'Extensions');
  
  if (fs.existsSync(extensionsDir)) {
    const extensionIds = fs.readdirSync(extensionsDir);
    
    for (const extId of extensionIds) {
      // Skip ignored extensions
      if (config.ignoreExtensions && config.ignoreExtensions.includes(extId)) {
        continue;
      }
      
      const extDir = path.join(extensionsDir, extId);
      const versionDirs = fs.readdirSync(extDir);
      
      if (versionDirs.length > 0) {
        // Use the highest version directory
        const latestVersion = versionDirs.sort().pop()!;
        const manifestPath = path.join(extDir, latestVersion, 'manifest.json');
        
        if (fs.existsSync(manifestPath)) {
          try {
            const manifestContent = fs.readFileSync(manifestPath, 'utf8');
            const manifest = JSON.parse(manifestContent);
            
            // Skip extensions matching ignore patterns
            if (config.ignorePatterns && 
                manifest.name && 
                config.ignorePatterns.some(pattern => new RegExp(pattern).test(manifest.name))) {
              continue;
            }
            
            extensions.push({
              id: extId,
              name: manifest.name || 'Unknown',
              version: manifest.version || 'Unknown',
              description: manifest.description,
              manifestPath,
              manifestVersion: manifest.manifest_version || 2,
              enabled: true // Assume enabled, we can't easily tell from the file system
            });
          } catch (manifestError) {
            log.warn(`Error parsing manifest at ${manifestPath}`, { error: manifestError });
          }
        }
      }
    }
  }
  
  // Check custom manifest locations if provided
  if (config.customManifestLocations && config.customManifestLocations['chrome']) {
    for (const manifestLocation of config.customManifestLocations['chrome']) {
      if (fs.existsSync(manifestLocation)) {
        try {
          const manifestContent = fs.readFileSync(manifestLocation, 'utf8');
          const manifest = JSON.parse(manifestContent);
          
          // Generate a makeshift ID if none exists
          const extId = manifest.key || `custom_${extensions.length}`;
          
          extensions.push({
            id: extId,
            name: manifest.name || 'Unknown',
            version: manifest.version || 'Unknown',
            description: manifest.description,
            manifestPath: manifestLocation,
            manifestVersion: manifest.manifest_version || 2,
            enabled: true // Assume enabled for custom locations
          });
        } catch (customManifestError) {
          log.warn(`Error parsing custom manifest at ${manifestLocation}`, { error: customManifestError });
        }
      }
    }
  }
  
  return extensions;
}

/**
 * Find Firefox extensions
 */
async function findFirefoxExtensions(
  profilePath: string,
  config: BrowserExtensionScannerConfig
): Promise<ExtensionInfo[]> {
  const extensions: ExtensionInfo[] = [];
  const extensionsDir = path.join(profilePath, 'extensions');
  
  if (fs.existsSync(extensionsDir)) {
    const extensionFiles = fs.readdirSync(extensionsDir);
    
    for (const extFile of extensionFiles) {
      const extPath = path.join(extensionsDir, extFile);
      
      // Firefox extensions can be directories or .xpi files
      if (fs.statSync(extPath).isDirectory()) {
        const manifestPath = path.join(extPath, 'manifest.json');
        
        if (fs.existsSync(manifestPath)) {
          try {
            const manifestContent = fs.readFileSync(manifestPath, 'utf8');
            const manifest = JSON.parse(manifestContent);
            
            // Firefox extension IDs often end with @mozilla.org
            const extId = extFile;
            
            // Skip ignored extensions
            if (config.ignoreExtensions && config.ignoreExtensions.includes(extId)) {
              continue;
            }
            
            // Skip extensions matching ignore patterns
            if (config.ignorePatterns && 
                manifest.name && 
                config.ignorePatterns.some(pattern => new RegExp(pattern).test(manifest.name))) {
              continue;
            }
            
            extensions.push({
              id: extId,
              name: manifest.name || 'Unknown',
              version: manifest.version || 'Unknown',
              description: manifest.description,
              manifestPath,
              manifestVersion: manifest.manifest_version || 2,
              enabled: true // Assume enabled, we can't easily tell from the file system
            });
          } catch (manifestError) {
            log.warn(`Error parsing manifest at ${manifestPath}`, { error: manifestError });
          }
        }
      }
      // Handle .xpi files if needed - would require extracting the archive
    }
  }
  
  return extensions;
}

/**
 * Find Safari extensions
 */
async function findSafariExtensions(
  profilePath: string,
  config: BrowserExtensionScannerConfig
): Promise<ExtensionInfo[]> {
  const extensions: ExtensionInfo[] = [];
  
  if (fs.existsSync(profilePath)) {
    const extensionFiles = fs.readdirSync(profilePath);
    
    for (const extFile of extensionFiles) {
      // Safari extensions have .safariextz or .appex extensions
      if (extFile.endsWith('.safariextz') || extFile.endsWith('.appex')) {
        // This is a simplified approach. Parsing Safari extensions properly would require
        // more complex handling of the binary format or using system tools
        const extId = path.basename(extFile, path.extname(extFile));
        
        // Skip ignored extensions
        if (config.ignoreExtensions && config.ignoreExtensions.includes(extId)) {
          continue;
        }
        
        // For Safari, we have less information without proper parsing
        extensions.push({
          id: extId,
          name: extId, // Approximate with filename
          version: 'Unknown', // Would need proper parsing
          manifestPath: path.join(profilePath, extFile),
          manifestVersion: 0, // Not applicable to Safari
          enabled: true // Assume enabled
        });
      }
    }
  }
  
  return extensions;
}

/**
 * Scan a browser profile for extension issues
 */
async function scanBrowserProfile(
  profile: BrowserProfile,
  config: BrowserExtensionScannerConfig
): Promise<BrowserExtensionIssue[]> {
  const issues: BrowserExtensionIssue[] = [];
  
  log.info(`Scanning ${profile.extensions.length} extensions in ${profile.browser} profile at ${profile.profilePath}`);
  
  for (const extension of profile.extensions) {
    try {
      // Check various criteria based on config
      if (config.checkForUpdates) {
        const latestVersion = await getLatestExtensionVersion(extension.id, profile.browser);
        
        if (latestVersion && compareVersions(extension.version, latestVersion) < 0) {
          // Extension is outdated
          const vulnerabilities: VulnerabilityInfo[] = [];
          let hasSecurityIssues = false;
          let isDeprecated = false;
          let isRemovedFromStore = false;
          
          // Check for security issues if enabled
          if (config.checkSecurityIssues) {
            const securityInfo = await checkExtensionSecurityIssues(extension.id, profile.browser);
            hasSecurityIssues = securityInfo.hasIssues;
            vulnerabilities.push(...securityInfo.vulnerabilities);
          }
          
          // Check if deprecated if enabled
          if (config.checkDeprecation) {
            isDeprecated = await isExtensionDeprecated(extension.id, profile.browser);
          }
          
          // Check if removed from store if enabled
          if (config.checkRemovedFromStore) {
            isRemovedFromStore = await isExtensionRemovedFromStore(extension.id, profile.browser);
          }
          
          // Create the issue record
          const issue: BrowserExtensionIssue = {
            name: extension.name,
            id: extension.id,
            currentVersion: extension.version,
            latestVersion: latestVersion,
            browser: profile.browser,
            isOutdated: true,
            isDeprecated,
            hasSecurityIssues,
            isRemovedFromStore,
            vulnerabilities,
            storeUrl: getExtensionStoreUrl(extension.id, profile.browser),
            detectedAt: new Date()
          };
          
          issues.push(issue);
        }
      } else {
        // If not checking for updates, still check other criteria
        let needsToReport = false;
        let hasSecurityIssues = false;
        let isDeprecated = false;
        let isRemovedFromStore = false;
        const vulnerabilities: VulnerabilityInfo[] = [];
        
        // Check for security issues if enabled
        if (config.checkSecurityIssues) {
          const securityInfo = await checkExtensionSecurityIssues(extension.id, profile.browser);
          hasSecurityIssues = securityInfo.hasIssues;
          vulnerabilities.push(...securityInfo.vulnerabilities);
          if (hasSecurityIssues) needsToReport = true;
        }
        
        // Check if deprecated if enabled
        if (config.checkDeprecation) {
          isDeprecated = await isExtensionDeprecated(extension.id, profile.browser);
          if (isDeprecated) needsToReport = true;
        }
        
        // Check if removed from store if enabled
        if (config.checkRemovedFromStore) {
          isRemovedFromStore = await isExtensionRemovedFromStore(extension.id, profile.browser);
          if (isRemovedFromStore) needsToReport = true;
        }
        
        if (needsToReport) {
          const latestVersion = await getLatestExtensionVersion(extension.id, profile.browser) || 'Unknown';
          
          // Create the issue record
          const issue: BrowserExtensionIssue = {
            name: extension.name,
            id: extension.id,
            currentVersion: extension.version,
            latestVersion,
            browser: profile.browser,
            isOutdated: compareVersions(extension.version, latestVersion) < 0,
            isDeprecated,
            hasSecurityIssues,
            isRemovedFromStore,
            vulnerabilities,
            storeUrl: getExtensionStoreUrl(extension.id, profile.browser),
            detectedAt: new Date()
          };
          
          issues.push(issue);
        }
      }
    } catch (extensionError) {
      log.warn(`Error checking extension ${extension.id} - ${extension.name}`, { error: extensionError });
    }
  }
  
  return issues;
}

/**
 * Get the latest version of an extension
 */
async function getLatestExtensionVersion(extId: string, browser: string): Promise<string | null> {
  // In a real implementation, this would query the appropriate extension stores
  // For this example, we'll return a mock version
  return '2.0.0';
}

/**
 * Check if an extension has known security issues
 */
async function checkExtensionSecurityIssues(
  extId: string, 
  browser: string
): Promise<{ hasIssues: boolean; vulnerabilities: VulnerabilityInfo[] }> {
  // In a real implementation, this would query security databases
  // For this example, we'll return mock data
  return {
    hasIssues: false,
    vulnerabilities: []
  };
}

/**
 * Check if an extension is deprecated
 */
async function isExtensionDeprecated(extId: string, browser: string): Promise<boolean> {
  // In a real implementation, this would check for deprecation notices
  // For this example, we'll return a mock result
  return false;
}

/**
 * Check if an extension has been removed from its store
 */
async function isExtensionRemovedFromStore(extId: string, browser: string): Promise<boolean> {
  // In a real implementation, this would check if the extension is still available
  // For this example, we'll return a mock result
  return false;
}

/**
 * Get the store URL for an extension
 */
function getExtensionStoreUrl(extId: string, browser: string): string {
  switch (browser) {
    case 'chrome':
      return `https://chrome.google.com/webstore/detail/${extId}`;
    case 'firefox':
      return `https://addons.mozilla.org/en-US/firefox/addon/${extId}`;
    case 'edge':
      return `https://microsoftedge.microsoft.com/addons/detail/${extId}`;
    case 'safari':
      return 'https://apps.apple.com/us/app/safari-extensions/id1445270965';
    case 'opera':
      return `https://addons.opera.com/en/extensions/details/${extId}`;
    default:
      return '';
  }
}
