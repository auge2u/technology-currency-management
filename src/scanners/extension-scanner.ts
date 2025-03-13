import * as fs from 'fs';
import * as path from 'path';
import axios from 'axios';
import * as os from 'os';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as semver from 'semver';
import { ExtensionIssue } from '../types/scanning';
import { log } from '../utils/logging';

const execAsync = promisify(exec);

/**
 * Configuration for browser extension scanning
 */
export interface ExtensionScannerConfig {
  // Which browsers to scan
  browsers: Array<'chrome' | 'firefox' | 'edge' | 'safari'>;
  
  // Whether to check for deprecated APIs
  checkDeprecatedApis: boolean;
  
  // Whether to check for security vulnerabilities
  checkSecurity: boolean;
  
  // Whether to check for compatibility issues
  checkCompatibility: boolean;
  
  // Minimum version age in days to consider an extension outdated
  minVersionAgeDays: number;
  
  // How often to refresh extension data cache in hours
  cacheRefreshHours: number;
  
  // Directory to store extension data cache
  cacheDir: string;
  
  // Extensions to ignore (by ID)
  ignoredExtensions: string[];
  
  // Custom security feeds for extension vulnerabilities
  securityFeeds?: Array<{
    name: string;
    url: string;
    headers?: Record<string, string>;
  }>;
}

/**
 * Interface for extension data
 */
interface BrowserExtension {
  id: string;
  name: string;
  version: string;
  browser: string;
  location: string;
  manifest: any;
  updateUrl?: string;
}

/**
 * Interface for extension store metadata
 */
interface ExtensionStoreData {
  version: string;
  lastUpdated?: string | Date;
  downloadCount?: number;
  rating?: number;
  supportedBrowsers?: string[];
  permissions?: string[];
  knownIssues?: Array<{
    type: string;
    description: string;
    affectedVersions: string;
    fixedInVersion?: string;
  }>;
  deprecated?: boolean;
  deprecationReason?: string;
}

/**
 * Scan for browser extension issues
 */
export async function scanForExtensionIssues(
  config: ExtensionScannerConfig
): Promise<ExtensionIssue[]> {
  try {
    log.info('Starting browser extension scanning');
    
    const allExtensions: BrowserExtension[] = [];
    const issues: ExtensionIssue[] = [];
    
    // Find installed extensions for each browser
    if (config.browsers.includes('chrome')) {
      const chromeExtensions = await findChromeExtensions();
      allExtensions.push(...chromeExtensions);
    }
    
    if (config.browsers.includes('firefox')) {
      const firefoxExtensions = await findFirefoxExtensions();
      allExtensions.push(...firefoxExtensions);
    }
    
    if (config.browsers.includes('edge')) {
      const edgeExtensions = await findEdgeExtensions();
      allExtensions.push(...edgeExtensions);
    }
    
    if (config.browsers.includes('safari')) {
      const safariExtensions = await findSafariExtensions();
      allExtensions.push(...safariExtensions);
    }
    
    log.info(`Found ${allExtensions.length} browser extensions`);
    
    // Filter out ignored extensions
    const filteredExtensions = allExtensions.filter(
      ext => !config.ignoredExtensions.includes(ext.id)
    );
    
    // Check each extension for issues
    for (const extension of filteredExtensions) {
      try {
        // Get store metadata for the extension
        const storeData = await getExtensionStoreData(extension);
        
        // Check for outdated extensions
        if (storeData?.version && extension.version !== storeData.version) {
          if (semver.valid(extension.version) && semver.valid(storeData.version) && 
              semver.lt(extension.version, storeData.version)) {
            const issue: ExtensionIssue = {
              id: `outdated-${extension.browser}-${extension.id}`,
              browser: extension.browser,
              extensionId: extension.id,
              extensionName: extension.name,
              extensionVersion: extension.version,
              issueType: 'compatibility',
              title: `Outdated extension: ${extension.name}`,
              description: `The extension is using version ${extension.version} but version ${storeData.version} is available.`,
              remediationSteps: `Update the extension to the latest version through the ${extension.browser} extension store.`,
              severity: 'medium',
              detectedAt: new Date()
            };
            
            issues.push(issue);
          }
        }
        
        // Check for deprecated APIs if enabled
        if (config.checkDeprecatedApis) {
          const deprecatedApiIssues = await checkForDeprecatedApis(extension);
          issues.push(...deprecatedApiIssues);
        }
        
        // Check for security vulnerabilities if enabled
        if (config.checkSecurity) {
          const securityIssues = await checkForSecurityVulnerabilities(extension, config.securityFeeds);
          issues.push(...securityIssues);
        }
        
        // Check for compatibility issues if enabled
        if (config.checkCompatibility) {
          const compatibilityIssues = await checkForCompatibilityIssues(extension);
          issues.push(...compatibilityIssues);
        }
        
        // Check if the extension is deprecated in the store
        if (storeData?.deprecated) {
          const issue: ExtensionIssue = {
            id: `deprecated-${extension.browser}-${extension.id}`,
            browser: extension.browser,
            extensionId: extension.id,
            extensionName: extension.name,
            extensionVersion: extension.version,
            issueType: 'end-of-life',
            title: `Deprecated extension: ${extension.name}`,
            description: storeData.deprecationReason || `This extension has been deprecated in the ${extension.browser} store.`,
            remediationSteps: 'Consider finding an alternative extension that provides similar functionality.',
            severity: 'high',
            detectedAt: new Date()
          };
          
          issues.push(issue);
        }
      } catch (extensionError) {
        log.warn(`Error checking extension ${extension.name}`, { error: extensionError });
      }
    }
    
    log.info(`Extension scanning completed. Found ${issues.length} issues`);
    return issues;
  } catch (error) {
    log.error('Error during browser extension scanning', { error });
    return [];
  }
}

/**
 * Find Chrome extensions
 */
async function findChromeExtensions(): Promise<BrowserExtension[]> {
  try {
    log.info('Scanning for Chrome extensions');
    
    const extensions: BrowserExtension[] = [];
    let chromePath = '';
    
    // Determine Chrome extensions directory based on OS
    const platform = os.platform();
    const homeDir = os.homedir();
    
    if (platform === 'darwin') { // macOS
      chromePath = path.join(homeDir, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Extensions');
    } else if (platform === 'win32') { // Windows
      chromePath = path.join(homeDir, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Extensions');
    } else if (platform === 'linux') { // Linux
      chromePath = path.join(homeDir, '.config', 'google-chrome', 'Default', 'Extensions');
    } else {
      log.warn(`Unsupported platform for Chrome extension scanning: ${platform}`);
      return [];
    }
    
    // Check if the directory exists
    if (!fs.existsSync(chromePath)) {
      log.warn(`Chrome extensions directory not found: ${chromePath}`);
      return [];
    }
    
    // Read all extension directories
    const extensionIds = fs.readdirSync(chromePath);
    
    for (const extId of extensionIds) {
      const extPath = path.join(chromePath, extId);
      
      // Each extension can have multiple versions installed
      const versionDirs = fs.readdirSync(extPath);
      
      if (versionDirs.length > 0) {
        // Get the latest version (assuming directories are named with version numbers)
        const latestVersion = versionDirs.sort(semver.compare).pop();
        if (latestVersion) {
          const manifestPath = path.join(extPath, latestVersion, 'manifest.json');
          
          if (fs.existsSync(manifestPath)) {
            try {
              const manifestData = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
              
              extensions.push({
                id: extId,
                name: manifestData.name || extId,
                version: manifestData.version || latestVersion,
                browser: 'chrome',
                location: path.join(extPath, latestVersion),
                manifest: manifestData,
                updateUrl: manifestData.update_url
              });
            } catch (parseError) {
              log.warn(`Error parsing manifest for Chrome extension ${extId}`, { error: parseError });
            }
          }
        }
      }
    }
    
    log.info(`Found ${extensions.length} Chrome extensions`);
    return extensions;
  } catch (error) {
    log.error('Error finding Chrome extensions', { error });
    return [];
  }
}

/**
 * Find Firefox extensions
 */
async function findFirefoxExtensions(): Promise<BrowserExtension[]> {
  try {
    log.info('Scanning for Firefox extensions');
    
    const extensions: BrowserExtension[] = [];
    let firefoxPath = '';
    
    // Determine Firefox extensions directory based on OS
    const platform = os.platform();
    const homeDir = os.homedir();
    
    if (platform === 'darwin') { // macOS
      firefoxPath = path.join(homeDir, 'Library', 'Application Support', 'Firefox', 'Profiles');
    } else if (platform === 'win32') { // Windows
      firefoxPath = path.join(homeDir, 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles');
    } else if (platform === 'linux') { // Linux
      firefoxPath = path.join(homeDir, '.mozilla', 'firefox');
    } else {
      log.warn(`Unsupported platform for Firefox extension scanning: ${platform}`);
      return [];
    }
    
    // Check if the directory exists
    if (!fs.existsSync(firefoxPath)) {
      log.warn(`Firefox profiles directory not found: ${firefoxPath}`);
      return [];
    }
    
    // Firefox has profile directories with random names
    const profileDirs = fs.readdirSync(firefoxPath);
    
    for (const profileDir of profileDirs) {
      const profilePath = path.join(firefoxPath, profileDir);
      const extensionsPath = path.join(profilePath, 'extensions');
      
      if (fs.existsSync(extensionsPath) && fs.statSync(profilePath).isDirectory()) {
        const extFiles = fs.readdirSync(extensionsPath);
        
        for (const extFile of extFiles) {
          const extPath = path.join(extensionsPath, extFile);
          
          // Extension could be a directory or an XPI file
          if (fs.statSync(extPath).isDirectory()) {
            const manifestPath = path.join(extPath, 'manifest.json');
            
            if (fs.existsSync(manifestPath)) {
              try {
                const manifestData = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
                
                extensions.push({
                  id: extFile,
                  name: manifestData.name || extFile,
                  version: manifestData.version || '0.0.0',
                  browser: 'firefox',
                  location: extPath,
                  manifest: manifestData
                });
              } catch (parseError) {
                log.warn(`Error parsing manifest for Firefox extension ${extFile}`, { error: parseError });
              }
            }
          }
          // Could add handling for XPI files here if needed
        }
      }
    }
    
    log.info(`Found ${extensions.length} Firefox extensions`);
    return extensions;
  } catch (error) {
    log.error('Error finding Firefox extensions', { error });
    return [];
  }
}

/**
 * Find Edge extensions
 */
async function findEdgeExtensions(): Promise<BrowserExtension[]> {
  try {
    log.info('Scanning for Edge extensions');
    
    const extensions: BrowserExtension[] = [];
    let edgePath = '';
    
    // Determine Edge extensions directory based on OS
    const platform = os.platform();
    const homeDir = os.homedir();
    
    if (platform === 'darwin') { // macOS
      edgePath = path.join(homeDir, 'Library', 'Application Support', 'Microsoft Edge', 'Default', 'Extensions');
    } else if (platform === 'win32') { // Windows
      edgePath = path.join(homeDir, 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default', 'Extensions');
    } else if (platform === 'linux') { // Linux
      edgePath = path.join(homeDir, '.config', 'microsoft-edge', 'Default', 'Extensions');
    } else {
      log.warn(`Unsupported platform for Edge extension scanning: ${platform}`);
      return [];
    }
    
    // Check if the directory exists
    if (!fs.existsSync(edgePath)) {
      log.warn(`Edge extensions directory not found: ${edgePath}`);
      return [];
    }
    
    // Structure is similar to Chrome
    const extensionIds = fs.readdirSync(edgePath);
    
    for (const extId of extensionIds) {
      const extPath = path.join(edgePath, extId);
      
      // Each extension can have multiple versions installed
      const versionDirs = fs.readdirSync(extPath);
      
      if (versionDirs.length > 0) {
        // Get the latest version
        const latestVersion = versionDirs.sort(semver.compare).pop();
        if (latestVersion) {
          const manifestPath = path.join(extPath, latestVersion, 'manifest.json');
          
          if (fs.existsSync(manifestPath)) {
            try {
              const manifestData = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
              
              extensions.push({
                id: extId,
                name: manifestData.name || extId,
                version: manifestData.version || latestVersion,
                browser: 'edge',
                location: path.join(extPath, latestVersion),
                manifest: manifestData,
                updateUrl: manifestData.update_url
              });
            } catch (parseError) {
              log.warn(`Error parsing manifest for Edge extension ${extId}`, { error: parseError });
            }
          }
        }
      }
    }
    
    log.info(`Found ${extensions.length} Edge extensions`);
    return extensions;
  } catch (error) {
    log.error('Error finding Edge extensions', { error });
    return [];
  }
}

/**
 * Find Safari extensions
 */
async function findSafariExtensions(): Promise<BrowserExtension[]> {
  try {
    log.info('Scanning for Safari extensions');
    
    const extensions: BrowserExtension[] = [];
    
    // Safari extensions are only available on macOS
    const platform = os.platform();
    if (platform !== 'darwin') {
      log.warn('Safari extension scanning is only supported on macOS');
      return [];
    }
    
    const homeDir = os.homedir();
    const safariExtPath = path.join(homeDir, 'Library', 'Safari', 'Extensions');
    
    // Check if the directory exists
    if (!fs.existsSync(safariExtPath)) {
      log.warn(`Safari extensions directory not found: ${safariExtPath}`);
      return [];
    }
    
    // Safari extensions have .safariextz files
    const extFiles = fs.readdirSync(safariExtPath);
    
    for (const extFile of extFiles) {
      if (extFile.endsWith('.safariextz') || fs.statSync(path.join(safariExtPath, extFile)).isDirectory()) {
        // For modern Safari App Extensions, we'd need to parse the Info.plist
        // This is simplified and would need more work for a complete implementation
        try {
          const extPath = path.join(safariExtPath, extFile);
          const extName = extFile.replace('.safariextz', '');
          
          // For a real implementation, we would extract and parse Info.plist from the extension
          // This is a placeholder for demonstration
          extensions.push({
            id: extName,
            name: extName,
            version: '1.0.0', // Placeholder version
            browser: 'safari',
            location: extPath,
            manifest: {}
          });
        } catch (parseError) {
          log.warn(`Error parsing Safari extension ${extFile}`, { error: parseError });
        }
      }
    }
    
    log.info(`Found ${extensions.length} Safari extensions`);
    return extensions;
  } catch (error) {
    log.error('Error finding Safari extensions', { error });
    return [];
  }
}

/**
 * Get extension metadata from extension stores
 */
async function getExtensionStoreData(extension: BrowserExtension): Promise<ExtensionStoreData | null> {
  try {
    // First check cache
    const cacheKey = `${extension.browser}-${extension.id}`;
    const cacheResult = getFromCache(cacheKey);
    
    if (cacheResult) {
      return cacheResult;
    }
    
    // If not in cache, fetch from store
    let storeData: ExtensionStoreData | null = null;
    
    switch (extension.browser) {
      case 'chrome':
        storeData = await getChromeStoreData(extension.id);
        break;
      case 'firefox':
        storeData = await getFirefoxStoreData(extension.id);
        break;
      case 'edge':
        storeData = await getEdgeStoreData(extension.id);
        break;
      case 'safari':
        storeData = await getSafariStoreData(extension.id);
        break;
    }
    
    if (storeData) {
      // Save to cache
      saveToCache(cacheKey, storeData);
    }
    
    return storeData;
  } catch (error) {
    log.warn(`Error getting store data for ${extension.name}`, { error });
    return null;
  }
}

/**
 * Get extension data from Chrome Web Store
 */
async function getChromeStoreData(extensionId: string): Promise<ExtensionStoreData | null> {
  try {
    // API endpoint for Chrome Web Store (this is an unofficial API)
    const url = `https://chrome.google.com/webstore/detail/${extensionId}`;
    const response = await axios.get(url);
    
    // This would need HTML parsing to extract data from the Chrome Web Store
    // For a real implementation, consider using a service that provides this data
    // This is a simplified placeholder implementation
    
    // Placeholder data
    return {
      version: '1.0.0',
      lastUpdated: new Date(),
      rating: 4.5,
      downloadCount: 10000,
      deprecated: false
    };
  } catch (error) {
    log.warn(`Error getting Chrome store data for ${extensionId}`, { error });
    return null;
  }
}

/**
 * Get extension data from Firefox Add-ons
 */
async function getFirefoxStoreData(extensionId: string): Promise<ExtensionStoreData | null> {
  try {
    // Firefox has an official API for add-ons
    const url = `https://addons.mozilla.org/api/v4/addons/addon/${extensionId}/`;
    const response = await axios.get(url);
    
    if (response.data) {
      const data = response.data;
      
      return {
        version: data.current_version?.version || '0.0.0',
        lastUpdated: data.last_updated,
        rating: data.ratings?.average || 0,
        downloadCount: data.average_daily_users || 0,
        deprecated: data.is_disabled || false,
        deprecationReason: data.disabled_by_user_abuse ? 'Disabled due to abuse' : undefined
      };
    }
    
    return null;
  } catch (error) {
    log.warn(`Error getting Firefox store data for ${extensionId}`, { error });
    return null;
  }
}

/**
 * Get extension data from Edge Add-ons
 */
async function getEdgeStoreData(extensionId: string): Promise<ExtensionStoreData | null> {
  try {
    // Edge Add-ons doesn't have a public API, this would need web scraping
    // Placeholder implementation
    return {
      version: '1.0.0',
      lastUpdated: new Date(),
      rating: 4.0,
      downloadCount: 5000,
      deprecated: false
    };
  } catch (error) {
    log.warn(`Error getting Edge store data for ${extensionId}`, { error });
    return null;
  }
}

/**
 * Get extension data from Safari Extensions Gallery
 */
async function getSafariStoreData(extensionId: string): Promise<ExtensionStoreData | null> {
  try {
    // Safari doesn't have a public API for extensions
    // Placeholder implementation
    return {
      version: '1.0.0',
      lastUpdated: new Date(),
      rating: 4.2,
      downloadCount: 3000,
      deprecated: false
    };
  } catch (error) {
    log.warn(`Error getting Safari store data for ${extensionId}`, { error });
    return null;
  }
}

/**
 * Check for deprecated APIs used by an extension
 */
async function checkForDeprecatedApis(extension: BrowserExtension): Promise<ExtensionIssue[]> {
  try {
    const issues: ExtensionIssue[] = [];
    const manifest = extension.manifest;
    
    // Check manifest version
    if (extension.browser === 'chrome' && manifest.manifest_version < 3) {
      issues.push({
        id: `deprecated-api-manifest-${extension.browser}-${extension.id}`,
        browser: extension.browser,
        extensionId: extension.id,
        extensionName: extension.name,
        extensionVersion: extension.version,
        issueType: 'deprecated-api',
        title: 'Deprecated Manifest Version',
        description: `The extension uses Manifest v${manifest.manifest_version}, which is being deprecated. Chrome will stop supporting Manifest v2 in the future.`,
        remediationSteps: 'Migrate the extension to Manifest v3. See Chrome developer documentation for migration guidelines.',
        severity: 'high',
        detectedAt: new Date()
      });
    }
    
    // Check for deprecated Chrome APIs
    if (extension.browser === 'chrome' && manifest.permissions) {
      const deprecatedPermissions = [
        { name: 'background', reason: 'background pages are deprecated in Manifest v3 in favor of service workers' },
        { name: 'webRequest', reason: 'blocking webRequest is restricted in Manifest v3, use declarativeNetRequest instead' }
      ];
      
      for (const dep of deprecatedPermissions) {
        if (Array.isArray(manifest.permissions) && manifest.permissions.includes(dep.name)) {
          issues.push({
            id: `deprecated-api-permission-${dep.name}-${extension.browser}-${extension.id}`,
            browser: extension.browser,
            extensionId: extension.id,
            extensionName: extension.name,
            extensionVersion: extension.version,
            issueType: 'deprecated-api',
            title: `Deprecated API: ${dep.name}`,
            description: dep.reason,
            remediationSteps: 'Update the extension to use the recommended alternative APIs.',
            severity: 'medium',
            detectedAt: new Date()
          });
        }
      }
    }
    
    // Firefox specific API deprecations
    if (extension.browser === 'firefox' && manifest.applications?.gecko?.id) {
      // Placeholder for Firefox-specific API checks
    }
    
    return issues;
  } catch (error) {
    log.warn(`Error checking deprecated APIs for ${extension.name}`, { error });
    return [];
  }
}

/**
 * Check for security vulnerabilities in an extension
 */
async function checkForSecurityVulnerabilities(
  extension: BrowserExtension,
  securityFeeds?: Array<{ name: string; url: string; headers?: Record<string, string>; }>
): Promise<ExtensionIssue[]> {
  try {
    const issues: ExtensionIssue[] = [];
    
    // Check extension permissions for high-risk permissions
    const highRiskPermissions = [
      { name: 'tabs', risk: 'Can access browser tab information' },
      { name: 'history', risk: 'Can access browsing history' },
      { name: 'webNavigation', risk: 'Can track web navigation' },
      { name: 'downloads', risk: 'Can access downloads' },
      { name: 'cookies', risk: 'Can access cookies' },
      { name: 'clipboardWrite', risk: 'Can write to clipboard' },
      { name: 'clipboardRead', risk: 'Can read from clipboard' },
      { name: 'management', risk: 'Can manage extensions' },
      { name: 'proxy', risk: 'Can control proxy settings' },
      { name: 'declarativeNetRequest', risk: 'Can modify network requests' },
      { name: 'webRequest', risk: 'Can intercept network requests' },
      { name: 'bookmarks', risk: 'Can access bookmarks' },
      { name: 'contentSettings', risk: 'Can change content settings' },
      { name: 'debugger', risk: 'Can use the debugger' },
      { name: 'privacy', risk: 'Can change privacy settings' },
      { name: 'identity', risk: 'Can access user identity' },
      { name: 'system.storage', risk: 'Can access storage devices' }
    ];
    
    const manifest = extension.manifest;
    
    if (manifest.permissions && Array.isArray(manifest.permissions)) {
      const riskyPermissions = highRiskPermissions.filter(p => 
        manifest.permissions.includes(p.name)
      );
      
      if (riskyPermissions.length >= 3) {
        // If the extension has many high-risk permissions, flag it
        issues.push({
          id: `security-high-risk-permissions-${extension.browser}-${extension.id}`,
          browser: extension.browser,
          extensionId: extension.id,
          extensionName: extension.name,
          extensionVersion: extension.version,
          issueType: 'security-vulnerability',
          title: 'Multiple High-Risk Permissions',
          description: [
            `This extension uses ${riskyPermissions.length} high-risk permissions:`,
            ...riskyPermissions.map(p => `- ${p.name}: ${p.risk}`)
          ].join('\n'),
          remediationSteps: 'Review if this extension truly needs these permissions and consider alternatives with fewer permissions.',
          severity: 'medium',
          detectedAt: new Date()
        });
      }
    }
    
    // Check for known vulnerabilities in security feeds
    if (securityFeeds && securityFeeds.length > 0) {
      for (const feed of securityFeeds) {
        try {
          const response = await axios.get(feed.url, {
            headers: feed.headers
          });
          
          if (response.data) {
            // This would need specific parsing logic based on the feed format
            // Placeholder for demonstration
            
            // Example: feed data might contain a list of vulnerable extensions
            const vulnerableExtensions = response.data.vulnerableExtensions || [];
            const extensionVulns = vulnerableExtensions.filter((v: any) => 
              v.id === extension.id && v.browser === extension.browser
            );
            
            for (const vuln of extensionVulns) {
              issues.push({
                id: `security-feed-${feed.name}-${extension.browser}-${extension.id}-${vuln.id}`,
                browser: extension.browser,
                extensionId: extension.id,
                extensionName: extension.name,
                extensionVersion: extension.version,
                issueType: 'security-vulnerability',
                title: vuln.title || 'Security Vulnerability',
                description: vuln.description || 'No details provided',
                remediationSteps: vuln.remediation || 'Update the extension to the latest version or consider removing it.',
                severity: mapVulnerabilitySeverity(vuln.severity),
                detectedAt: new Date()
              });
            }
          }
        } catch (feedError) {
          log.warn(`Error checking security feed ${feed.name}`, { error: feedError });
        }
      }
    }
    
    return issues;
  } catch (error) {
    log.warn(`Error checking security vulnerabilities for ${extension.name}`, { error });
    return [];
  }
}

/**
 * Map vulnerability severity string to our severity levels
 */
function mapVulnerabilitySeverity(severity?: string): 'low' | 'medium' | 'high' | 'critical' {
  if (!severity) return 'medium';
  
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
    case 'moderate':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return 'medium';
  }
}

/**
 * Check for compatibility issues with an extension
 */
async function checkForCompatibilityIssues(extension: BrowserExtension): Promise<ExtensionIssue[]> {
  try {
    const issues: ExtensionIssue[] = [];
    const manifest = extension.manifest;
    
    // Check for Manifest v2 extensions that will stop working
    if (extension.browser === 'chrome' && manifest.manifest_version === 2) {
      // Get the browser version to check compatibility
      const browserVersion = await getChromeVersion();
      
      if (browserVersion && semver.gte(browserVersion, '112.0.0')) {
        issues.push({
          id: `compatibility-manifest-v2-${extension.browser}-${extension.id}`,
          browser: extension.browser,
          extensionId: extension.id,
          extensionName: extension.name,
          extensionVersion: extension.version,
          issueType: 'compatibility',
          title: 'Manifest v2 Compatibility Issue',
          description: 'This extension uses Manifest v2, which is being phased out by Chrome. In Chrome 112+, you may start to see issues with this extension.',
          remediationSteps: 'Contact the extension developer to ensure they are migrating to Manifest v3, or look for alternative extensions that are already using Manifest v3.',
          severity: 'medium',
          detectedAt: new Date()
        });
      }
      
      // Check for soon-to-be-removed APIs in Manifest v2
      if (manifest.background && manifest.background.page) {
        issues.push({
          id: `compatibility-background-page-${extension.browser}-${extension.id}`,
          browser: extension.browser,
          extensionId: extension.id,
          extensionName: extension.name,
          extensionVersion: extension.version,
          issueType: 'compatibility',
          title: 'Background Page Compatibility Issue',
          description: 'This extension uses a background page, which is not supported in Manifest v3. It will stop working when Chrome fully deprecates Manifest v2.',
          remediationSteps: 'Contact the extension developer to ensure they are migrating to service workers in Manifest v3.',
          severity: 'high',
          detectedAt: new Date()
        });
      }
    }
    
    // Firefox-specific compatibility checks
    if (extension.browser === 'firefox') {
      // Placeholder for Firefox-specific compatibility checks
    }
    
    return issues;
  } catch (error) {
    log.warn(`Error checking compatibility issues for ${extension.name}`, { error });
    return [];
  }
}

/**
 * Get Chrome browser version
 */
async function getChromeVersion(): Promise<string | null> {
  try {
    const platform = os.platform();
    let command = '';
    
    if (platform === 'darwin') { // macOS
      command = '/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --version';
    } else if (platform === 'win32') { // Windows
      command = 'reg query "HKEY_CURRENT_USER\Software\Google\Chrome\BLBeacon" /v version';
    } else if (platform === 'linux') { // Linux
      command = 'google-chrome --version';
    } else {
      return null;
    }
    
    const { stdout } = await execAsync(command);
    
    // Parse version from output
    const versionMatch = stdout.match(/Chrome\s+([\d\.]+)/) || 
                         stdout.match(/version\s+REG_SZ\s+([\d\.]+)/);
    
    return versionMatch ? versionMatch[1] : null;
  } catch (error) {
    log.warn('Error getting Chrome version', { error });
    return null;
  }
}

/**
 * Save extension data to cache
 */
function saveToCache(key: string, data: ExtensionStoreData): void {
  // This would be implemented to write to a cache file
  // For brevity, not implementing the actual file operations
}

/**
 * Get extension data from cache
 */
function getFromCache(key: string): ExtensionStoreData | null {
  // This would be implemented to read from a cache file
  // For brevity, not implementing the actual file operations
  return null;
}
