import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { promisify } from 'util';
import { BrowserExtensionIssue, VulnerabilityInfo } from '../types/scanning';
import { compareVersions } from '../utils/scanner-utils';
import { log } from '../utils/logging';
import * as child_process from 'child_process';

const readFileAsync = promisify(fs.readFile);
const readdirAsync = promisify(fs.readdir);
const execAsync = promisify(child_process.exec);

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
 * Information about a browser extension
 */
interface BrowserExtension {
  // Extension ID
  id: string;
  
  // Extension name
  name: string;
  
  // Current version
  version: string;
  
  // Extension description
  description?: string;
  
  // Whether the extension is enabled
  enabled: boolean;
  
  // Location of the extension
  path: string;
  
  // Browser this extension is for
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera';
  
  // User this extension is installed for
  user?: string;
  
  // Permissions requested by the extension
  permissions?: string[];
  
  // Extension metadata
  metadata?: Record<string, any>;
}

/**
 * Extension vulnerability information
 */
interface ExtensionVulnerability {
  // Extension ID
  extensionId: string;
  
  // Affected versions
  affectedVersions: string;
  
  // Vulnerability title
  title: string;
  
  // Detailed description
  description: string;
  
  // Severity
  severity: 'low' | 'medium' | 'high' | 'critical';
  
  // URL for more information
  infoUrl?: string;
  
  // Published date
  publishedDate?: Date;
  
  // Recommendation to fix
  recommendation?: string;
  
  // Whether the extension has been removed from the store
  removedFromStore?: boolean;
}

/**
 * Extension database with version and vulnerability information
 */
interface BrowserExtensionDatabase {
  // Map of extension ID to latest version info
  extensions: Record<string, {
    latestVersion: string;
    name: string;
    storeUrl?: string;
    isRemoved?: boolean;
  }>;
  
  // Map of extension ID to known vulnerabilities
  vulnerabilities: Record<string, ExtensionVulnerability[]>;
  
  // Last updated timestamp
  lastUpdated: Date;
}

/**
 * Scanner for detecting outdated or vulnerable browser extensions
 */
export async function scanBrowserExtensions(
  config: BrowserExtensionScannerConfig
): Promise<BrowserExtensionIssue[]> {
  try {
    log.info('Starting browser extension scanner');
    const issues: BrowserExtensionIssue[] = [];
    
    // Load extension database
    const extensionDb = await loadExtensionDatabase(config);
    
    log.info(`Loaded extension database with ${Object.keys(extensionDb.extensions).length} extensions`);
    
    // Get users to scan
    const users = config.users || [os.userInfo().username];
    
    // Scan extensions for each browser
    for (const browser of config.browsers) {
      try {
        log.info(`Scanning ${browser} extensions`);
        
        // Get installed extensions for this browser
        for (const user of users) {
          try {
            log.info(`Scanning ${browser} extensions for user ${user}`);
            
            const extensions = await getInstalledExtensions(browser, user);
            
            log.info(`Found ${extensions.length} installed ${browser} extensions for user ${user}`);
            
            // Check each extension
            for (const extension of extensions) {
              try {
                // Skip ignored extensions
                if (config.ignoreExtensions && config.ignoreExtensions.includes(extension.id)) {
                  log.info(`Skipping ignored extension: ${extension.id} (${extension.name})`);
                  continue;
                }
                
                // Skip extensions matching ignore patterns
                if (config.ignorePatterns && 
                    config.ignorePatterns.some(pattern => new RegExp(pattern).test(extension.id))) {
                  log.info(`Skipping extension matching ignore pattern: ${extension.id} (${extension.name})`);
                  continue;
                }
                
                // Get latest version information
                const latestInfo = extensionDb.extensions[extension.id];
                
                if (!latestInfo) {
                  log.info(`No version information found for extension: ${extension.id} (${extension.name})`);
                  continue;
                }
                
                // Check if outdated
                const isOutdated = compareVersions(extension.version, latestInfo.latestVersion) < 0;
                
                // Check if removed from store
                const isRemovedFromStore = latestInfo.isRemoved || false;
                
                // Get vulnerabilities
                let vulnerabilities: VulnerabilityInfo[] = [];
                let hasSecurityIssues = false;
                
                if (config.checkVulnerabilities) {
                  vulnerabilities = await getExtensionVulnerabilities(
                    extension.id, 
                    extension.version, 
                    extensionDb.vulnerabilities
                  );
                  hasSecurityIssues = vulnerabilities.length > 0;
                }
                
                // Skip if not outdated, not removed, and no vulnerabilities
                if (!isOutdated && !isRemovedFromStore && !hasSecurityIssues) {
                  log.info(`Extension ${extension.name} (${extension.id}) is current and has no issues`);
                  continue;
                }
                
                // Create issue
                const issue: BrowserExtensionIssue = {
                  name: extension.name,
                  id: extension.id,
                  currentVersion: extension.version,
                  latestVersion: latestInfo.latestVersion,
                  isOutdated,
                  browser: extension.browser,
                  isRemovedFromStore,
                  hasSecurityIssues,
                  storeUrl: latestInfo.storeUrl,
                  vulnerabilities,
                  detectedAt: new Date()
                };
                
                // Add to issues list
                issues.push(issue);
                log.info(`Added issue for extension ${extension.name} (${extension.id})`);
              } catch (extensionError) {
                log.warn(`Error processing extension: ${extension.id}`, { error: extensionError });
              }
            }
          } catch (userError) {
            log.warn(`Error scanning ${browser} extensions for user ${user}`, { error: userError });
          }
        }
      } catch (browserError) {
        log.error(`Error scanning ${browser} extensions`, { error: browserError });
      }
    }
    
    log.info(`Completed browser extension scanning. Found ${issues.length} total issues`);
    return issues;
  } catch (error) {
    log.error('Error during browser extension scanning', { error });
    return [];
  }
}

/**
 * Load the browser extension database
 */
async function loadExtensionDatabase(
  config: BrowserExtensionScannerConfig
): Promise<BrowserExtensionDatabase> {
  // In a real implementation, this would load from a file or API
  // For this example, we'll return a small hardcoded database
  
  return {
    extensions: {
      'react-developer-tools': {
        name: 'React Developer Tools',
        latestVersion: '4.28.0',
        storeUrl: 'https://chrome.google.com/webstore/detail/react-developer-tools/fmkadmapgofadopljbjfkapdkoienihi'
      },
      'redux-devtools': {
        name: 'Redux DevTools',
        latestVersion: '3.1.0',
        storeUrl: 'https://chrome.google.com/webstore/detail/redux-devtools/lmhkpmbekcpmknklioeibfkpmmfibljd'
      },
      'angular-devtools': {
        name: 'Angular DevTools',
        latestVersion: '1.0.6',
        storeUrl: 'https://chrome.google.com/webstore/detail/angular-devtools/ienfalfjdbdpebioblfackkekamfmbnh'
      },
      'vue-devtools': {
        name: 'Vue.js devtools',
        latestVersion: '6.5.0',
        storeUrl: 'https://chrome.google.com/webstore/detail/vuejs-devtools/nhdogjmejiglipccpnnnanhbledajbpd'
      },
      'unsafe-extension': {
        name: 'Unsafe Extension (Example)',
        latestVersion: '2.0.0',
        isRemoved: true
      }
    },
    vulnerabilities: {
      'unsafe-extension': [
        {
          extensionId: 'unsafe-extension',
          affectedVersions: '<2.0.0',
          title: 'Data Exfiltration Vulnerability',
          description: 'This extension contains a vulnerability that could allow attackers to exfiltrate sensitive data.',
          severity: 'critical',
          infoUrl: 'https://example.com/vulnerability',
          publishedDate: new Date('2023-01-15'),
          recommendation: 'Uninstall this extension immediately',
          removedFromStore: true
        }
      ]
    },
    lastUpdated: new Date()
  };
}

/**
 * Get installed extensions for a specific browser and user
 */
async function getInstalledExtensions(
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera',
  username: string
): Promise<BrowserExtension[]> {
  try {
    // Get platform-specific extension directories
    const extensionDirs = getBrowserExtensionDirectories(browser, username);
    
    const extensions: BrowserExtension[] = [];
    
    for (const dir of extensionDirs) {
      try {
        if (!fs.existsSync(dir)) {
          log.info(`Extension directory does not exist: ${dir}`);
          continue;
        }
        
        // For Chrome-based browsers
        if (['chrome', 'edge', 'opera'].includes(browser)) {
          const extensionFolders = await readdirAsync(dir);
          
          for (const extId of extensionFolders) {
            try {
              const extensionPath = path.join(dir, extId);
              const manifestPath = path.join(extensionPath, 'manifest.json');
              
              if (fs.existsSync(manifestPath)) {
                const manifestContent = await readFileAsync(manifestPath, 'utf8');
                const manifest = JSON.parse(manifestContent);
                
                extensions.push({
                  id: extId,
                  name: manifest.name || 'Unknown',
                  version: manifest.version || '0.0.0',
                  description: manifest.description,
                  enabled: true, // Assuming enabled by default
                  path: extensionPath,
                  browser,
                  user: username,
                  permissions: manifest.permissions,
                  metadata: {
                    manifestVersion: manifest.manifest_version
                  }
                });
              }
            } catch (extError) {
              log.warn(`Error processing extension: ${extId}`, { error: extError });
            }
          }
        }
        // For Firefox
        else if (browser === 'firefox') {
          // Firefox stores extensions in a more complex way
          // This is a simplified approach
          const extensionsIni = path.join(dir, 'extensions.json');
          
          if (fs.existsSync(extensionsIni)) {
            const iniContent = await readFileAsync(extensionsIni, 'utf8');
            const extensionsData = JSON.parse(iniContent);
            
            for (const addon of extensionsData.addons || []) {
              try {
                extensions.push({
                  id: addon.id,
                  name: addon.name || 'Unknown',
                  version: addon.version || '0.0.0',
                  description: addon.description,
                  enabled: addon.active,
                  path: addon.path,
                  browser,
                  user: username
                });
              } catch (addonError) {
                log.warn(`Error processing Firefox addon: ${addon.id}`, { error: addonError });
              }
            }
          }
        }
        // For Safari
        else if (browser === 'safari') {
          // Safari extensions are more complex to detect
          // This is a placeholder for a real implementation
          if (process.platform === 'darwin') {
            try {
              // On macOS, we could use the 'pluginkit' command
              const { stdout } = await execAsync('pluginkit -v')
              const lines = stdout.split('\n');
              
              // Process output to extract Safari extensions
              // This is a simplified example
              for (const line of lines) {
                if (line.includes('safari-extension://')) {
                  const match = line.match(/safari-extension:\/\/([^-]+)-([^/]+)/);
                  if (match) {
                    const [, name, version] = match;
                    const id = `safari-${name}`;
                    
                    extensions.push({
                      id,
                      name,
                      version,
                      enabled: true,
                      path: '',
                      browser,
                      user: username
                    });
                  }
                }
              }
            } catch (safariError) {
              log.warn('Error detecting Safari extensions', { error: safariError });
            }
          }
        }
      } catch (dirError) {
        log.warn(`Error processing extension directory: ${dir}`, { error: dirError });
      }
    }
    
    return extensions;
  } catch (error) {
    log.error(`Error getting installed ${browser} extensions`, { error });
    return [];
  }
}

/**
 * Get browser extension directories for a specific browser and user
 */
function getBrowserExtensionDirectories(
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera',
  username: string
): string[] {
  const platform = process.platform;
  const homeDir = os.homedir();
  
  if (platform === 'win32') {
    // Windows paths
    switch (browser) {
      case 'chrome':
        return [
          `C:\\Users\\${username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions`
        ];
      case 'firefox':
        return [
          `C:\\Users\\${username}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles`
        ];
      case 'edge':
        return [
          `C:\\Users\\${username}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Extensions`
        ];
      case 'opera':
        return [
          `C:\\Users\\${username}\\AppData\\Roaming\\Opera Software\\Opera Stable\\Extensions`
        ];
      case 'safari':
        return []; // Safari is not available on Windows
    }
  } else if (platform === 'darwin') {
    // macOS paths
    switch (browser) {
      case 'chrome':
        return [
          `${homeDir}/Library/Application Support/Google/Chrome/Default/Extensions`
        ];
      case 'firefox':
        return [
          `${homeDir}/Library/Application Support/Firefox/Profiles`
        ];
      case 'edge':
        return [
          `${homeDir}/Library/Application Support/Microsoft Edge/Default/Extensions`
        ];
      case 'opera':
        return [
          `${homeDir}/Library/Application Support/com.operasoftware.Opera/Extensions`
        ];
      case 'safari':
        return [
          `${homeDir}/Library/Safari/Extensions`,
          `${homeDir}/Library/Containers/com.apple.Safari/Data/Library/Safari/Extensions`
        ];
    }
  } else if (platform === 'linux') {
    // Linux paths
    switch (browser) {
      case 'chrome':
        return [
          `${homeDir}/.config/google-chrome/Default/Extensions`,
          `${homeDir}/.config/chromium/Default/Extensions`
        ];
      case 'firefox':
        return [
          `${homeDir}/.mozilla/firefox`
        ];
      case 'edge':
        return [
          `${homeDir}/.config/microsoft-edge/Default/Extensions`
        ];
      case 'opera':
        return [
          `${homeDir}/.config/opera/Extensions`
        ];
      case 'safari':
        return []; // Safari is not available on Linux
    }
  }
  
  return [];
}

/**
 * Get vulnerabilities for an extension version
 */
async function getExtensionVulnerabilities(
  extensionId: string,
  version: string,
  vulnerabilityDatabase: Record<string, ExtensionVulnerability[]>
): Promise<VulnerabilityInfo[]> {
  try {
    // Get vulnerabilities for this extension
    const extensionVulnerabilities = vulnerabilityDatabase[extensionId] || [];
    
    // Filter to those affecting this version
    const affectingVulnerabilities = extensionVulnerabilities.filter(v => {
      // Check if this version is in the affected range
      return v.affectedVersions.includes(version) || 
             (v.affectedVersions.includes('<') && compareVersions(version, v.affectedVersions.replace('<', '')) < 0);
    });
    
    // Map to VulnerabilityInfo format
    return affectingVulnerabilities.map(v => ({
      id: `${extensionId}-${v.title.replace(/\s+/g, '-').toLowerCase()}`,
      severity: v.severity,
      title: v.title,
      description: v.description,
      infoUrl: v.infoUrl,
      publishedDate: v.publishedDate,
      affectedVersions: v.affectedVersions,
      recommendation: v.recommendation
    }));
  } catch (error) {
    log.warn(`Error getting vulnerabilities for extension ${extensionId} ${version}`, { error });
    return [];
  }
}
