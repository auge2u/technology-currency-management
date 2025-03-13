import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import * as child_process from 'child_process';
import * as os from 'os';
import { BrowserExtensionIssue, VulnerabilityInfo } from '../types/scanning';
import { log } from '../utils/logging';
import { compareVersions } from '../utils/scanner-utils';

const readFileAsync = promisify(fs.readFile);
const execAsync = promisify(child_process.exec);

/**
 * Configuration for extension scanning
 */
export interface ExtensionScannerConfig {
  // Which browsers to scan
  browsers: Array<'chrome' | 'firefox' | 'safari' | 'edge' | 'opera'>;
  
  // Whether to use offline mode (don't make API calls)
  offlineMode: boolean;
  
  // Whether to check for security vulnerabilities
  checkVulnerabilities: boolean;
  
  // Whether to check for compatibility issues
  checkCompatibility: boolean;
  
  // Whether to check store removal status
  checkStoreStatus: boolean;
  
  // Skip extensions with specific IDs
  ignoreExtensions?: string[];
  
  // API timeout in milliseconds
  apiTimeoutMs: number;
  
  // Directory to store extension data
  cacheDir?: string;
}

/**
 * Extension database record 
 */
interface ExtensionDbRecord {
  id: string;
  name: string;
  latestVersion: string;
  knownVulnerabilities: VulnerabilityInfo[];
  isDeprecated: boolean;
  removedFromStore: boolean;
  compatibilityIssues: {
    browser: string;
    version: string;
    issue: string;
  }[];
  alternativeExtensions?: {
    id: string;
    name: string;
    url: string;
  }[];
}

/**
 * Installed extension info
 */
interface InstalledExtension {
  id: string;
  name: string;
  version: string;
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera';
  path: string;
  enabled: boolean;
}

/**
 * Scanner for detecting outdated browser extensions
 */
export async function scanBrowserExtensions(
  config: ExtensionScannerConfig
): Promise<BrowserExtensionIssue[]> {
  try {
    log.info('Starting browser extension scanner');
    const issues: BrowserExtensionIssue[] = [];
    
    // Create extension database or load from cache
    const extensionDb = await getExtensionDatabase(config.cacheDir, config.offlineMode);
    
    // Scan extensions for each browser type
    for (const browser of config.browsers) {
      try {
        log.info(`Scanning ${browser} extensions`);
        
        // Get installed extensions
        const extensions = await getInstalledExtensions(browser);
        log.info(`Found ${extensions.length} ${browser} extensions`);
        
        // Check each extension
        for (const extension of extensions) {
          try {
            // Skip ignored extensions
            if (config.ignoreExtensions && config.ignoreExtensions.includes(extension.id)) {
              log.info(`Skipping ignored extension: ${extension.name} (${extension.id})`);
              continue;
            }
            
            // Check if extension exists in database
            const extRecord = extensionDb.find(e => e.id === extension.id);
            
            if (!extRecord) {
              log.info(`Extension not found in database: ${extension.name} (${extension.id})`);
              
              // If not in offline mode, try to fetch info
              if (!config.offlineMode) {
                try {
                  const fetchedInfo = await fetchExtensionInfo(extension.id, browser);
                  if (fetchedInfo) {
                    // Add to database for future runs
                    extensionDb.push(fetchedInfo);
                  }
                } catch (fetchError) {
                  log.warn(`Error fetching extension info: ${extension.name}`, { error: fetchError });
                }
              }
              
              continue;
            }
            
            // Check if extension is outdated
            const isOutdated = compareVersions(extension.version, extRecord.latestVersion) < 0;
            
            // Check for various issues
            const isDeprecated = extRecord.isDeprecated;
            const isRemovedFromStore = extRecord.removedFromStore;
            
            // Check for compatibility issues
            const compatibilityIssues = extRecord.compatibilityIssues.filter(issue => 
              issue.browser === browser
            );
            
            // Only create an issue if there's at least one problem
            if (isOutdated || isDeprecated || isRemovedFromStore || compatibilityIssues.length > 0 || 
                (config.checkVulnerabilities && extRecord.knownVulnerabilities.length > 0)) {
              
              // Create the issue
              const issue: BrowserExtensionIssue = {
                name: extension.name,
                id: extension.id,
                browser,
                currentVersion: extension.version,
                latestVersion: extRecord.latestVersion,
                isOutdated,
                isDeprecated,
                isRemovedFromStore,
                hasSecurityIssues: extRecord.knownVulnerabilities.length > 0,
                location: extension.path,
                detectedAt: new Date(),
                storeUrl: getStoreUrl(extension.id, browser)
              };
              
              // Add vulnerability info if any exist
              if (extRecord.knownVulnerabilities.length > 0) {
                issue.vulnerabilities = extRecord.knownVulnerabilities;
                issue.securityImpact = Math.max(...extRecord.knownVulnerabilities.map(v => 
                  securityImpactFromSeverity(v.severity)));
              }
              
              // Generate recommendation
              issue.recommendation = generateRecommendation(
                extension,
                extRecord,
                isOutdated,
                isDeprecated,
                isRemovedFromStore,
                compatibilityIssues.length > 0,
                extRecord.knownVulnerabilities.length > 0
              );
              
              // Add to issues list
              issues.push(issue);
              log.info(`Added issue for extension ${extension.name} (${extension.id})`);
            }
          } catch (extError) {
            log.warn(`Error processing extension: ${extension.name}`, { error: extError });
          }
        }
      } catch (browserError) {
        log.error(`Error scanning ${browser} extensions`, { error: browserError });
      }
    }
    
    // If not in offline mode and we have a cache dir, save updated extension database
    if (!config.offlineMode && config.cacheDir) {
      try {
        await saveExtensionDatabase(extensionDb, config.cacheDir);
      } catch (saveError) {
        log.warn('Error saving extension database', { error: saveError });
      }
    }
    
    log.info(`Completed extension scanning. Found ${issues.length} total issues`);
    return issues;
  } catch (error) {
    log.error('Error during extension scanning', { error });
    return [];
  }
}

/**
 * Get installed extensions for a specific browser
 */
async function getInstalledExtensions(
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera'
): Promise<InstalledExtension[]> {
  try {
    const platform = os.platform();
    const extensions: InstalledExtension[] = [];
    
    // Different browsers store extensions in different locations based on OS
    let extensionsPath = '';
    
    // Get browser profile/extensions directory
    if (platform === 'win32') {
      const appDataPath = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
      const localAppDataPath = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
      
      switch (browser) {
        case 'chrome':
          extensionsPath = path.join(localAppDataPath, 'Google', 'Chrome', 'User Data', 'Default', 'Extensions');
          break;
        case 'firefox':
          extensionsPath = path.join(appDataPath, 'Mozilla', 'Firefox', 'Profiles');
          break;
        case 'edge':
          extensionsPath = path.join(localAppDataPath, 'Microsoft', 'Edge', 'User Data', 'Default', 'Extensions');
          break;
        case 'opera':
          extensionsPath = path.join(appDataPath, 'Opera Software', 'Opera Stable', 'Extensions');
          break;
        default:
          throw new Error(`Unsupported browser: ${browser}`);
      }
    } else if (platform === 'darwin') {
      const homedir = os.homedir();
      
      switch (browser) {
        case 'chrome':
          extensionsPath = path.join(homedir, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Extensions');
          break;
        case 'firefox':
          extensionsPath = path.join(homedir, 'Library', 'Application Support', 'Firefox', 'Profiles');
          break;
        case 'safari':
          extensionsPath = path.join(homedir, 'Library', 'Safari', 'Extensions');
          break;
        case 'edge':
          extensionsPath = path.join(homedir, 'Library', 'Application Support', 'Microsoft Edge', 'Default', 'Extensions');
          break;
        case 'opera':
          extensionsPath = path.join(homedir, 'Library', 'Application Support', 'com.operasoftware.Opera', 'Extensions');
          break;
        default:
          throw new Error(`Unsupported browser: ${browser}`);
      }
    } else if (platform === 'linux') {
      const homedir = os.homedir();
      
      switch (browser) {
        case 'chrome':
          extensionsPath = path.join(homedir, '.config', 'google-chrome', 'Default', 'Extensions');
          break;
        case 'firefox':
          extensionsPath = path.join(homedir, '.mozilla', 'firefox');
          break;
        case 'edge':
          extensionsPath = path.join(homedir, '.config', 'microsoft-edge', 'Default', 'Extensions');
          break;
        case 'opera':
          extensionsPath = path.join(homedir, '.config', 'opera', 'Extensions');
          break;
        default:
          throw new Error(`Unsupported browser: ${browser}`);
      }
    } else {
      throw new Error(`Unsupported operating system: ${platform}`);
    }
    
    // Check if extensions directory exists
    if (!fs.existsSync(extensionsPath)) {
      log.info(`Extensions directory not found: ${extensionsPath}`);
      return [];
    }
    
    // Extract extensions based on browser
    if (browser === 'firefox') {
      // Firefox has a more complex structure
      let profileDirs = fs.readdirSync(extensionsPath);
      
      for (const profileDir of profileDirs) {
        const profilePath = path.join(extensionsPath, profileDir);
        const extensionsDirPath = path.join(profilePath, 'extensions');
        
        if (fs.existsSync(extensionsDirPath) && fs.statSync(extensionsDirPath).isDirectory()) {
          const extNames = fs.readdirSync(extensionsDirPath);
          
          for (const extName of extNames) {
            try {
              const extPath = path.join(extensionsDirPath, extName);
              
              if (fs.statSync(extPath).isFile() && extName.endsWith('.xpi')) {
                // Parse XPI name to get ID and version (if possible)
                const parts = extName.split('-');
                const id = parts[0];
                const version = parts[1] ? parts[1].replace('.xpi', '') : 'unknown';
                
                extensions.push({
                  id,
                  name: id, // We don't have the name without parsing the XPI
                  version,
                  browser,
                  path: extPath,
                  enabled: true // Assuming installed means enabled
                });
              }
            } catch (extError) {
              log.warn(`Error processing Firefox extension: ${extName}`, { error: extError });
            }
          }
        }
      }
    } else if (browser === 'safari') {
      // Safari extensions are bundled differently
      const extFiles = fs.readdirSync(extensionsPath);
      
      for (const extFile of extFiles) {
        try {
          if (extFile.endsWith('.safariextz')) {
            const extPath = path.join(extensionsPath, extFile);
            const extName = extFile.replace('.safariextz', '');
            
            // We'd need to parse the extension bundle to get more details
            extensions.push({
              id: extName,
              name: extName,
              version: 'unknown', // Need to parse the bundle
              browser,
              path: extPath,
              enabled: true // Assuming installed means enabled
            });
          }
        } catch (extError) {
          log.warn(`Error processing Safari extension: ${extFile}`, { error: extError });
        }
      }
    } else {
      // Chrome, Edge, Opera have similar directory structures
      const extIds = fs.readdirSync(extensionsPath);
      
      for (const extId of extIds) {
        try {
          const extPath = path.join(extensionsPath, extId);
          
          if (fs.statSync(extPath).isDirectory()) {
            // Get version directories
            const versionDirs = fs.readdirSync(extPath);
            
            if (versionDirs.length > 0) {
              // Sort version directories to get the latest
              const latestVersion = versionDirs.sort(compareVersions).pop() || 'unknown';
              const manifestPath = path.join(extPath, latestVersion, 'manifest.json');
              
              if (fs.existsSync(manifestPath)) {
                const manifestContent = await readFileAsync(manifestPath, 'utf8');
                const manifest = JSON.parse(manifestContent);
                
                extensions.push({
                  id: extId,
                  name: manifest.name || extId,
                  version: manifest.version || latestVersion,
                  browser,
                  path: path.join(extPath, latestVersion),
                  enabled: true // Assuming installed means enabled
                });
              }
            }
          }
        } catch (extError) {
          log.warn(`Error processing ${browser} extension: ${extId}`, { error: extError });
        }
      }
    }
    
    return extensions;
  } catch (error) {
    log.error(`Error getting installed ${browser} extensions`, { error });
    return [];
  }
}

/**
 * Get extension database (either from cache or create a new one)
 */
async function getExtensionDatabase(
  cacheDir?: string,
  offlineMode: boolean = false
): Promise<ExtensionDbRecord[]> {
  // Check for cached database
  if (cacheDir && fs.existsSync(cacheDir)) {
    const dbPath = path.join(cacheDir, 'extension-database.json');
    
    if (fs.existsSync(dbPath)) {
      try {
        const dbContent = await readFileAsync(dbPath, 'utf8');
        const db = JSON.parse(dbContent) as ExtensionDbRecord[];
        log.info(`Loaded extension database from cache with ${db.length} entries`);
        return db;
      } catch (readError) {
        log.warn('Error reading extension database from cache', { error: readError });
      }
    }
  }
  
  // If we're in offline mode and couldn't load from cache, return empty database
  if (offlineMode) {
    log.info('Offline mode enabled and no cache found, using empty extension database');
    return [];
  }
  
  // Otherwise, create a new database with some known problematic extensions
  log.info('Creating new extension database');
  return [
    {
      id: 'hdokiejnpimakedhajhdlcegeplioahd', // LastPass
      name: 'LastPass: Free Password Manager',
      latestVersion: '4.99.0',
      knownVulnerabilities: [],
      isDeprecated: false,
      removedFromStore: false,
      compatibilityIssues: []
    },
    {
      id: 'cjpalhdlnbpafiamejdnhcphjbkeiagm', // uBlock Origin
      name: 'uBlock Origin',
      latestVersion: '1.51.0',
      knownVulnerabilities: [],
      isDeprecated: false,
      removedFromStore: false,
      compatibilityIssues: []
    },
    {
      id: 'gighmmpiobklfepjocnamgkkbiglidom', // AdBlock
      name: 'AdBlock — best ad blocker',
      latestVersion: '5.12.0',
      knownVulnerabilities: [],
      isDeprecated: false,
      removedFromStore: false,
      compatibilityIssues: []
    },
    {
      id: 'nkbihfbeogaeaoehlefnkodbefgpgknn', // MetaMask
      name: 'MetaMask',
      latestVersion: '10.35.1',
      knownVulnerabilities: [],
      isDeprecated: false,
      removedFromStore: false,
      compatibilityIssues: []
    },
    {
      id: 'fbeffbjdlemaoicjdapfpochpgogmeoh', // Deprecated Example
      name: 'Deprecated Extension',
      latestVersion: '1.0.0',
      knownVulnerabilities: [],
      isDeprecated: true,
      removedFromStore: true,
      compatibilityIssues: [
        {
          browser: 'chrome',
          version: '100',
          issue: 'No longer compatible with Chrome v100+'
        }
      ],
      alternativeExtensions: [
        {
          id: 'cjpalhdlnbpafiamejdnhcphjbkeiagm',
          name: 'Better Alternative',
          url: 'https://chrome.google.com/webstore/detail/cjpalhdlnbpafiamejdnhcphjbkeiagm'
        }
      ]
    },
    {
      id: 'kmendfapggjehodndflmmgagdbamhnfd', // Vulnerable Example
      name: 'Vulnerable Extension',
      latestVersion: '2.0.0',
      knownVulnerabilities: [
        {
          id: 'CVE-2023-1234',
          severity: 'high',
          title: 'Data Exfiltration Vulnerability',
          description: 'This extension has a vulnerability that allows attackers to steal user data.',
          infoUrl: 'https://example.com/cve-2023-1234',
          publishedDate: new Date('2023-01-15'),
          recommendation: 'Update to the latest version or uninstall this extension'
        }
      ],
      isDeprecated: false,
      removedFromStore: false,
      compatibilityIssues: []
    }
  ];
}

/**
 * Save extension database to cache
 */
async function saveExtensionDatabase(
  database: ExtensionDbRecord[],
  cacheDir: string
): Promise<void> {
  try {
    // Create cache directory if it doesn't exist
    if (!fs.existsSync(cacheDir)) {
      fs.mkdirSync(cacheDir, { recursive: true });
    }
    
    const dbPath = path.join(cacheDir, 'extension-database.json');
    await fs.promises.writeFile(dbPath, JSON.stringify(database, null, 2), 'utf8');
    log.info(`Saved extension database to ${dbPath}`);
  } catch (error) {
    log.error('Error saving extension database', { error });
    throw error;
  }
}

/**
 * Fetch extension information from store
 */
async function fetchExtensionInfo(
  extensionId: string,
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera'
): Promise<ExtensionDbRecord | null> {
  // In a real implementation, this would query the browser extension stores
  // For this example, we'll just return null
  log.info(`Fetching extension info for ${extensionId} (${browser})`);
  return null;
}

/**
 * Get store URL for an extension
 */
function getStoreUrl(
  extensionId: string,
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera'
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
 * Generate a recommendation for addressing an extension issue
 */
function generateRecommendation(
  extension: InstalledExtension,
  extRecord: ExtensionDbRecord,
  isOutdated: boolean,
  isDeprecated: boolean,
  isRemovedFromStore: boolean,
  hasCompatibilityIssues: boolean,
  hasVulnerabilities: boolean
): string {
  const recommendations: string[] = [];
  
  if (isOutdated) {
    recommendations.push(`Update ${extension.name} from ${extension.version} to ${extRecord.latestVersion}`);
  }
  
  if (isDeprecated || isRemovedFromStore) {
    if (extRecord.alternativeExtensions && extRecord.alternativeExtensions.length > 0) {
      const alternative = extRecord.alternativeExtensions[0];
      recommendations.push(`Replace ${extension.name} with ${alternative.name} (${alternative.url})`);
    } else {
      recommendations.push(`Uninstall deprecated extension ${extension.name}`);
    }
  }
  
  if (hasCompatibilityIssues) {
    recommendations.push(`Address compatibility issues with ${extension.name}`);
  }
  
  if (hasVulnerabilities) {
    recommendations.push(`Immediately update or remove ${extension.name} due to security vulnerabilities`);
  }
  
  // Return combined recommendations
  return recommendations.join('. ');
}

/**
 * Convert severity to a numeric security impact score
 */
function securityImpactFromSeverity(severity: 'low' | 'medium' | 'high' | 'critical'): number {
  switch (severity) {
    case 'critical': return 5;
    case 'high': return 4;
    case 'medium': return 3;
    case 'low': return 2;
    default: return 1;
  }
}
