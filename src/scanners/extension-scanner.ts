import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { promisify } from 'util';
import { execFile } from 'child_process';
import { glob } from 'glob';
import { log } from '../utils/logging';
import { ExtensionIssue } from '../types/scanning';

const readFileAsync = promisify(fs.readFile);
const execFileAsync = promisify(execFile);

/**
 * Configuration for browser extension scanning
 */
export interface ExtensionScannerConfig {
  // Whether to scan Chrome extensions
  scanChrome: boolean;
  
  // Whether to scan Firefox extensions
  scanFirefox: boolean;
  
  // Whether to scan Edge extensions
  scanEdge: boolean;
  
  // Whether to scan Safari extensions
  scanSafari: boolean;
  
  // Custom extension directories to scan
  customExtensionDirs?: string[];
  
  // API timeout in milliseconds
  apiTimeoutMs: number;
  
  // Directory to store cached data
  cacheDir?: string;
  
  // Skip specific extensions by ID
  ignoreExtensions?: string[];
  
  // Organization-approved extensions
  approvedExtensions?: string[];
}

/**
 * Browser types supported by the scanner
 */
enum Browser {
  CHROME = 'chrome',
  FIREFOX = 'firefox',
  EDGE = 'edge',
  SAFARI = 'safari',
  UNKNOWN = 'unknown'
}

/**
 * Detected browser extension
 */
interface DetectedExtension {
  id: string;
  name: string;
  version: string;
  browser: Browser;
  path: string;
  detectedAt: Date;
  manifestVersion?: number;
  installedFromStore?: boolean;
  permissions?: string[];
  lastUpdated?: Date;
  description?: string;
  homepage?: string;
  author?: string;
}

/**
 * Extension information from repository or cache
 */
interface ExtensionInfo {
  latestVersion: string;
  isOutdated: boolean;
  isDeprecated: boolean;
  hasSecurityIssues: boolean;
  securityIssues?: Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    cve?: string;
  }>;
  store?: 'chrome_web_store' | 'firefox_addons' | 'edge_addons' | 'safari_extensions';
  storeUrl?: string;
  latestReleaseDate?: Date;
  reviewCount?: number;
  rating?: number;
  userCount?: number;
  homepage?: string;
  alternatives?: string[];
  compatibilityIssues?: string[];
  removedFromStore?: boolean;
  developerResponse?: string;
}

/**
 * Scanner for detecting browser extensions
 */
export async function scanExtensions(
  config: ExtensionScannerConfig
): Promise<ExtensionIssue[]> {
  try {
    log.info('Starting browser extension scanner');
    const issues: ExtensionIssue[] = [];
    
    // Detect extensions
    const extensions = await detectExtensions(config);
    log.info(`Found ${extensions.length} browser extensions`);
    
    // Check each extension
    for (const extension of extensions) {
      try {
        // Skip ignored extensions
        if (config.ignoreExtensions && config.ignoreExtensions.includes(extension.id)) {
          log.info(`Skipping ignored extension: ${extension.name} (${extension.id})`);
          continue;
        }
        
        // Get extension information
        const extensionInfo = await getExtensionInfo(
          extension.id,
          extension.version,
          extension.browser,
          config.apiTimeoutMs,
          config.cacheDir
        );
        
        // Only create an issue if there's at least one problem
        if (extensionInfo.isOutdated || extensionInfo.isDeprecated || extensionInfo.hasSecurityIssues || extensionInfo.removedFromStore || (extensionInfo.compatibilityIssues && extensionInfo.compatibilityIssues.length > 0)) {
          
          // Create the issue
          const issue: ExtensionIssue = {
            id: extension.id,
            name: extension.name,
            browser: extension.browser,
            currentVersion: extension.version,
            latestVersion: extensionInfo.latestVersion,
            path: extension.path,
            detectedAt: extension.detectedAt,
            isOutdated: extensionInfo.isOutdated,
            isDeprecated: extensionInfo.isDeprecated,
            hasSecurityIssues: extensionInfo.hasSecurityIssues,
            storeUrl: extensionInfo.storeUrl
          };
          
          // Add security issues if any
          if (extensionInfo.securityIssues?.length) {
            issue.securityIssues = extensionInfo.securityIssues;
          }
          
          // Add compatibility issues if any
          if (extensionInfo.compatibilityIssues?.length) {
            issue.compatibilityIssues = extensionInfo.compatibilityIssues;
          }
          
          // Check if approved
          issue.isApproved = config.approvedExtensions?.includes(extension.id) || false;
          
          // Add removed from store flag
          issue.removedFromStore = extensionInfo.removedFromStore || false;
          
          // Calculate risk level
          issue.riskLevel = calculateRiskLevel(
            extension,
            extensionInfo
          );
          
          // Calculate update urgency
          issue.updateUrgency = calculateUpdateUrgency(
            extension,
            extensionInfo
          );
          
          // Generate recommendation
          issue.recommendation = generateRecommendation(
            extension,
            extensionInfo,
            issue.isApproved
          );
          
          // Generate tags
          issue.tags = generateTags(
            extension,
            extensionInfo,
            issue.isApproved
          );
          
          // Add to issues list
          issues.push(issue);
          log.info(`Added issue for extension ${extension.name} ${extension.version}`);
        }
      } catch (extError) {
        log.warn(`Error processing extension: ${extension.name}`, { error: extError });
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
 * Detect browser extensions across supported browsers
 */
async function detectExtensions(
  config: ExtensionScannerConfig
): Promise<DetectedExtension[]> {
  try {
    const extensions: DetectedExtension[] = [];
    const platform = os.platform();
    
    // Scan Chrome extensions
    if (config.scanChrome) {
      const chromeExtensions = await detectChromeExtensions(platform);
      extensions.push(...chromeExtensions);
    }
    
    // Scan Firefox extensions
    if (config.scanFirefox) {
      const firefoxExtensions = await detectFirefoxExtensions(platform);
      extensions.push(...firefoxExtensions);
    }
    
    // Scan Edge extensions
    if (config.scanEdge) {
      const edgeExtensions = await detectEdgeExtensions(platform);
      extensions.push(...edgeExtensions);
    }
    
    // Scan Safari extensions
    if (config.scanSafari && platform === 'darwin') {
      const safariExtensions = await detectSafariExtensions();
      extensions.push(...safariExtensions);
    }
    
    // Scan custom extension directories
    if (config.customExtensionDirs?.length) {
      for (const customDir of config.customExtensionDirs) {
        const customExtensions = await detectCustomExtensions(customDir);
        extensions.push(...customExtensions);
      }
    }
    
    return extensions;
  } catch (error) {
    log.error('Error detecting extensions', { error });
    return [];
  }
}

/**
 * Detect Chrome extensions based on platform
 */
async function detectChromeExtensions(platform: string): Promise<DetectedExtension[]> {
  try {
    const extensions: DetectedExtension[] = [];
    let extensionPaths: string[] = [];
    
    // Find Chrome extension directories based on platform
    switch (platform) {
      case 'win32':
        extensionPaths = await glob(
          path.join(os.homedir(), 'AppData/Local/Google/Chrome/User Data/*/Extensions/*/*/*'),
          { ignore: ['**/Temp/**'] }
        );
        break;
      case 'darwin':
        extensionPaths = await glob(
          path.join(os.homedir(), 'Library/Application Support/Google/Chrome/*/Extensions/*/*/*'),
          { ignore: ['**/Temp/**'] }
        );
        break;
      case 'linux':
        extensionPaths = await glob(
          path.join(os.homedir(), '.config/google-chrome/*/Extensions/*/*/*'),
          { ignore: ['**/Temp/**'] }
        );
        break;
    }
    
    // Process each extension path
    for (const extensionPath of extensionPaths) {
      try {
        // Check for manifest.json
        const manifestPath = path.join(extensionPath, 'manifest.json');
        if (!fs.existsSync(manifestPath)) continue;
        
        // Parse manifest
        const manifestContent = await readFileAsync(manifestPath, 'utf8');
        const manifest = JSON.parse(manifestContent);
        
        if (manifest.name && manifest.version) {
          // Get extension ID from path (second to last segment)
          const pathSegments = extensionPath.split(path.sep);
          const extensionId = pathSegments[pathSegments.length - 3];
          
          extensions.push({
            id: extensionId,
            name: typeof manifest.name === 'string' ? manifest.name : `Chrome Extension ${extensionId}`,
            version: manifest.version,
            browser: Browser.CHROME,
            path: extensionPath,
            detectedAt: new Date(),
            manifestVersion: manifest.manifest_version,
            installedFromStore: true, // Assuming from store
            permissions: manifest.permissions,
            description: manifest.description,
            homepage: manifest.homepage_url,
            author: manifest.author
          });
          
          log.info(`Detected Chrome extension: ${manifest.name} v${manifest.version}`);
        }
      } catch (manifestError) {
        log.warn(`Error parsing Chrome extension manifest: ${extensionPath}`, { error: manifestError });
      }
    }
    
    return extensions;
  } catch (error) {
    log.error('Error detecting Chrome extensions', { error });
    return [];
  }
}

/**
 * Detect Firefox extensions based on platform
 */
async function detectFirefoxExtensions(platform: string): Promise<DetectedExtension[]> {
  try {
    const extensions: DetectedExtension[] = [];
    let profilesPath = '';
    
    // Find Firefox profiles path based on platform
    switch (platform) {
      case 'win32':
        profilesPath = path.join(os.homedir(), 'AppData/Roaming/Mozilla/Firefox/Profiles');
        break;
      case 'darwin':
        profilesPath = path.join(os.homedir(), 'Library/Application Support/Firefox/Profiles');
        break;
      case 'linux':
        profilesPath = path.join(os.homedir(), '.mozilla/firefox');
        break;
    }
    
    if (!fs.existsSync(profilesPath)) {
      log.info(`Firefox profiles directory not found: ${profilesPath}`);
      return [];
    }
    
    // Get all profile directories
    const profileDirs = fs.readdirSync(profilesPath)
      .map(name => path.join(profilesPath, name))
      .filter(dir => fs.statSync(dir).isDirectory());
    
    for (const profileDir of profileDirs) {
      try {
        // Check for extensions.json
        const extensionsJsonPath = path.join(profileDir, 'extensions.json');
        const extensionsPath = path.join(profileDir, 'extensions');
        
        // Process extensions.json if it exists
        if (fs.existsSync(extensionsJsonPath)) {
          const extensionsJsonContent = await readFileAsync(extensionsJsonPath, 'utf8');
          const extensionsData = JSON.parse(extensionsJsonContent);
          
          if (extensionsData.addons) {
            for (const addon of extensionsData.addons) {
              if (addon.id && addon.version) {
                extensions.push({
                  id: addon.id,
                  name: addon.name || addon.defaultLocale?.name || `Firefox Extension ${addon.id}`,
                  version: addon.version,
                  browser: Browser.FIREFOX,
                  path: addon.path || path.join(extensionsPath, addon.id),
                  detectedAt: new Date(),
                  installedFromStore: addon.installDate !== undefined,
                  lastUpdated: addon.updateDate ? new Date(addon.updateDate) : undefined,
                  description: addon.description || addon.defaultLocale?.description
                });
                
                log.info(`Detected Firefox extension: ${addon.name || addon.id} v${addon.version}`);
              }
            }
          }
        }
        
        // Also check the extensions directory for XPI files
        if (fs.existsSync(extensionsPath)) {
          const extensionFiles = fs.readdirSync(extensionsPath);
          
          for (const extFile of extensionFiles) {
            // Skip processing if it's already been detected via extensions.json
            if (extensions.some(ext => ext.id === extFile)) continue;
            
            // Check for unpacked extension with manifest
            const manifestPath = path.join(extensionsPath, extFile, 'manifest.json');
            if (fs.existsSync(manifestPath)) {
              try {
                const manifestContent = await readFileAsync(manifestPath, 'utf8');
                const manifest = JSON.parse(manifestContent);
                
                if (manifest.name && manifest.version) {
                  extensions.push({
                    id: extFile,
                    name: manifest.name,
                    version: manifest.version,
                    browser: Browser.FIREFOX,
                    path: path.join(extensionsPath, extFile),
                    detectedAt: new Date(),
                    manifestVersion: manifest.manifest_version,
                    permissions: manifest.permissions,
                    description: manifest.description,
                    homepage: manifest.homepage_url,
                    author: manifest.author
                  });
                  
                  log.info(`Detected Firefox extension: ${manifest.name} v${manifest.version}`);
                }
              } catch (manifestError) {
                log.warn(`Error parsing Firefox extension manifest: ${manifestPath}`, { error: manifestError });
              }
            }
          }
        }
      } catch (profileError) {
        log.warn(`Error processing Firefox profile: ${profileDir}`, { error: profileError });
      }
    }
    
    return extensions;
  } catch (error) {
    log.error('Error detecting Firefox extensions', { error });
    return [];
  }
}

/**
 * Detect Edge extensions based on platform
 */
async function detectEdgeExtensions(platform: string): Promise<DetectedExtension[]> {
  try {
    const extensions: DetectedExtension[] = [];
    let extensionPaths: string[] = [];
    
    // Find Edge extension directories based on platform
    switch (platform) {
      case 'win32':
        extensionPaths = await glob(
          path.join(os.homedir(), 'AppData/Local/Microsoft/Edge/User Data/*/Extensions/*/*/*'),
          { ignore: ['**/Temp/**'] }
        );
        break;
      case 'darwin':
        extensionPaths = await glob(
          path.join(os.homedir(), 'Library/Application Support/Microsoft Edge/*/Extensions/*/*/*'),
          { ignore: ['**/Temp/**'] }
        );
        break;
      case 'linux':
        extensionPaths = await glob(
          path.join(os.homedir(), '.config/microsoft-edge/*/Extensions/*/*/*'),
          { ignore: ['**/Temp/**'] }
        );
        break;
    }
    
    // Process each extension path
    for (const extensionPath of extensionPaths) {
      try {
        // Check for manifest.json
        const manifestPath = path.join(extensionPath, 'manifest.json');
        if (!fs.existsSync(manifestPath)) continue;
        
        // Parse manifest
        const manifestContent = await readFileAsync(manifestPath, 'utf8');
        const manifest = JSON.parse(manifestContent);
        
        if (manifest.name && manifest.version) {
          // Get extension ID from path (second to last segment)
          const pathSegments = extensionPath.split(path.sep);
          const extensionId = pathSegments[pathSegments.length - 3];
          
          extensions.push({
            id: extensionId,
            name: typeof manifest.name === 'string' ? manifest.name : `Edge Extension ${extensionId}`,
            version: manifest.version,
            browser: Browser.EDGE,
            path: extensionPath,
            detectedAt: new Date(),
            manifestVersion: manifest.manifest_version,
            installedFromStore: true, // Assuming from store
            permissions: manifest.permissions,
            description: manifest.description,
            homepage: manifest.homepage_url,
            author: manifest.author
          });
          
          log.info(`Detected Edge extension: ${manifest.name} v${manifest.version}`);
        }
      } catch (manifestError) {
        log.warn(`Error parsing Edge extension manifest: ${extensionPath}`, { error: manifestError });
      }
    }
    
    return extensions;
  } catch (error) {
    log.error('Error detecting Edge extensions', { error });
    return [];
  }
}

/**
 * Detect Safari extensions (macOS only)
 */
async function detectSafariExtensions(): Promise<DetectedExtension[]> {
  try {
    const extensions: DetectedExtension[] = [];
    
    // Safari extensions are located in the Extensions folder (macOS only)
    const safariExtensionsPath = path.join(os.homedir(), 'Library/Safari/Extensions');
    if (!fs.existsSync(safariExtensionsPath)) {
      log.info(`Safari extensions directory not found: ${safariExtensionsPath}`);
      
      // Also try to check Safari App Extensions
      const appExtensionsPath = path.join(os.homedir(), 'Library/Containers');
      if (!fs.existsSync(appExtensionsPath)) {
        return [];
      }
      
      try {
        // Try to list Safari app extensions using system_profiler
        const { stdout } = await execFileAsync('system_profiler', ['SPExtensionsDataType', '-json']);
        const extensionData = JSON.parse(stdout);
        
        if (extensionData['SPExtensionsDataType'] && Array.isArray(extensionData['SPExtensionsDataType'])) {
          for (const extGroup of extensionData['SPExtensionsDataType']) {
            if (extGroup['extensions'] && Array.isArray(extGroup['extensions'])) {
              for (const ext of extGroup['extensions']) {
                if (ext['safari_extension'] === 'enabled') {
                  extensions.push({
                    id: ext['bundleID'] || ext['bundle_id'] || ext['path'].split('/').pop() || 'unknown',
                    name: ext['name'] || 'Unknown Safari Extension',
                    version: ext['version'] || '0.0.0',
                    browser: Browser.SAFARI,
                    path: ext['path'] || '',
                    detectedAt: new Date(),
                    description: ext['info'] || undefined
                  });
                  
                  log.info(`Detected Safari extension: ${ext['name']} v${ext['version']}`);
                }
              }
            }
          }
        }
      } catch (profileError) {
        log.warn('Error getting Safari extensions from system_profiler', { error: profileError });
      }
      
      return extensions;
    }
    
    // List all .safariextz files
    const extFiles = fs.readdirSync(safariExtensionsPath)
      .filter(file => file.endsWith('.safariextz') || file.endsWith('.safariextension'));
    
    for (const extFile of extFiles) {
      try {
        const extPath = path.join(safariExtensionsPath, extFile);
        let extInfo: DetectedExtension | null = null;
        
        if (extFile.endsWith('.safariextension')) {
          // Unpacked extension - check for Info.plist
          const infoPlistPath = path.join(extPath, 'Info.plist');
          
          if (fs.existsSync(infoPlistPath)) {
            try {
              // Try to extract basic information from plist (this would require a plist parser)
              // For now, just capture basic information
              extInfo = {
                id: extFile.replace('.safariextension', ''),
                name: extFile.replace('.safariextension', ''),
                version: '0.0.0', // Would extract from plist
                browser: Browser.SAFARI,
                path: extPath,
                detectedAt: new Date()
              };
            } catch (plistError) {
              log.warn(`Error parsing Safari extension plist: ${infoPlistPath}`, { error: plistError });
            }
          }
        } else {
          // Packed extension - just record basic information
          extInfo = {
            id: extFile.replace('.safariextz', ''),
            name: extFile.replace('.safariextz', ''),
            version: '0.0.0', // Would need to unpack to extract
            browser: Browser.SAFARI,
            path: extPath,
            detectedAt: new Date()
          };
        }
        
        if (extInfo) {
          extensions.push(extInfo);
          log.info(`Detected Safari extension: ${extInfo.name}`);
        }
      } catch (extError) {
        log.warn(`Error processing Safari extension: ${extFile}`, { error: extError });
      }
    }
    
    return extensions;
  } catch (error) {
    log.error('Error detecting Safari extensions', { error });
    return [];
  }
}

/**
 * Detect extensions in custom directories
 */
async function detectCustomExtensions(customDir: string): Promise<DetectedExtension[]> {
  try {
    const extensions: DetectedExtension[] = [];
    
    if (!fs.existsSync(customDir)) {
      log.warn(`Custom extension directory not found: ${customDir}`);
      return [];
    }
    
    // Look for manifest.json files in subdirectories
    const manifestPaths = await glob(path.join(customDir, '**/manifest.json'));
    
    for (const manifestPath of manifestPaths) {
      try {
        const manifestContent = await readFileAsync(manifestPath, 'utf8');
        const manifest = JSON.parse(manifestContent);
        
        if (manifest.name && manifest.version) {
          // Try to determine browser type from manifest
          let browser = Browser.UNKNOWN;
          
          // Check for browser-specific manifest properties
          if (manifest.applications?.gecko) {
            browser = Browser.FIREFOX;
          } else if (manifest.background?.persistent === false) {
            browser = Browser.CHROME; // Could also be Edge, hard to tell
          } else if (manifest.background?.scripts && !manifest.background.persistent) {
            browser = Browser.EDGE;
          }
          
          // Generate an ID if none exists
          const id = manifest.applications?.gecko?.id || 
                     manifest.browser_specific_settings?.gecko?.id ||
                     `custom-${path.basename(path.dirname(manifestPath))}`;
          
          extensions.push({
            id,
            name: typeof manifest.name === 'string' ? manifest.name : `Extension ${id}`,
            version: manifest.version,
            browser,
            path: path.dirname(manifestPath),
            detectedAt: new Date(),
            manifestVersion: manifest.manifest_version,
            installedFromStore: false, // Custom location, likely not from store
            permissions: manifest.permissions,
            description: manifest.description,
            homepage: manifest.homepage_url,
            author: manifest.author
          });
          
          log.info(`Detected custom extension: ${manifest.name} v${manifest.version}`);
        }
      } catch (manifestError) {
        log.warn(`Error parsing custom extension manifest: ${manifestPath}`, { error: manifestError });
      }
    }
    
    return extensions;
  } catch (error) {
    log.error(`Error detecting extensions in custom directory: ${customDir}`, { error });
    return [];
  }
}

/**
 * Get extension information from repository or cache
 */
async function getExtensionInfo(
  id: string,
  version: string,
  browser: Browser,
  timeoutMs: number,
  cacheDir?: string
): Promise<ExtensionInfo> {
  // Check cache first
  if (cacheDir) {
    const cacheFile = path.join(cacheDir, `ext-${browser}-${id.replace(/[^a-z0-9]/gi, '-').toLowerCase()}.json`);
    
    if (fs.existsSync(cacheFile)) {
      try {
        const cacheContent = await readFileAsync(cacheFile, 'utf8');
        const cachedInfo = JSON.parse(cacheContent) as ExtensionInfo;
        log.info(`Loaded ${id} extension info from cache`);
        return cachedInfo;
      } catch (cacheError) {
        log.warn(`Error reading extension cache for ${id}`, { error: cacheError });
      }
    }
  }
  
  // In a real implementation, we would query extension stores
  // For this example, we'll use mock data
  try {
    log.info(`Querying info for extension: ${id} ${version} (${browser})`);
    
    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 50 + Math.random() * 200));
    
    // Generate latest version based on current version
    const latestVersion = incrementVersion(version);
    const isOutdated = compareVersions(latestVersion, version) > 0;
    
    // Generate store URL based on browser
    let storeUrl = '';
    let store: ExtensionInfo['store'] = undefined;
    
    switch (browser) {
      case Browser.CHROME:
        storeUrl = `https://chrome.google.com/webstore/detail/${id}`;
        store = 'chrome_web_store';
        break;
      case Browser.FIREFOX:
        storeUrl = `https://addons.mozilla.org/en-US/firefox/addon/${id}/`;
        store = 'firefox_addons';
        break;
      case Browser.EDGE:
        storeUrl = `https://microsoftedge.microsoft.com/addons/detail/${id}`;
        store = 'edge_addons';
        break;
      case Browser.SAFARI:
        storeUrl = `https://apps.apple.com/us/app/${id}`;
        store = 'safari_extensions';
        break;
    }
    
    // Generate mock data
    const info: ExtensionInfo = {
      latestVersion,
      isOutdated,
      isDeprecated: Math.random() < 0.1, // 10% chance of being deprecated
      hasSecurityIssues: Math.random() < 0.15, // 15% chance of having security issues
      store,
      storeUrl,
      latestReleaseDate: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000),
      reviewCount: Math.floor(Math.random() * 5000),
      rating: 3 + Math.random() * 2,
      userCount: Math.floor(Math.random() * 1000000),
      removedFromStore: Math.random() < 0.05 // 5% chance of being removed from store
    };
    
    // Add security issues if flagged
    if (info.hasSecurityIssues) {
      info.securityIssues = [
        {
          severity: getRandomSeverity(),
          description: `${getRandomVulnerabilityType()} vulnerability in extension`,
          cve: `CVE-${new Date().getFullYear()}-${Math.floor(Math.random() * 10000)}`
        }
      ];
    }
    
    // Add compatibility issues randomly
    if (Math.random() < 0.2) { // 20% chance
      info.compatibilityIssues = [
        getRandomCompatibilityIssue(browser)
      ];
    }
    
    // Suggest alternatives if deprecated
    if (info.isDeprecated) {
      info.alternatives = getRandomAlternatives(id, browser);
    }
    
    // Save to cache if cacheDir is provided
    if (cacheDir) {
      try {
        if (!fs.existsSync(cacheDir)) {
          fs.mkdirSync(cacheDir, { recursive: true });
        }
        
        const cacheFile = path.join(cacheDir, `ext-${browser}-${id.replace(/[^a-z0-9]/gi, '-').toLowerCase()}.json`);
        await fs.promises.writeFile(cacheFile, JSON.stringify(info, null, 2), 'utf8');
        log.info(`Cached ${id} extension info`);
      } catch (cacheError) {
        log.warn(`Error writing extension cache for ${id}`, { error: cacheError });
      }
    }
    
    return info;
  } catch (error) {
    log.error(`Error querying info for extension ${id}`, { error });
    
    // Return basic info if query fails
    return {
      latestVersion: version,
      isOutdated: false,
      isDeprecated: false,
      hasSecurityIssues: false
    };
  }
}

/**
 * Calculate risk level for an extension
 */
function calculateRiskLevel(
  extension: DetectedExtension,
  info: ExtensionInfo
): 'low' | 'medium' | 'high' | 'critical' {
  let riskScore = 0;
  
  // Security issues present the highest risk
  if (info.hasSecurityIssues) {
    const hasCritical = info.securityIssues?.some(issue => issue.severity === 'critical');
    const hasHigh = info.securityIssues?.some(issue => issue.severity === 'high');
    
    if (hasCritical) riskScore += 4;
    else if (hasHigh) riskScore += 3;
    else riskScore += 2;
  }
  
  // Removed from store is high risk
  if (info.removedFromStore) riskScore += 3;
  
  // Deprecated extensions are medium risk
  if (info.isDeprecated) riskScore += 2;
  
  // Outdated extensions have lower risk
  if (info.isOutdated) riskScore += 1;
  
  // Extensions with broad permissions are higher risk
  if (extension.permissions) {
    const highRiskPermissions = [
      'tabs', 'webNavigation', 'webRequest', 'cookies', 
      'storage', 'history', 'downloads', 'proxy',
      'clipboardWrite', 'clipboardRead', 'bookmarks',
      'geolocation', 'declarativeNetRequest'
    ];
    
    const highRiskCount = extension.permissions.filter(
      perm => highRiskPermissions.some(risk => perm.includes(risk))
    ).length;
    
    if (highRiskCount > 3) riskScore += 2;
    else if (highRiskCount > 0) riskScore += 1;
  }
  
  // Map score to risk level
  if (riskScore >= 4) return 'critical';
  if (riskScore >= 3) return 'high';
  if (riskScore >= 1) return 'medium';
  return 'low';
}

/**
 * Calculate update urgency for an extension
 */
function calculateUpdateUrgency(
  extension: DetectedExtension,
  info: ExtensionInfo
): 'low' | 'medium' | 'high' | 'critical' {
  let urgencyScore = 0;
  
  // Security issues require immediate updating
  if (info.hasSecurityIssues) {
    const hasCritical = info.securityIssues?.some(issue => issue.severity === 'critical');
    const hasHigh = info.securityIssues?.some(issue => issue.severity === 'high');
    
    if (hasCritical) urgencyScore += 4;
    else if (hasHigh) urgencyScore += 3;
    else urgencyScore += 2;
  }
  
  // Removed from store needs urgent attention
  if (info.removedFromStore) urgencyScore += 3;
  
  // Compatibility issues need addressing
  if (info.compatibilityIssues?.length) urgencyScore += 2;
  
  // Deprecated extensions should be updated soon
  if (info.isDeprecated) urgencyScore += 2;
  
  // Significantly outdated versions are more urgent
  if (info.isOutdated) {
    const versionDiff = calculateVersionDifference(extension.version, info.latestVersion);
    if (versionDiff.major > 1) urgencyScore += 2;
    else if (versionDiff.major === 1) urgencyScore += 1;
    else if (versionDiff.minor >= 5) urgencyScore += 1;
  }
  
  // Map score to urgency level
  if (urgencyScore >= 4) return 'critical';
  if (urgencyScore >= 3) return 'high';
  if (urgencyScore >= 1) return 'medium';
  return 'low';
}

/**
 * Generate a recommendation for an extension issue
 */
function generateRecommendation(
  extension: DetectedExtension,
  info: ExtensionInfo,
  isApproved: boolean
): string {
  const recommendations: string[] = [];
  
  if (info.hasSecurityIssues) {
    const highestSeverity = info.securityIssues?.reduce(
      (highest, current) => {
        const severityRank = { 'low': 1, 'medium': 2, 'high': 3, 'critical': 4 };
        const currentRank = severityRank[current.severity] || 0;
        const highestRank = severityRank[highest] || 0;
        return currentRank > highestRank ? current.severity : highest;
      },
      'low' as 'low' | 'medium' | 'high' | 'critical'
    );
    
    recommendations.push(
      `Update ${extension.name} immediately to fix ${highestSeverity} severity security ${info.securityIssues?.length === 1 ? 'issue' : 'issues'}`
    );
  } else if (info.removedFromStore) {
    recommendations.push(
      `Replace ${extension.name} as it has been removed from the ${getBrowserStoreName(extension.browser)} store`
    );
    
    if (info.alternatives?.length) {
      recommendations.push(
        `Consider these alternatives: ${info.alternatives.join(', ')}`
      );
    }
  } else if (info.isDeprecated) {
    if (info.alternatives?.length) {
      recommendations.push(
        `Replace deprecated extension ${extension.name} with one of the recommended alternatives: ${info.alternatives.join(', ')}`
      );
    } else {
      recommendations.push(
        `Find a replacement for deprecated extension ${extension.name}`
      );
    }
  } else if (info.compatibilityIssues?.length) {
    recommendations.push(
      `Update ${extension.name} to address compatibility issues: ${info.compatibilityIssues.join(', ')}`
    );
  } else if (info.isOutdated) {
    recommendations.push(
      `Update ${extension.name} from ${extension.version} to ${info.latestVersion}`
    );
  }
  
  // Add approval-related recommendation
  if (!isApproved) {
    recommendations.push(
      `Submit ${extension.name} for organizational approval`
    );
  }
  
  if (recommendations.length === 0) {
    recommendations.push(`No immediate action required for ${extension.name} ${extension.version}`);
  }
  
  return recommendations.join('. ');
}

/**
 * Generate tags for an extension issue
 */
function generateTags(
  extension: DetectedExtension,
  info: ExtensionInfo,
  isApproved: boolean
): string[] {
  const tags: string[] = [extension.browser];
  
  if (isApproved) {
    tags.push('approved');
  } else {
    tags.push('unapproved');
  }
  
  if (info.isOutdated) tags.push('outdated');
  if (info.isDeprecated) tags.push('deprecated');
  if (info.removedFromStore) tags.push('removed-from-store');
  
  // Add security tags
  if (info.hasSecurityIssues) {
    tags.push('security-issue');
    
    // Add tag for highest severity
    const severities = info.securityIssues?.map(v => v.severity) || [];
    if (severities.includes('critical')) tags.push('critical-severity');
    else if (severities.includes('high')) tags.push('high-severity');
    else if (severities.includes('medium')) tags.push('medium-severity');
    else if (severities.includes('low')) tags.push('low-severity');
  }
  
  // Add compatibility tag
  if (info.compatibilityIssues?.length) {
    tags.push('compatibility-issue');
  }
  
  // Add manifest version tag if available
  if (extension.manifestVersion) {
    tags.push(`manifest-v${extension.manifestVersion}`);
  }
  
  return tags;
}

/* ---- Helper Functions ---- */

/**
 * Increment a version for demonstration purposes
 */
function incrementVersion(version: string): string {
  try {
    const parts = version.split('.');
    
    if (parts.length < 3) {
      // Ensure we have at least 3 parts
      while (parts.length < 3) {
        parts.push('0');
      }
    }
    
    // Randomly decide which part to increment
    const random = Math.random();
    let incrementIndex = 2; // Default to patch increment
    
    if (random < 0.1) {
      // 10% chance of major version increment
      incrementIndex = 0;
    } else if (random < 0.3) {
      // 20% chance of minor version increment
      incrementIndex = 1;
    }
    
    // Increment the selected part
    parts[incrementIndex] = String(parseInt(parts[incrementIndex], 10) + 1);
    
    // Reset subsequent parts to 0
    for (let i = incrementIndex + 1; i < parts.length; i++) {
      parts[i] = '0';
    }
    
    return parts.join('.');
  } catch (error) {
    return `${version}.1`; // Fallback
  }
}

/**
 * Compare two version strings
 * Returns > 0 if version1 is greater, < 0 if version2 is greater, 0 if equal
 */
function compareVersions(version1: string, version2: string): number {
  const v1parts = version1.split('.').map(p => parseInt(p, 10) || 0);
  const v2parts = version2.split('.').map(p => parseInt(p, 10) || 0);
  
  // Ensure both arrays have the same length
  while (v1parts.length < v2parts.length) v1parts.push(0);
  while (v2parts.length < v1parts.length) v2parts.push(0);
  
  // Compare each part
  for (let i = 0; i < v1parts.length; i++) {
    if (v1parts[i] > v2parts[i]) return 1;
    if (v1parts[i] < v2parts[i]) return -1;
  }
  
  return 0;
}

/**
 * Calculate the difference between two versions
 */
function calculateVersionDifference(
  currentVersion: string,
  latestVersion: string
): { major: number, minor: number, patch: number } {
  const current = currentVersion.split('.').map(p => parseInt(p, 10) || 0);
  const latest = latestVersion.split('.').map(p => parseInt(p, 10) || 0);
  
  // Ensure both arrays have at least 3 elements
  while (current.length < 3) current.push(0);
  while (latest.length < 3) latest.push(0);
  
  return {
    major: Math.max(0, latest[0] - current[0]),
    minor: Math.max(0, latest[1] - current[1]),
    patch: Math.max(0, latest[2] - current[2])
  };
}

/**
 * Get a random severity level
 */
function getRandomSeverity(): 'low' | 'medium' | 'high' | 'critical' {
  const severities: Array<'low' | 'medium' | 'high' | 'critical'> = [
    'low', 'medium', 'high', 'critical'
  ];
  const weights = [0.3, 0.4, 0.2, 0.1]; // More medium and low than high and critical
  
  const random = Math.random();
  let sum = 0;
  
  for (let i = 0; i < weights.length; i++) {
    sum += weights[i];
    if (random < sum) {
      return severities[i];
    }
  }
  
  return 'medium'; // Default fallback
}

/**
 * Get a random vulnerability type
 */
function getRandomVulnerabilityType(): string {
  const types = [
    'data leakage',
    'code injection',
    'cross-site scripting',
    'privilege escalation',
    'API key exposure',
    'browser fingerprinting',
    'unencrypted data transfer',
    'excessive permission use',
    'malicious code insertion',
    'content script injection'
  ];
  return types[Math.floor(Math.random() * types.length)];
}

/**
 * Get a random compatibility issue
 */
function getRandomCompatibilityIssue(browser: Browser): string {
  const issues = [
    `Not compatible with the latest ${getBrowserName(browser)} version`,
    `Uses deprecated ${getBrowserName(browser)} APIs`,
    'Manifest version requires updating',
    'Permission model has changed',
    'Content security policy conflicts',
    'Background script model deprecated',
    'Uses unsupported features',
    'Incompatible with platform security changes'
  ];
  return issues[Math.floor(Math.random() * issues.length)];
}

/**
 * Get random alternatives for extensions
 */
function getRandomAlternatives(id: string, browser: Browser): string[] {
  // This would be powered by a real recommendation engine in production
  // Here we just generate some mock alternatives
  const count = 1 + Math.floor(Math.random() * 2);
  const alternatives = [];
  
  for (let i = 0; i < count; i++) {
    alternatives.push(`Alternative Extension ${i+1} for ${getBrowserName(browser)}`);
  }
  
  return alternatives;
}

/**
 * Get browser name from enum
 */
function getBrowserName(browser: Browser): string {
  switch (browser) {
    case Browser.CHROME: return 'Chrome';
    case Browser.FIREFOX: return 'Firefox';
    case Browser.EDGE: return 'Edge';
    case Browser.SAFARI: return 'Safari';
    default: return 'Unknown Browser';
  }
}

/**
 * Get browser store name
 */
function getBrowserStoreName(browser: Browser): string {
  switch (browser) {
    case Browser.CHROME: return 'Chrome Web Store';
    case Browser.FIREFOX: return 'Firefox Add-ons';
    case Browser.EDGE: return 'Edge Add-ons';
    case Browser.SAFARI: return 'Safari Extensions';
    default: return 'extension store';
  }
}
