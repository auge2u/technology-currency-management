import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { glob } from 'glob';
import { exec } from 'child_process';
import { log } from '../utils/logging';
import { ExtensionIssue, ScannerConfig } from '../types/scanning';

const readFileAsync = promisify(fs.readFile);
const execAsync = promisify(exec);

/**
 * Configuration specific to browser extension scanning
 */
export interface ExtensionScannerConfig extends ScannerConfig {
  // Browser types to include in scan
  browsers?: Array<'chrome' | 'firefox' | 'safari' | 'edge'>;
  
  // Custom extension database paths
  extensionDbPaths?: {
    chrome?: string;
    firefox?: string;
    safari?: string;
    edge?: string;
  };
  
  // Whether to check for browser extension manifests in the codebase
  scanForManifests?: boolean;
  
  // Whether to scan for installed extensions on the system
  scanInstalledExtensions?: boolean;
  
  // Custom extensions to add to the scan
  customExtensions?: {
    id: string;
    name: string;
    version: string;
    browser: 'chrome' | 'firefox' | 'safari' | 'edge';
    manifestPath?: string;
  }[];
  
  // Whether to check extensions against vulnerability databases
  checkVulnerabilities?: boolean;
  
  // Restrict to particular extension categories
  categories?: string[];
  
  // Exclude certain extensions
  excludeExtensions?: string[];
}

/**
 * Information about a browser extension
 */
interface ExtensionInfo {
  id: string;
  name: string;
  version: string;
  browser: 'chrome' | 'firefox' | 'safari' | 'edge';
  manifestPath?: string;  // Path to manifest in codebase, if available
  updateUrl?: string;     // URL for updates, if available
  lastUpdated?: Date;     // If available
  category?: string;      // Extension category if known
  permissions?: string[]; // Requested permissions
  installType?: 'development' | 'normal' | 'sideloaded';
}

/**
 * Vulnerability information for an extension
 */
interface ExtensionVulnerabilityInfo {
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  cveIds?: string[];
  affectedVersions?: string;
  fixedInVersion?: string;
  url?: string;
}

/**
 * Result of checking an extension against databases
 */
interface ExtensionCheckResult {
  isOutdated: boolean;
  latestVersion?: string;
  isVulnerable: boolean;
  vulnerabilities: ExtensionVulnerabilityInfo[];
  hasCompatibilityIssues: boolean;
  compatibilityIssues: {
    type: 'api_deprecated' | 'browser_update_required' | 'permission_changes' | 'manifest_version';
    description: string;
    remediation?: string;
  }[];
  isDeprecated: boolean;
  deprecationDetails?: {
    deprecationDate?: Date;
    endOfSupportDate?: Date;
    reason?: string;
    alternatives?: string[];
  };
}

/**
 * Main function to scan browser extensions
 */
export async function scanExtensions(
  config: ExtensionScannerConfig
): Promise<ExtensionIssue[]> {
  try {
    log.info('Starting browser extension scanner');
    const issues: ExtensionIssue[] = [];
    
    // Determine which browsers to scan
    const browsers = config.browsers || ['chrome', 'firefox', 'safari', 'edge'];
    log.info(`Scanning for extension issues in browsers: ${browsers.join(', ')}`);
    
    // Get extensions from all sources
    const extensions = await collectExtensions(config, browsers);
    log.info(`Found ${extensions.length} browser extensions to analyze`);
    
    // Check each extension
    for (const ext of extensions) {
      try {
        // Skip excluded extensions
        if (config.excludeExtensions?.includes(ext.id) || 
            config.excludeExtensions?.includes(ext.name)) {
          continue;
        }
        
        // Skip extensions not in requested categories if categories specified
        if (config.categories && ext.category && 
            !config.categories.includes(ext.category)) {
          continue;
        }
        
        log.info(`Checking browser extension: ${ext.name} (${ext.id}) for ${ext.browser}`);
        
        // Check extension against databases
        const checkResult = await checkExtension(ext, config);
        
        // Create issues for problematic extensions
        if (checkResult.isOutdated || 
            checkResult.isVulnerable || 
            checkResult.hasCompatibilityIssues || 
            checkResult.isDeprecated) {
          
          const issue: ExtensionIssue = {
            detectedAt: new Date(),
            name: ext.name,
            id: ext.id,
            currentVersion: ext.version,
            latestVersion: checkResult.latestVersion,
            browser: ext.browser,
            isOutdated: checkResult.isOutdated,
            isVulnerable: checkResult.isVulnerable,
            vulnerabilities: checkResult.vulnerabilities,
            hasCompatibilityIssues: checkResult.hasCompatibilityIssues,
            compatibilityIssues: checkResult.compatibilityIssues,
            isDeprecated: checkResult.isDeprecated,
            deprecationDetails: checkResult.deprecationDetails,
            permissions: ext.permissions,
            manifestPath: ext.manifestPath,
            riskLevel: calculateRiskLevel(checkResult),
            recommendation: generateRecommendation(ext, checkResult),
            tags: generateTags(ext, checkResult)
          };
          
          issues.push(issue);
          log.info(`Added issue for extension ${ext.name}`);
        }
      } catch (extError) {
        log.error(`Error checking extension ${ext.name}`, { error: extError });
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
 * Collect extensions from various sources
 */
async function collectExtensions(
  config: ExtensionScannerConfig,
  browsers: Array<'chrome' | 'firefox' | 'safari' | 'edge'>
): Promise<ExtensionInfo[]> {
  const extensions: ExtensionInfo[] = [];
  
  // Add custom extensions from config
  if (config.customExtensions) {
    extensions.push(...config.customExtensions);
  }
  
  // Scan for extension manifests in the codebase if configured
  if (config.scanForManifests) {
    const manifestExtensions = await findExtensionManifests(config);
    extensions.push(...manifestExtensions);
  }
  
  // Scan for installed extensions on the system if configured
  if (config.scanInstalledExtensions) {
    for (const browser of browsers) {
      try {
        const installedExtensions = await getInstalledExtensions(browser, config);
        extensions.push(...installedExtensions);
      } catch (browserError) {
        log.warn(`Error getting installed extensions for ${browser}`, { error: browserError });
      }
    }
  }
  
  // Deduplicate extensions based on ID and browser
  const uniqueExtensions: ExtensionInfo[] = [];
  const seen = new Set<string>();
  
  for (const ext of extensions) {
    const key = `${ext.browser}:${ext.id}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniqueExtensions.push(ext);
    }
  }
  
  return uniqueExtensions;
}

/**
 * Find extension manifests in the codebase
 */
async function findExtensionManifests(
  config: ExtensionScannerConfig
): Promise<ExtensionInfo[]> {
  const extensions: ExtensionInfo[] = [];
  
  try {
    // Look for manifest files
    // Chrome/Edge use manifest.json
    // Firefox can use manifest.json or manifest.webapp
    // Safari uses Info.plist
    const manifestPatterns = [
      '**/manifest.json',
      '**/manifest.webapp',
      '**/Info.plist'
    ];
    
    let manifestPaths: string[] = [];
    
    for (const pattern of manifestPatterns) {
      const files = await glob(pattern, {
        cwd: config.rootDir,
        absolute: true,
        ignore: [...(config.excludePaths || []), '**/node_modules/**', '**/.git/**', '**/dist/**', '**/build/**']
      });
      manifestPaths.push(...files);
    }
    
    log.info(`Found ${manifestPaths.length} potential extension manifest files`);
    
    // Process each manifest file
    for (const manifestPath of manifestPaths) {
      try {
        const extension = await extractExtensionFromManifest(manifestPath);
        if (extension) {
          extensions.push(extension);
        }
      } catch (manifestError) {
        log.warn(`Error processing manifest at ${manifestPath}`, { error: manifestError });
      }
    }
  } catch (error) {
    log.error('Error finding extension manifests', { error });
  }
  
  return extensions;
}

/**
 * Extract extension information from a manifest file
 */
async function extractExtensionFromManifest(manifestPath: string): Promise<ExtensionInfo | null> {
  try {
    const content = await readFileAsync(manifestPath, 'utf8');
    const filename = path.basename(manifestPath).toLowerCase();
    
    // Chrome/Edge/Firefox manifest.json
    if (filename === 'manifest.json') {
      try {
        const manifest = JSON.parse(content);
        
        // Determine browser based on manifest properties
        let browser: 'chrome' | 'firefox' | 'edge' = 'chrome';
        
        // Firefox manifests often have browser_specific_settings or applications
        if (manifest.browser_specific_settings?.gecko || 
            manifest.applications?.gecko) {
          browser = 'firefox';
        } 
        // Edge manifests might have -ms-preload
        else if (manifest['-ms-preload']) {
          browser = 'edge';
        }
        
        // Minimum required properties
        if (!manifest.name || !manifest.version) {
          return null;
        }
        
        // Generate a reasonable ID if not present
        let id = manifest.applications?.gecko?.id || 
                 manifest.browser_specific_settings?.gecko?.id || 
                 manifest.key || 
                 `${manifest.name.replace(/\s+/g, '')}`;
        
        return {
          id,
          name: manifest.name,
          version: manifest.version,
          browser,
          manifestPath,
          updateUrl: manifest.update_url,
          permissions: manifest.permissions || [],
          installType: 'development',
          category: getExtensionCategory(manifest)
        };
      } catch (jsonError) {
        log.warn(`Error parsing JSON manifest at ${manifestPath}`, { error: jsonError });
        return null;
      }
    }
    // Firefox manifest.webapp
    else if (filename === 'manifest.webapp') {
      try {
        const manifest = JSON.parse(content);
        
        if (!manifest.name || !manifest.version) {
          return null;
        }
        
        return {
          id: manifest.origin || `${manifest.name.replace(/\s+/g, '')}`,
          name: manifest.name,
          version: manifest.version,
          browser: 'firefox',
          manifestPath,
          permissions: Object.keys(manifest.permissions || {}),
          installType: 'development',
          category: getExtensionCategory(manifest)
        };
      } catch (jsonError) {
        log.warn(`Error parsing webapp manifest at ${manifestPath}`, { error: jsonError });
        return null;
      }
    }
    // Safari Info.plist
    else if (filename === 'info.plist') {
      // Very basic plist parsing - a real implementation would use a proper XML parser
      const bundleIdMatch = content.match(/<key>CFBundleIdentifier<\/key>\s*<string>([^<]+)<\/string>/i);
      const nameMatch = content.match(/<key>CFBundleDisplayName<\/key>\s*<string>([^<]+)<\/string>/i);
      const versionMatch = content.match(/<key>CFBundleShortVersionString<\/key>\s*<string>([^<]+)<\/string>/i);
      
      if (nameMatch && versionMatch) {
        return {
          id: bundleIdMatch ? bundleIdMatch[1] : `safari-${nameMatch[1].replace(/\s+/g, '')}`,
          name: nameMatch[1],
          version: versionMatch[1],
          browser: 'safari',
          manifestPath,
          installType: 'development'
        };
      }
    }
    
    return null;
  } catch (error) {
    log.warn(`Error reading manifest file ${manifestPath}`, { error });
    return null;
  }
}

/**
 * Try to determine an extension's category from its manifest
 */
function getExtensionCategory(manifest: any): string | undefined {
  // Some extension manifests have a category field
  if (manifest.category) {
    return manifest.category;
  }
  
  // Try to infer category from permissions or description
  const permissions = manifest.permissions || [];
  const description = manifest.description || '';
  
  // Security/privacy related
  if (permissions.some(p => [
      'webNavigation', 'proxy', 'privacy', 'contentSettings',
      'declarativeNetRequest', 'host', 'vpn'
    ].includes(String(p))) || 
    /password|securit|privac|protect|firewall|vpn|antivirus/i.test(description)) {
    return 'security';
  }
  
  // Developer tools
  if (permissions.some(p => [
      'devtools', 'debugger', 'declarativeContent'
    ].includes(String(p))) || 
    /developer|debug|inspect|code|program/i.test(description)) {
    return 'developer';
  }
  
  // Productivity
  if (permissions.some(p => [
      'bookmarks', 'history', 'tabs', 'pageCapture', 'downloads'
    ].includes(String(p))) || 
    /productiv|bookmark|download|tab|task|todo|notes/i.test(description)) {
    return 'productivity';
  }
  
  // Content/Ad blocking
  if (permissions.some(p => [
      'declarativeNetRequest', 'webRequest', 'webRequestBlocking'
    ].includes(String(p))) || 
    /block|ad\s*block|content\s*block|filter/i.test(description)) {
    return 'content-blocker';
  }
  
  // Social
  if (/social|twitter|facebook|instagram|linkedin|share/i.test(description)) {
    return 'social';
  }
  
  return 'other';
}

/**
 * Get installed extensions for a specific browser
 */
async function getInstalledExtensions(
  browser: 'chrome' | 'firefox' | 'safari' | 'edge',
  config: ExtensionScannerConfig
): Promise<ExtensionInfo[]> {
  switch (browser) {
    case 'chrome':
      return getInstalledChromeExtensions(config);
    case 'firefox':
      return getInstalledFirefoxExtensions(config);
    case 'safari':
      return getInstalledSafariExtensions(config);
    case 'edge':
      return getInstalledEdgeExtensions(config);
    default:
      return [];
  }
}

/**
 * Get installed Chrome extensions
 */
async function getInstalledChromeExtensions(
  config: ExtensionScannerConfig
): Promise<ExtensionInfo[]> {
  const extensions: ExtensionInfo[] = [];
  
  try {
    // Chrome extension directory paths by OS
    let chromeDirs: string[] = [];
    
    if (process.platform === 'win32') {
      // Windows
      chromeDirs = [
        path.join(process.env.LOCALAPPDATA || '', 'Google/Chrome/User Data/Default/Extensions'),
        path.join(process.env.LOCALAPPDATA || '', 'Google/Chrome/User Data/Profile 1/Extensions'),
        path.join(process.env.LOCALAPPDATA || '', 'Google/Chrome/User Data/Profile 2/Extensions')
      ];
    } else if (process.platform === 'darwin') {
      // macOS
      chromeDirs = [
        path.join(process.env.HOME || '', 'Library/Application Support/Google/Chrome/Default/Extensions'),
        path.join(process.env.HOME || '', 'Library/Application Support/Google/Chrome/Profile 1/Extensions'),
        path.join(process.env.HOME || '', 'Library/Application Support/Google/Chrome/Profile 2/Extensions')
      ];
    } else if (process.platform === 'linux') {
      // Linux
      chromeDirs = [
        path.join(process.env.HOME || '', '.config/google-chrome/Default/Extensions'),
        path.join(process.env.HOME || '', '.config/google-chrome/Profile 1/Extensions'),
        path.join(process.env.HOME || '', '.config/google-chrome/Profile 2/Extensions')
      ];
    }
    
    // Process each Chrome directory
    for (const chromeDir of chromeDirs) {
      if (fs.existsSync(chromeDir)) {
        const extensionIds = await fs.promises.readdir(chromeDir).catch(() => []);
        
        for (const id of extensionIds) {
          const extDir = path.join(chromeDir, id);
          
          // Get version directories
          const versionDirs = await fs.promises.readdir(extDir).catch(() => []);
          
          if (versionDirs.length > 0) {
            // Get the latest version directory (assuming sorting works for version strings)
            const latestVersion = versionDirs.sort().pop() || '';
            const manifestPath = path.join(extDir, latestVersion, 'manifest.json');
            
            if (fs.existsSync(manifestPath)) {
              try {
                const manifest = JSON.parse(await readFileAsync(manifestPath, 'utf8'));
                
                extensions.push({
                  id,
                  name: manifest.name || id,
                  version: manifest.version || latestVersion,
                  browser: 'chrome',
                  manifestPath,
                  updateUrl: manifest.update_url,
                  permissions: manifest.permissions || [],
                  installType: manifest.update_url ? 'normal' : 'sideloaded',
                  category: getExtensionCategory(manifest)
                });
              } catch (err) {
                log.warn(`Error reading Chrome extension manifest at ${manifestPath}`, { error: err });
              }
            }
          }
        }
      }
    }
  } catch (error) {
    log.error('Error getting installed Chrome extensions', { error });
  }
  
  return extensions;
}

/**
 * Get installed Firefox extensions
 */
async function getInstalledFirefoxExtensions(
  config: ExtensionScannerConfig
): Promise<ExtensionInfo[]> {
  const extensions: ExtensionInfo[] = [];
  
  try {
    // Firefox extension directory paths by OS
    let firefoxDirs: string[] = [];
    
    if (process.platform === 'win32') {
      // Windows
      firefoxDirs = [
        path.join(process.env.APPDATA || '', 'Mozilla/Firefox/Profiles')
      ];
    } else if (process.platform === 'darwin') {
      // macOS
      firefoxDirs = [
        path.join(process.env.HOME || '', 'Library/Application Support/Firefox/Profiles')
      ];
    } else if (process.platform === 'linux') {
      // Linux
      firefoxDirs = [
        path.join(process.env.HOME || '', '.mozilla/firefox')
      ];
    }
    
    // Find all profile directories
    for (const ffBaseDir of firefoxDirs) {
      if (fs.existsSync(ffBaseDir)) {
        const profiles = await fs.promises.readdir(ffBaseDir).catch(() => []);
        
        for (const profile of profiles) {
          const profileDir = path.join(ffBaseDir, profile);
          const extensionsDir = path.join(profileDir, 'extensions');
          
          if (fs.existsSync(extensionsDir)) {
            const extFiles = await fs.promises.readdir(extensionsDir).catch(() => []);
            
            for (const file of extFiles) {
              // Firefox extensions can be XPI files (zip) or directories
              const extPath = path.join(extensionsDir, file);
              const stats = await fs.promises.stat(extPath).catch(() => null);
              
              if (stats?.isDirectory()) {
                // It's a directory - look for manifest.json
                const manifestPath = path.join(extPath, 'manifest.json');
                
                if (fs.existsSync(manifestPath)) {
                  try {
                    const manifest = JSON.parse(await readFileAsync(manifestPath, 'utf8'));
                    
                    const id = file; // The directory name is the extension ID
                    
                    extensions.push({
                      id,
                      name: manifest.name || id,
                      version: manifest.version || 'unknown',
                      browser: 'firefox',
                      manifestPath,
                      permissions: manifest.permissions || [],
                      installType: 'normal',
                      category: getExtensionCategory(manifest)
                    });
                  } catch (err) {
                    log.warn(`Error reading Firefox extension manifest at ${manifestPath}`, { error: err });
                  }
                }
              }
              // Reading XPI files would require additional zip handling libraries
            }
          }
        }
      }
    }
  } catch (error) {
    log.error('Error getting installed Firefox extensions', { error });
  }
  
  return extensions;
}

/**
 * Get installed Safari extensions
 */
async function getInstalledSafariExtensions(
  config: ExtensionScannerConfig
): Promise<ExtensionInfo[]> {
  const extensions: ExtensionInfo[] = [];
  
  // Safari extensions on macOS are now essentially Mac apps
  if (process.platform !== 'darwin') {
    return extensions;
  }
  
  try {
    // Main locations for Safari extensions
    const extensionDirs = [
      '/Applications/Safari Extensions',
      path.join(process.env.HOME || '', 'Library/Safari/Extensions')
    ];
    
    // For each potential directory
    for (const dir of extensionDirs) {
      if (fs.existsSync(dir)) {
        const files = await fs.promises.readdir(dir).catch(() => []);
        
        for (const file of files) {
          if (file.endsWith('.safariextz') || file.endsWith('.appex')) {
            const extPath = path.join(dir, file);
            
            // Instead of trying to extract the contents, we just use the filename info
            // A proper implementation would extract and parse the Info.plist
            const name = path.basename(file, path.extname(file));
            
            extensions.push({
              id: `safari-${name.toLowerCase().replace(/[^a-z0-9]/g, '')}`,
              name,
              version: 'unknown', // Would need extraction to get this
              browser: 'safari',
              installType: 'normal'
            });
          }
        }
      }
    }
    
    // For newer Safari App Extensions, use the macOS system_profiler
    try {
      const { stdout } = await execAsync('system_profiler SPSafariExtensionsDataType -json');
      const profileData = JSON.parse(stdout);
      
      if (profileData && 
          profileData.SPSafariExtensionsDataType && 
          profileData.SPSafariExtensionsDataType[0] && 
          profileData.SPSafariExtensionsDataType[0].extensions) {
        
        const safariExts = profileData.SPSafariExtensionsDataType[0].extensions;
        
        for (const ext of safariExts) {
          if (ext.name && ext.path) {
            extensions.push({
              id: `safari-${ext.name.toLowerCase().replace(/[^a-z0-9]/g, '')}`,
              name: ext.name,
              version: ext.version || 'unknown',
              browser: 'safari',
              installType: 'normal',
              lastUpdated: ext['last-modified'] ? new Date(ext['last-modified']) : undefined
            });
          }
        }
      }
    } catch (profileError) {
      log.warn('Error using system_profiler for Safari extensions', { error: profileError });
    }
  } catch (error) {
    log.error('Error getting installed Safari extensions', { error });
  }
  
  return extensions;
}

/**
 * Get installed Edge extensions
 */
async function getInstalledEdgeExtensions(
  config: ExtensionScannerConfig
): Promise<ExtensionInfo[]> {
  const extensions: ExtensionInfo[] = [];
  
  try {
    // Edge extension directory paths by OS
    let edgeDirs: string[] = [];
    
    if (process.platform === 'win32') {
      // Windows
      edgeDirs = [
        path.join(process.env.LOCALAPPDATA || '', 'Microsoft/Edge/User Data/Default/Extensions'),
        path.join(process.env.LOCALAPPDATA || '', 'Microsoft/Edge/User Data/Profile 1/Extensions')
      ];
    } else if (process.platform === 'darwin') {
      // macOS
      edgeDirs = [
        path.join(process.env.HOME || '', 'Library/Application Support/Microsoft Edge/Default/Extensions'),
        path.join(process.env.HOME || '', 'Library/Application Support/Microsoft Edge/Profile 1/Extensions')
      ];
    } else if (process.platform === 'linux') {
      // Linux
      edgeDirs = [
        path.join(process.env.HOME || '', '.config/microsoft-edge/Default/Extensions'),
        path.join(process.env.HOME || '', '.config/microsoft-edge/Profile 1/Extensions')
      ];
    }
    
    // Edge uses the same extension format as Chrome
    for (const edgeDir of edgeDirs) {
      if (fs.existsSync(edgeDir)) {
        const extensionIds = await fs.promises.readdir(edgeDir).catch(() => []);
        
        for (const id of extensionIds) {
          const extDir = path.join(edgeDir, id);
          
          // Get version directories
          const versionDirs = await fs.promises.readdir(extDir).catch(() => []);
          
          if (versionDirs.length > 0) {
            // Get the latest version directory
            const latestVersion = versionDirs.sort().pop() || '';
            const manifestPath = path.join(extDir, latestVersion, 'manifest.json');
            
            if (fs.existsSync(manifestPath)) {
              try {
                const manifest = JSON.parse(await readFileAsync(manifestPath, 'utf8'));
                
                extensions.push({
                  id,
                  name: manifest.name || id,
                  version: manifest.version || latestVersion,
                  browser: 'edge',
                  manifestPath,
                  updateUrl: manifest.update_url,
                  permissions: manifest.permissions || [],
                  installType: manifest.update_url ? 'normal' : 'sideloaded',
                  category: getExtensionCategory(manifest)
                });
              } catch (err) {
                log.warn(`Error reading Edge extension manifest at ${manifestPath}`, { error: err });
              }
            }
          }
        }
      }
    }
  } catch (error) {
    log.error('Error getting installed Edge extensions', { error });
  }
  
  return extensions;
}

/**
 * Check an extension against databases for issues
 */
async function checkExtension(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<ExtensionCheckResult> {
  try {
    // Default result
    const result: ExtensionCheckResult = {
      isOutdated: false,
      isVulnerable: false,
      vulnerabilities: [],
      hasCompatibilityIssues: false,
      compatibilityIssues: [],
      isDeprecated: false
    };
    
    // Check for latest version
    const latestVersionInfo = await getLatestExtensionVersion(ext, config);
    if (latestVersionInfo.isOutdated) {
      result.isOutdated = true;
      result.latestVersion = latestVersionInfo.latestVersion;
    }
    
    // Check for vulnerabilities if configured
    if (config.checkVulnerabilities) {
      const vulnerabilityInfo = await checkExtensionVulnerabilities(ext, config);
      
      if (vulnerabilityInfo.length > 0) {
        result.isVulnerable = true;
        result.vulnerabilities = vulnerabilityInfo;
      }
    }
    
    // Check for compatibility issues
    const compatibilityIssues = await checkExtensionCompatibility(ext, config);
    if (compatibilityIssues.length > 0) {
      result.hasCompatibilityIssues = true;
      result.compatibilityIssues = compatibilityIssues;
    }
    
    // Check if the extension is deprecated
    const deprecationInfo = await checkExtensionDeprecation(ext, config);
    if (deprecationInfo) {
      result.isDeprecated = true;
      result.deprecationDetails = deprecationInfo;
    }
    
    return result;
  } catch (checkError) {
    log.warn(`Error checking extension ${ext.name}`, { error: checkError });
    
    // Return default result on error
    return {
      isOutdated: false,
      isVulnerable: false,
      vulnerabilities: [],
      hasCompatibilityIssues: false,
      compatibilityIssues: [],
      isDeprecated: false
    };
  }
}

/**
 * Get the latest version of an extension
 */
async function getLatestExtensionVersion(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<{ isOutdated: boolean; latestVersion?: string }> {
  try {
    // Check based on browser type
    switch (ext.browser) {
      case 'chrome':
      case 'edge':
        return await getChromeWebStoreVersion(ext, config);
      case 'firefox':
        return await getFirefoxAddonVersion(ext, config);
      case 'safari':
        return await getSafariExtensionVersion(ext, config);
      default:
        return { isOutdated: false };
    }
  } catch (error) {
    log.warn(`Error getting latest version for extension ${ext.name}`, { error });
    return { isOutdated: false };
  }
}

/**
 * Get the latest version from Chrome Web Store
 */
async function getChromeWebStoreVersion(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<{ isOutdated: boolean; latestVersion?: string }> {
  // For a production system, you would use the Chrome Web Store API or scrape the web store page
  // Here we'll use a simple approach with a custom extension database
  
  try {
    // First check custom database if available
    const dbPath = config.extensionDbPaths?.chrome || config.extensionDbPaths?.edge;
    
    if (dbPath && fs.existsSync(dbPath)) {
      try {
        const db = JSON.parse(await readFileAsync(dbPath, 'utf8'));
        
        if (db[ext.id]) {
          const latestVersion = db[ext.id].version;
          
          if (latestVersion && ext.version !== 'unknown' && ext.version !== latestVersion) {
            return { isOutdated: true, latestVersion };
          }
          
          return { isOutdated: false, latestVersion };
        }
      } catch (dbError) {
        log.warn(`Error reading Chrome extension database`, { error: dbError });
      }
    }
    
    // If the extension has an update URL, we can assume it's maintained
    // A real implementation would actually check the update manifest
    if (ext.updateUrl) {
      // Just return not outdated since we can't easily check
      return { isOutdated: false };
    }
    
    // For complete implementation, you would use Chrome Web Store API or scraping
    
    return { isOutdated: false };
  } catch (error) {
    log.warn(`Error checking Chrome Web Store for ${ext.id}`, { error });
    return { isOutdated: false };
  }
}

/**
 * Get the latest version from Firefox Add-ons
 */
async function getFirefoxAddonVersion(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<{ isOutdated: boolean; latestVersion?: string }> {
  try {
    // First check custom database if available
    const dbPath = config.extensionDbPaths?.firefox;
    
    if (dbPath && fs.existsSync(dbPath)) {
      try {
        const db = JSON.parse(await readFileAsync(dbPath, 'utf8'));
        
        if (db[ext.id]) {
          const latestVersion = db[ext.id].version;
          
          if (latestVersion && ext.version !== 'unknown' && ext.version !== latestVersion) {
            return { isOutdated: true, latestVersion };
          }
          
          return { isOutdated: false, latestVersion };
        }
      } catch (dbError) {
        log.warn(`Error reading Firefox extension database`, { error: dbError });
      }
    }
    
    // For Firefox, we can try to use their API if we have a valid ID
    if (ext.id && ext.id.includes('@')) {
      try {
        const cmd = `curl -s "https://addons.mozilla.org/api/v5/addons/addon/${encodeURIComponent(ext.id)}/"`;
        const { stdout } = await execAsync(cmd);
        
        const addonInfo = JSON.parse(stdout);
        
        if (addonInfo && addonInfo.current_version && addonInfo.current_version.version) {
          const latestVersion = addonInfo.current_version.version;
          
          if (ext.version !== 'unknown' && ext.version !== latestVersion) {
            return { isOutdated: true, latestVersion };
          }
          
          return { isOutdated: false, latestVersion };
        }
      } catch (apiError) {
        // API request failed, just continue
        log.warn(`Error checking Firefox Add-ons API for ${ext.id}`, { error: apiError });
      }
    }
    
    return { isOutdated: false };
  } catch (error) {
    log.warn(`Error checking Firefox Add-ons for ${ext.id}`, { error });
    return { isOutdated: false };
  }
}

/**
 * Get the latest version for Safari extensions
 */
async function getSafariExtensionVersion(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<{ isOutdated: boolean; latestVersion?: string }> {
  try {
    // First check custom database if available
    const dbPath = config.extensionDbPaths?.safari;
    
    if (dbPath && fs.existsSync(dbPath)) {
      try {
        const db = JSON.parse(await readFileAsync(dbPath, 'utf8'));
        
        if (db[ext.id] || db[ext.name]) {
          const extInfo = db[ext.id] || db[ext.name];
          const latestVersion = extInfo.version;
          
          if (latestVersion && ext.version !== 'unknown' && ext.version !== latestVersion) {
            return { isOutdated: true, latestVersion };
          }
          
          return { isOutdated: false, latestVersion };
        }
      } catch (dbError) {
        log.warn(`Error reading Safari extension database`, { error: dbError });
      }
    }
    
    // Safari has no good public API for extensions
    // Would need to scrape the Mac App Store
    
    return { isOutdated: false };
  } catch (error) {
    log.warn(`Error checking Safari extensions for ${ext.id}`, { error });
    return { isOutdated: false };
  }
}

/**
 * Check for extension vulnerabilities
 */
async function checkExtensionVulnerabilities(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<ExtensionVulnerabilityInfo[]> {
  try {
    const vulnerabilities: ExtensionVulnerabilityInfo[] = [];
    
    // Check custom database if available
    const dbPath = config.extensionDbPaths?.[ext.browser];
    
    if (dbPath && fs.existsSync(dbPath)) {
      try {
        const db = JSON.parse(await readFileAsync(dbPath, 'utf8'));
        
        // Check for vulnerabilities in the database
        if (db[ext.id] && db[ext.id].vulnerabilities) {
          const vulns = db[ext.id].vulnerabilities;
          
          for (const vuln of vulns) {
            // Check if this version is affected
            if (isVersionAffected(ext.version, vuln.affected_versions || '*')) {
              vulnerabilities.push({
                severity: vuln.severity || 'medium',
                description: vuln.description || 'Vulnerability in extension',
                affectedVersions: vuln.affected_versions,
                fixedInVersion: vuln.fixed_in_version,
                url: vuln.more_info_url,
                cveIds: vuln.cve_ids
              });
            }
          }
        }
      } catch (dbError) {
        log.warn(`Error reading extension vulnerability database`, { error: dbError });
      }
    }
    
    // For high-risk permissions, add a potential vulnerability
    if (ext.permissions && ext.permissions.length > 0) {
      const highRiskPermissions = [
        'tabs', 'webRequest', 'webRequestBlocking', 'proxy', 
        'cookies', 'history', 'management', 'privacy', 
        'contentSettings', 'debugger', 'declarativeNetRequest',
        'declarativeNetRequestFeedback', 'declarativeWebRequest',
        'enterprise.platformKeys', 'networking.config', 'vpnProvider',
        'clipboardRead', 'clipboardWrite', 'geolocation', 
        'nativeMessaging', 'webNavigation', 'bookmarks',
        'host', // host permission for all sites
        '*://*/*', // all hosts
        'http://*/*', // all http sites
        'https://*/*' // all https sites
      ];
      
      const hasHighRiskPermissions = ext.permissions.some(p => {
        const perm = String(p);
        return highRiskPermissions.includes(perm) || 
               perm.includes('://') || // URL patterns
               perm.includes('<all_urls>'); // all URLs
      });
      
      if (hasHighRiskPermissions) {
        vulnerabilities.push({
          severity: 'medium',
          description: 'Extension requests high-risk permissions that could potentially be misused. Review extension trustworthiness.',
          url: 'https://developer.chrome.com/docs/extensions/mv3/permission_warnings/'
        });
      }
    }
    
    return vulnerabilities;
  } catch (error) {
    log.warn(`Error checking vulnerabilities for extension ${ext.name}`, { error });
    return [];
  }
}

/**
 * Check for extension compatibility issues
 */
async function checkExtensionCompatibility(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<{
  type: 'api_deprecated' | 'browser_update_required' | 'permission_changes' | 'manifest_version';
  description: string;
  remediation?: string;
}[]> {
  const compatibilityIssues: {
    type: 'api_deprecated' | 'browser_update_required' | 'permission_changes' | 'manifest_version';
    description: string;
    remediation?: string;
  }[] = [];
  
  try {
    // Need to read manifest to check for compatibility issues
    if (!ext.manifestPath || !fs.existsSync(ext.manifestPath)) {
      return [];
    }
    
    const manifest = JSON.parse(await readFileAsync(ext.manifestPath, 'utf8'));
    
    // Check manifest version
    if (ext.browser === 'chrome' || ext.browser === 'edge') {
      // Check for deprecated manifest V2
      if (manifest.manifest_version === 2) {
        compatibilityIssues.push({
          type: 'manifest_version',
          description: 'Extension uses Manifest V2, which is being deprecated in Chrome and Edge',
          remediation: 'Update extension to use Manifest V3 format before Chrome fully removes support for Manifest V2'
        });
      }
    }
    
    // Check for deprecated APIs
    const deprecatedApis: Record<string, { browser: string, alternative?: string }> = {
      'chrome.webRequest.onAuthRequired': { 
        browser: 'chrome', 
        alternative: 'declarativeNetRequest API' 
      },
      'chrome.webRequest.handlerBehaviorChanged': { 
        browser: 'chrome', 
        alternative: 'declarativeNetRequest API' 
      },
      'chrome.extension.getURL': { 
        browser: 'chrome', 
        alternative: 'chrome.runtime.getURL' 
      },
      'chrome.extension.onRequest': { 
        browser: 'chrome', 
        alternative: 'chrome.runtime.onMessage' 
      },
      'chrome.extension.onRequestExternal': { 
        browser: 'chrome', 
        alternative: 'chrome.runtime.onMessageExternal' 
      },
      'chrome.extension.sendRequest': { 
        browser: 'chrome', 
        alternative: 'chrome.runtime.sendMessage' 
      },
      'chrome.extension.connect': { 
        browser: 'chrome', 
        alternative: 'chrome.runtime.connect' 
      },
      'chrome.extension.onConnect': { 
        browser: 'chrome', 
        alternative: 'chrome.runtime.onConnect' 
      },
      'chrome.extension.onConnectExternal': { 
        browser: 'chrome', 
        alternative: 'chrome.runtime.onConnectExternal' 
      },
      'browser.downloads.onChanged.addListener': { 
        browser: 'firefox' 
      },
      'safari.extension.baseURI': { 
        browser: 'safari', 
        alternative: 'browser.runtime.getURL' 
      },
      'safari.extension.dispatchMessage': { 
        browser: 'safari', 
        alternative: 'browser.runtime.sendMessage' 
      }
    };
    
    // Only check for deprecated APIs if we have the manifest content available
    if (ext.manifestPath) {
      try {
        const content = await readFileAsync(ext.manifestPath, 'utf8');
        
        for (const [api, info] of Object.entries(deprecatedApis)) {
          if (info.browser === ext.browser && content.includes(api)) {
            compatibilityIssues.push({
              type: 'api_deprecated',
              description: `Extension uses deprecated API: ${api}`,
              remediation: info.alternative ? 
                `Replace with ${info.alternative}` : 
                'Update to use current APIs'
            });
          }
        }
      } catch (contentError) {
        log.warn(`Error reading extension manifest content for API check`, { error: contentError });
      }
    }
    
    // Check for permission changes (based on browser)
    if (ext.browser === 'chrome' && manifest.manifest_version === 2) {
      // Check for permissions that require changes in Manifest V3
      const v3ChangedPermissions = [
        'webRequestBlocking'
      ];
      
      const hasChangedPermissions = (manifest.permissions || []).some(
        (p: string) => v3ChangedPermissions.includes(p)
      );
      
      if (hasChangedPermissions) {
        compatibilityIssues.push({
          type: 'permission_changes',
          description: 'Extension uses permissions that are changing in Manifest V3',
          remediation: 'Update to use declarativeNetRequest API instead of webRequestBlocking'
        });
      }
    }
    
    return compatibilityIssues;
  } catch (error) {
    log.warn(`Error checking compatibility for extension ${ext.name}`, { error });
    return [];
  }
}

/**
 * Check if an extension has been deprecated
 */
async function checkExtensionDeprecation(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<{
  deprecationDate?: Date;
  endOfSupportDate?: Date;
  reason?: string;
  alternatives?: string[];
} | null> {
  try {
    // Check custom database if available
    const dbPath = config.extensionDbPaths?.[ext.browser];
    
    if (dbPath && fs.existsSync(dbPath)) {
      try {
        const db = JSON.parse(await readFileAsync(dbPath, 'utf8'));
        
        // Check for deprecation info in the database
        if (db[ext.id] && db[ext.id].deprecated === true) {
          return {
            deprecationDate: db[ext.id].deprecation_date ? new Date(db[ext.id].deprecation_date) : undefined,
            endOfSupportDate: db[ext.id].end_of_support_date ? new Date(db[ext.id].end_of_support_date) : undefined,
            reason: db[ext.id].deprecation_reason,
            alternatives: db[ext.id].alternatives
          };
        }
      } catch (dbError) {
        log.warn(`Error reading extension deprecation database`, { error: dbError });
      }
    }
    
    // Check last update date if available
    // Extensions not updated in a long time might be abandoned
    if (ext.lastUpdated) {
      const twoYearsAgo = new Date();
      twoYearsAgo.setFullYear(twoYearsAgo.getFullYear() - 2);
      
      if (ext.lastUpdated < twoYearsAgo) {
        return {
          reason: 'Extension has not been updated in over 2 years and may be abandoned',
          deprecationDate: ext.lastUpdated
        };
      }
    }
    
    // Handle known deprecated extensions
    const knownDeprecated: Record<string, { browser: string, reason: string, alternatives?: string[] }> = {
      // Examples of known deprecated extensions
      'adobe-flash-player': { 
        browser: 'chrome',
        reason: 'Adobe Flash is discontinued', 
        alternatives: ['HTML5 video'] 
      },
      'chrome-http2-indicator': { 
        browser: 'chrome', 
        reason: 'Chrome removed the Chrome Apps platform', 
        alternatives: ['Modern browser DevTools'] 
      },
      'firefox-multi-account-containers': { 
        browser: 'firefox', 
        reason: 'Functionality now built into Firefox', 
        alternatives: ['Firefox built-in containers'] 
      }
    };
    
    // Check if the extension is in our known deprecated list
    const normalizedId = ext.id.toLowerCase();
    if (knownDeprecated[normalizedId] && knownDeprecated[normalizedId].browser === ext.browser) {
      return {
        reason: knownDeprecated[normalizedId].reason,
        alternatives: knownDeprecated[normalizedId].alternatives
      };
    }
    
    return null;
  } catch (error) {
    log.warn(`Error checking deprecation for extension ${ext.name}`, { error });
    return null;
  }
}

/**
 * Calculate risk level for an extension issue
 */
function calculateRiskLevel(
  result: ExtensionCheckResult
): 'low' | 'medium' | 'high' | 'critical' {
  // Start with low risk
  let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
  
  // Prioritize vulnerabilities
  if (result.isVulnerable && result.vulnerabilities.length > 0) {
    // Use the highest vulnerability severity
    for (const vuln of result.vulnerabilities) {
      if (vuln.severity === 'critical') {
        return 'critical';
      } else if (vuln.severity === 'high' && riskLevel !== 'critical') {
        riskLevel = 'high';
      } else if (vuln.severity === 'medium' && riskLevel !== 'critical' && riskLevel !== 'high') {
        riskLevel = 'medium';
      }
    }
  }
  
  // Then consider deprecation
  if (result.isDeprecated) {
    // Deprecated extensions are at least medium risk
    if (riskLevel === 'low') riskLevel = 'medium';
    
    // If an end-of-support date is provided and it's in the past,
    // that's a higher risk
    if (result.deprecationDetails?.endOfSupportDate) {
      const eosDate = result.deprecationDetails.endOfSupportDate;
      const now = new Date();
      
      if (eosDate < now) {
        if (riskLevel === 'medium') riskLevel = 'high';
        
        // If it's been more than a year since end of support, it's critical
        const yearInMs = 365 * 24 * 60 * 60 * 1000;
        if (now.getTime() - eosDate.getTime() > yearInMs) {
          riskLevel = 'critical';
        }
      }
    }
  }
  
  // Consider compatibility issues
  if (result.hasCompatibilityIssues && result.compatibilityIssues.length > 0) {
    // Manifest version issues are becoming more urgent
    const hasManifestIssue = result.compatibilityIssues.some(i => i.type === 'manifest_version');
    
    if (hasManifestIssue) {
      if (riskLevel === 'low') riskLevel = 'medium';
      // If it's both deprecated and has manifest issues, that's high risk
      if (result.isDeprecated && riskLevel === 'medium') riskLevel = 'high';
    }
  }
  
  // Consider outdated status
  if (result.isOutdated) {
    // Being outdated alone is not high risk, but combined with other factors it can be
    if (result.isVulnerable || result.isDeprecated || result.hasCompatibilityIssues) {
      if (riskLevel === 'medium') riskLevel = 'high';
    }
  }
  
  return riskLevel;
}

/**
 * Generate tags for an extension issue
 */
function generateTags(
  ext: ExtensionInfo,
  result: ExtensionCheckResult
): string[] {
  const tags: string[] = [ext.browser];
  
  // Add category if available
  if (ext.category) {
    tags.push(`category:${ext.category}`);
  }
  
  // Add install type
  if (ext.installType) {
    tags.push(`install:${ext.installType}`);
  }
  
  // Add issue type tags
  if (result.isOutdated) {
    tags.push('outdated');
  }
  
  if (result.isVulnerable) {
    tags.push('vulnerable');
    
    // Add highest severity level
    let highestSeverity = 'low';
    for (const vuln of result.vulnerabilities) {
      if (vuln.severity === 'critical') {
        highestSeverity = 'critical';
        break;
      } else if (vuln.severity === 'high' && highestSeverity !== 'critical') {
        highestSeverity = 'high';
      } else if (vuln.severity === 'medium' && highestSeverity !== 'critical' && highestSeverity !== 'high') {
        highestSeverity = 'medium';
      }
    }
    tags.push(`vulnerability:${highestSeverity}`);
  }
  
  if (result.hasCompatibilityIssues) {
    tags.push('compatibility-issues');
    
    // Add specific compatibility issue types
    for (const issue of result.compatibilityIssues) {
      tags.push(`compatibility:${issue.type}`);
    }
  }
  
  if (result.isDeprecated) {
    tags.push('deprecated');
    
    // Add end-of-support tag if available
    if (result.deprecationDetails?.endOfSupportDate) {
      const eosDate = result.deprecationDetails.endOfSupportDate;
      const now = new Date();
      
      if (eosDate < now) {
        tags.push('end-of-support-passed');
      } else {
        tags.push('approaching-end-of-support');
      }
    }
  }
  
  // Add high-risk permission tags if applicable
  if (ext.permissions && ext.permissions.length > 0) {
    const highRiskPermissions = [
      'tabs', 'webRequest', 'webRequestBlocking', 'proxy', 
      'cookies', 'history', 'management', 'privacy', 
      'contentSettings', 'debugger', 'all_urls'
    ];
    
    for (const perm of ext.permissions) {
      if (highRiskPermissions.includes(String(perm))) {
        tags.push('high-risk-permissions');
        break;
      }
    }
  }
  
  return tags;
}

/**
 * Generate a recommendation for an extension issue
 */
function generateRecommendation(
  ext: ExtensionInfo,
  result: ExtensionCheckResult
): string {
  const recommendations: string[] = [];
  
  // Handle vulnerable extensions with highest priority
  if (result.isVulnerable) {
    recommendations.push(
      `The ${ext.browser} extension "${ext.name}" has ${result.vulnerabilities.length} security vulnerabilities.`
    );
    
    // Group vulnerabilities by severity for better readability
    const bySeverity: Record<string, ExtensionVulnerabilityInfo[]> = {};
    for (const vuln of result.vulnerabilities) {
      if (!bySeverity[vuln.severity]) {
        bySeverity[vuln.severity] = [];
      }
      bySeverity[vuln.severity].push(vuln);
    }
    
    // Report vulnerabilities from highest to lowest severity
    for (const severity of ['critical', 'high', 'medium', 'low']) {
      if (bySeverity[severity] && bySeverity[severity].length > 0) {
        recommendations.push(
          `${bySeverity[severity].length} ${severity} severity issues found:`
        );
        
        // List vulnerabilities at this severity
        for (const vuln of bySeverity[severity]) {
          let vulnDesc = `- ${vuln.description}`;
          
          if (vuln.cveIds && vuln.cveIds.length > 0) {
            vulnDesc += ` (${vuln.cveIds.join(', ')})`;
          }
          
          if (vuln.fixedInVersion) {
            vulnDesc += ` - Fixed in version ${vuln.fixedInVersion}`;
          }
          
          recommendations.push(vulnDesc);
        }
      }
    }
    
    // Recommend updating or removing
    if (result.latestVersion) {
      recommendations.push(
        `Update to version ${result.latestVersion} to resolve these security issues.`
      );
    } else {
      recommendations.push(
        `Consider removing this extension or replacing it with a secure alternative.`
      );
    }
  }
  
  // Handle deprecated extensions
  if (result.isDeprecated) {
    recommendations.push(
      `The ${ext.browser} extension "${ext.name}" is deprecated.`
    );
    
    if (result.deprecationDetails?.reason) {
      recommendations.push(`Reason: ${result.deprecationDetails.reason}`);
    }
    
    if (result.deprecationDetails?.endOfSupportDate) {
      const eosDate = result.deprecationDetails.endOfSupportDate;
      const dateString = eosDate.toISOString().split('T')[0];
      
      const now = new Date();
      if (eosDate < now) {
        recommendations.push(`This extension reached end-of-support on ${dateString}.`);
      } else {
        recommendations.push(`This extension will reach end-of-support on ${dateString}.`);
      }
    }
    
    if (result.deprecationDetails?.alternatives && result.deprecationDetails.alternatives.length > 0) {
      recommendations.push(
        `Recommended alternatives: ${result.deprecationDetails.alternatives.join(', ')}`
      );
    } else {
      recommendations.push(
        `Find and migrate to an actively maintained alternative extension.`
      );
    }
  }
  
  // Handle compatibility issues
  if (result.hasCompatibilityIssues) {
    recommendations.push(
      `The ${ext.browser} extension "${ext.name}" has compatibility issues:`
    );
    
    for (const issue of result.compatibilityIssues) {
      recommendations.push(`- ${issue.description}`);
      
      if (issue.remediation) {
        recommendations.push(`  Remediation: ${issue.remediation}`);
      }
    }
  }
  
  // Handle outdated extensions
  if (result.isOutdated && result.latestVersion) {
    // Only add this if not already covered by vulnerabilities or deprecation
    if (!result.isVulnerable && !result.isDeprecated) {
      recommendations.push(
        `The ${ext.browser} extension "${ext.name}" (${ext.version}) is outdated. Latest version is ${result.latestVersion}.`
      );
      
      recommendations.push(
        `Update to the latest version to receive bug fixes and enhancements.`
      );
    }
  }
  
  // If no specific recommendations were made, add generic advice
  if (recommendations.length === 0) {
    recommendations.push(
      `Review the ${ext.browser} extension "${ext.name}" for potential updates or replacements as part of regular maintenance.`
    );
  }
  
  return recommendations.join('\n');
}

/**
 * Check if a version is affected by a specified range
 * This is a simplified implementation
 */
function isVersionAffected(version: string, affectedVersions: string): boolean {
  if (version === 'unknown') {
    return true; // Assume unknown versions are affected
  }
  
  // Very simplified version check - in a real implementation use semver or similar
  if (affectedVersions === '*') {
    return true;
  }
  
  // Check exact version match
  if (affectedVersions === version) {
    return true;
  }
  
  // Check range using commas
  if (affectedVersions.includes(',')) {
    const versions = affectedVersions.split(',').map(v => v.trim());
    return versions.includes(version);
  }
  
  // Check range with operators (very simplified)
  // For proper implementation, use a version comparison library
  if (affectedVersions.startsWith('<=')) {
    const maxVersion = affectedVersions.substring(2);
    return version <= maxVersion;
  }
  
  if (affectedVersions.startsWith('<')) {
    const maxVersion = affectedVersions.substring(1);
    return version < maxVersion;
  }
  
  if (affectedVersions.startsWith('>=')) {
    const minVersion = affectedVersions.substring(2);
    return version >= minVersion;
  }
  
  if (affectedVersions.startsWith('>')) {
    const minVersion = affectedVersions.substring(1);
    return version > minVersion;
  }
  
  return false;
}

/**
 * Operating system utilities
 */
import * as os from 'os';