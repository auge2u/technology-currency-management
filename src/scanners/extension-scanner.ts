import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { promisify } from 'util';
import { exec } from 'child_process';
import { glob } from 'glob';
import { log } from '../utils/logging';
import { ExtensionIssue, ScannerConfig } from '../types/scanning';

const readFileAsync = promisify(fs.readFile);
const execAsync = promisify(exec);

/**
 * Configuration specific to browser extension scanning
 */
export interface ExtensionScannerConfig extends ScannerConfig {
  // Types of browsers to scan
  browsers?: Array<
    | 'chrome'
    | 'firefox'
    | 'safari'
    | 'edge'
    | 'brave'
    | 'opera'
  >;
  
  // Whether to check for security vulnerabilities
  checkVulnerabilities?: boolean;
  
  // Whether to check permissions
  checkPermissions?: boolean;
  
  // Whether to check for compatibility issues
  checkCompatibility?: boolean;
  
  // Whether to check if the extension is maintained
  checkMaintained?: boolean;
  
  // Whether to check for deprecated APIs
  checkDeprecatedApis?: boolean;
  
  // Whether to check for extension replacements or alternatives
  checkAlternatives?: boolean;
  
  // Maximum age of an extension update in days before flagging
  maxUpdateAge?: number;
  
  // Custom vulnerability database paths
  vulnerabilityDbPaths?: {
    extensions?: string;
  };
  
  // Extensions to exclude from scanning
  excludeExtensions?: string[];

  // Whether to include enterprise-managed extensions
  includeEnterpriseManaged?: boolean;
  
  // Paths to browser profiles (if non-standard)
  browserProfilePaths?: {
    chrome?: string;
    firefox?: string;
    safari?: string;
    edge?: string;
    brave?: string;
    opera?: string;
  };
}

/**
 * Information about a browser extension
 */
interface ExtensionInfo {
  id: string;
  name: string;
  version: string;
  browser: string;
  manifestVersion: number;
  description?: string;
  permissions?: string[];
  optionalPermissions?: string[];
  hostPermissions?: string[];
  installType?: 'normal' | 'development' | 'sideload' | 'admin' | 'unknown';
  installedPath?: string;
  manifestPath?: string;
  manifestContent?: any;
  homepageUrl?: string;
  updateUrl?: string;
  latestVersion?: string;
  latestReleaseDate?: Date;
  isOutdated?: boolean;
  isVulnerable?: boolean;
  isDeprecated?: boolean;
  isCompatibilityIssue?: boolean;
  isNotMaintained?: boolean;
  hasExcessivePermissions?: boolean;
  usesDeprecatedApis?: boolean;
  recommandedAlternative?: string;
  author?: string;
  installDate?: Date;
  lastUpdateDate?: Date;
  storeUrl?: string;
  vulnerabilities?: {
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    affectedVersions?: string;
    fixedInVersion?: string;
    url?: string;
    cveIds?: string[];
  }[];
  compatibilityIssues?: {
    browserVersion: string;
    description: string;
    impact: 'low' | 'medium' | 'high';
  }[];
  deprecatedApis?: {
    api: string;
    deprecatedSince: string;
    alternatives?: string;
    removalTimeline?: string;
  }[];
  permissionConcerns?: {
    permission: string;
    level: 'low' | 'medium' | 'high';
    description: string;
  }[];
}

/**
 * Main function to scan for browser extensions
 */
export async function scanExtensions(
  config: ExtensionScannerConfig
): Promise<ExtensionIssue[]> {
  try {
    log.info('Starting browser extension scanner');
    const issues: ExtensionIssue[] = [];
    
    // Determine which browsers to scan
    const browsers = config.browsers || [
      'chrome', 'firefox', 'safari', 'edge', 'brave', 'opera'
    ];
    log.info(`Scanning for extensions in browsers: ${browsers.join(', ')}`);
    
    // Scan for all extensions
    const extensions: ExtensionInfo[] = [];
    
    // Chrome extensions
    if (browsers.includes('chrome')) {
      try {
        log.info('Scanning for Chrome extensions');
        const chromeExtensions = await scanChromeExtensions(config);
        extensions.push(...chromeExtensions);
        log.info(`Found ${chromeExtensions.length} Chrome extensions`);
      } catch (chromeError) {
        log.error('Error scanning Chrome extensions', { error: chromeError });
      }
    }
    
    // Firefox extensions
    if (browsers.includes('firefox')) {
      try {
        log.info('Scanning for Firefox extensions');
        const firefoxExtensions = await scanFirefoxExtensions(config);
        extensions.push(...firefoxExtensions);
        log.info(`Found ${firefoxExtensions.length} Firefox extensions`);
      } catch (firefoxError) {
        log.error('Error scanning Firefox extensions', { error: firefoxError });
      }
    }
    
    // Safari extensions
    if (browsers.includes('safari')) {
      try {
        log.info('Scanning for Safari extensions');
        const safariExtensions = await scanSafariExtensions(config);
        extensions.push(...safariExtensions);
        log.info(`Found ${safariExtensions.length} Safari extensions`);
      } catch (safariError) {
        log.error('Error scanning Safari extensions', { error: safariError });
      }
    }
    
    // Edge extensions
    if (browsers.includes('edge')) {
      try {
        log.info('Scanning for Edge extensions');
        const edgeExtensions = await scanEdgeExtensions(config);
        extensions.push(...edgeExtensions);
        log.info(`Found ${edgeExtensions.length} Edge extensions`);
      } catch (edgeError) {
        log.error('Error scanning Edge extensions', { error: edgeError });
      }
    }
    
    // Brave extensions
    if (browsers.includes('brave')) {
      try {
        log.info('Scanning for Brave extensions');
        const braveExtensions = await scanBraveExtensions(config);
        extensions.push(...braveExtensions);
        log.info(`Found ${braveExtensions.length} Brave extensions`);
      } catch (braveError) {
        log.error('Error scanning Brave extensions', { error: braveError });
      }
    }
    
    // Opera extensions
    if (browsers.includes('opera')) {
      try {
        log.info('Scanning for Opera extensions');
        const operaExtensions = await scanOperaExtensions(config);
        extensions.push(...operaExtensions);
        log.info(`Found ${operaExtensions.length} Opera extensions`);
      } catch (operaError) {
        log.error('Error scanning Opera extensions', { error: operaError });
      }
    }
    
    log.info(`Found total of ${extensions.length} extensions to analyze`);
    
    // Filter out excluded extensions
    let filteredExtensions = extensions;
    if (config.excludeExtensions && config.excludeExtensions.length > 0) {
      filteredExtensions = filteredExtensions.filter(ext => {
        return !config.excludeExtensions!.some(excluded => {
          if (excluded === ext.id || excluded === ext.name) {
            return true;
          }
          if (excluded.includes('*')) {
            const pattern = excluded.replace(/\*/g, '.*');
            return new RegExp(`^${pattern}$`).test(ext.name);
          }
          return false;
        });
      });
      log.info(`Filtered out excluded extensions, ${filteredExtensions.length} remaining`);
    }
    
    // Process each extension
    for (const ext of filteredExtensions) {
      try {
        log.info(`Checking extension: ${ext.name} (${ext.id}) v${ext.version} for ${ext.browser}`);
        
        // Check for issues
        await checkExtensionForIssues(ext, config);
        
        // Create issue for problematic extensions
        if (ext.isOutdated || 
            ext.isVulnerable || 
            ext.isDeprecated || 
            ext.isCompatibilityIssue || 
            ext.isNotMaintained ||
            ext.hasExcessivePermissions ||
            ext.usesDeprecatedApis) {
          
          const issue: ExtensionIssue = {
            detectedAt: new Date(),
            id: ext.id,
            name: ext.name,
            version: ext.version,
            browser: ext.browser,
            manifestVersion: ext.manifestVersion,
            description: ext.description,
            installType: ext.installType,
            installedPath: ext.installedPath,
            permissions: ext.permissions,
            optionalPermissions: ext.optionalPermissions,
            hostPermissions: ext.hostPermissions,
            homepageUrl: ext.homepageUrl,
            updateUrl: ext.updateUrl,
            storeUrl: ext.storeUrl,
            latestVersion: ext.latestVersion,
            isOutdated: ext.isOutdated || false,
            isVulnerable: ext.isVulnerable || false,
            vulnerabilities: ext.vulnerabilities || [],
            isDeprecated: ext.isDeprecated || false,
            isCompatibilityIssue: ext.isCompatibilityIssue || false,
            compatibilityIssues: ext.compatibilityIssues,
            isNotMaintained: ext.isNotMaintained || false,
            lastUpdateDate: ext.lastUpdateDate,
            hasExcessivePermissions: ext.hasExcessivePermissions || false,
            permissionConcerns: ext.permissionConcerns,
            usesDeprecatedApis: ext.usesDeprecatedApis || false,
            deprecatedApis: ext.deprecatedApis,
            recommandedAlternative: ext.recommandedAlternative,
            author: ext.author,
            installDate: ext.installDate,
            riskLevel: calculateRiskLevel(ext),
            recommendation: generateRecommendation(ext),
            tags: generateTags(ext)
          };
          
          issues.push(issue);
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
 * Scan for Chrome extensions
 */
async function scanChromeExtensions(
  config: ExtensionScannerConfig
): Promise<ExtensionInfo[]> {
  const extensions: ExtensionInfo[] = [];
  
  try {
    // Determine Chrome profile path based on platform
    let chromePath: string;
    const platform = os.platform();
    
    if (config.browserProfilePaths?.chrome) {
      chromePath = config.browserProfilePaths.chrome;
    } else if (platform === 'win32') {
      const userDataDir = path.join(os.homedir(), 'AppData', 'Local', 'Google', 'Chrome', 'User Data');
      chromePath = path.join(userDataDir, 'Default');
    } else if (platform === 'darwin') {
      chromePath = path.join(os.homedir(), 'Library', 'Application Support', 'Google', 'Chrome', 'Default');
    } else if (platform === 'linux') {
      chromePath = path.join(os.homedir(), '.config', 'google-chrome', 'Default');
    } else {
      throw new Error(`Unsupported platform: ${platform}`);
    }
    
    // Find all profiles directories
    const profileDirs = [chromePath];
    
    // Find other profiles if any (Profile 1, Profile 2, etc.)
    const userDataDir = path.dirname(chromePath);
    try {
      const items = fs.readdirSync(userDataDir);
      for (const item of items) {
        if (item.startsWith('Profile ') && fs.statSync(path.join(userDataDir, item)).isDirectory()) {
          profileDirs.push(path.join(userDataDir, item));
        }
      }
    } catch (profileError) {
      log.warn('Error finding Chrome profiles', { error: profileError });
    }
    
    // Process each profile
    for (const profileDir of profileDirs) {
      log.debug(`Processing Chrome profile at ${profileDir}`);
      
      // Load the Preferences file to get extension info
      const preferencesPath = path.join(profileDir, 'Preferences');
      
      try {
        const content = await readFileAsync(preferencesPath, 'utf8');
        const preferences = JSON.parse(content);
        
        // extensions key may be at different places depending on Chrome version
        const extensionsData = preferences.extensions?.settings || preferences.extensions?.installations || {};
        
        // Iterate through installed extensions
        for (const [id, data] of Object.entries(extensionsData)) {
          // Skip entry if it's not an extension
          if (!id || id === 'theme' || id.startsWith('_')) {
            continue;
          }
          
          // Skip if no path (might be a removed extension)
          if (!data.path) {
            continue;
          }
          
          // Skip enterprise extensions if not included
          if (data.install_type === 'admin' && !config.includeEnterpriseManaged) {
            continue;
          }
          
          try {
            // Find the extension directory
            const extDir = path.join(userDataDir, data.path);
            
            // Read the manifest file for extension details
            const manifestPath = path.join(extDir, 'manifest.json');
            
            if (!fs.existsSync(manifestPath)) {
              continue; // Skip if manifest doesn't exist
            }
            
            const manifestContent = JSON.parse(await readFileAsync(manifestPath, 'utf8'));
            
            const extension: ExtensionInfo = {
              id,
              name: manifestContent.name || id,
              version: manifestContent.version || 'unknown',
              browser: 'chrome',
              manifestVersion: manifestContent.manifest_version || 2,
              description: manifestContent.description,
              permissions: manifestContent.permissions || [],
              optionalPermissions: manifestContent.optional_permissions || [],
              hostPermissions: manifestContent.host_permissions || [],
              installType: data.install_type || 'unknown',
              installedPath: extDir,
              manifestPath,
              manifestContent,
              homepageUrl: manifestContent.homepage_url,
              updateUrl: manifestContent.update_url,
              storeUrl: `https://chrome.google.com/webstore/detail/${id}`,
              author: manifestContent.author
            };
            
            // Try to get install/update dates from filesystem
            try {
              const stats = fs.statSync(extDir);
              extension.installDate = stats.birthtime;
              extension.lastUpdateDate = stats.mtime;
            } catch (statsError) {
              log.debug(`Error getting stats for ${extDir}`, { error: statsError });
            }
            
            extensions.push(extension);
          } catch (extError) {
            log.debug(`Error processing Chrome extension ${id}`, { error: extError });
          }
        }
      } catch (preferencesError) {
        log.warn(`Error processing Chrome preferences at ${preferencesPath}`, { error: preferencesError });
      }
    }
  } catch (error) {
    log.error('Error scanning Chrome extensions', { error });
  }
  
  return extensions;
}

/**
 * Scan for Firefox extensions
 */
async function scanFirefoxExtensions(
  config: ExtensionScannerConfig
): Promise<ExtensionInfo[]> {
  const extensions: ExtensionInfo[] = [];
  
  try {
    // Determine Firefox profile path based on platform
    let firefoxProfilesPath: string;
    const platform = os.platform();
    
    if (config.browserProfilePaths?.firefox) {
      firefoxProfilesPath = config.browserProfilePaths.firefox;
    } else if (platform === 'win32') {
      firefoxProfilesPath = path.join(os.homedir(), 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles');
    } else if (platform === 'darwin') {
      firefoxProfilesPath = path.join(os.homedir(), 'Library', 'Application Support', 'Firefox', 'Profiles');
    } else if (platform === 'linux') {
      firefoxProfilesPath = path.join(os.homedir(), '.mozilla', 'firefox');
    } else {
      throw new Error(`Unsupported platform: ${platform}`);
    }
    
    // Find all profile directories
    const profileDirs = [];
    try {
      const items = fs.readdirSync(firefoxProfilesPath);
      for (const item of items) {
        if (item.includes('.') && fs.statSync(path.join(firefoxProfilesPath, item)).isDirectory()) {
          profileDirs.push(path.join(firefoxProfilesPath, item));
        }
      }
    } catch (profileError) {
      log.warn('Error finding Firefox profiles', { error: profileError });
    }
    
    // Process each profile
    for (const profileDir of profileDirs) {
      log.debug(`Processing Firefox profile at ${profileDir}`);
      
      // Extensions can be in several places in Firefox
      const extensionDirs = [
        path.join(profileDir, 'extensions'),
        path.join(profileDir, 'browser-extension-data')
      ];
      
      for (const extDir of extensionDirs) {
        if (!fs.existsSync(extDir)) {
          continue;
        }
        
        try {
          const items = fs.readdirSync(extDir);
          
          for (const item of items) {
            try {
              const extensionPath = path.join(extDir, item);
              
              if (!fs.statSync(extensionPath).isDirectory()) {
                continue;
              }
              
              // Firefox extensions can be in XPI format (zip files) or unpacked folders
              // For simplicity, we'll focus on unpacked extensions
              const manifestPath = path.join(extensionPath, 'manifest.json');
              
              if (!fs.existsSync(manifestPath)) {
                continue;
              }
              
              const manifestContent = JSON.parse(await readFileAsync(manifestPath, 'utf8'));
              
              // Get extension ID - in Firefox it can be in several formats
              let id = item;
              if (manifestContent.applications?.gecko?.id) {
                id = manifestContent.applications.gecko.id;
              }
              
              const extension: ExtensionInfo = {
                id,
                name: manifestContent.name || id,
                version: manifestContent.version || 'unknown',
                browser: 'firefox',
                manifestVersion: manifestContent.manifest_version || 2,
                description: manifestContent.description,
                permissions: manifestContent.permissions || [],
                optionalPermissions: manifestContent.optional_permissions || [],
                hostPermissions: manifestContent.host_permissions || [],
                installType: 'normal', // Firefox doesn't expose this info easily
                installedPath: extensionPath,
                manifestPath,
                manifestContent,
                homepageUrl: manifestContent.homepage_url,
                updateUrl: manifestContent.applications?.gecko?.update_url,
                storeUrl: `https://addons.mozilla.org/en-US/firefox/addon/${id}`,
                author: manifestContent.author
              };
              
              // Try to get install/update dates from filesystem
              try {
                const stats = fs.statSync(extensionPath);
                extension.installDate = stats.birthtime;
                extension.lastUpdateDate = stats.mtime;
              } catch (statsError) {
                log.debug(`Error getting stats for ${extensionPath}`, { error: statsError });
              }
              
              extensions.push(extension);
            } catch (extError) {
              log.debug(`Error processing Firefox extension ${item}`, { error: extError });
            }
          }
        } catch (dirError) {
          log.warn(`Error reading Firefox extensions directory ${extDir}`, { error: dirError });
        }
      }
    }
  } catch (error) {
    log.error('Error scanning Firefox extensions', { error });
  }
  
  return extensions;
}

/**
 * Scan for Safari extensions
 */
async function scanSafariExtensions(
  config: ExtensionScannerConfig
): Promise<ExtensionInfo[]> {
  const extensions: ExtensionInfo[] = [];
  
  try {
    // Safari extensions are only available on macOS
    if (os.platform() !== 'darwin') {
      log.info('Safari extensions can only be scanned on macOS');
      return [];
    }
    
    // Determine Safari extensions path
    let safariExtensionsPath: string;
    
    if (config.browserProfilePaths?.safari) {
      safariExtensionsPath = config.browserProfilePaths.safari;
    } else {
      // Safari extensions can be in several locations
      safariExtensionsPath = path.join(os.homedir(), 'Library', 'Safari', 'Extensions');
      
      // Safari 14+ uses App Extensions that are in a different location
      const modernExtensionsPath = path.join(os.homedir(), 'Library', 'Containers', 'com.apple.Safari', 'Data', 'Library', 'Safari', 'Extensions');
      
      // Check both locations
      if (fs.existsSync(modernExtensionsPath)) {
        // Use the newer location if it exists
        safariExtensionsPath = modernExtensionsPath;
      }
    }
    
    if (!fs.existsSync(safariExtensionsPath)) {
      log.info(`Safari extensions directory does not exist: ${safariExtensionsPath}`);
      return [];
    }
    
    // List all extension bundles (.appex files)
    let extensionFiles = fs.readdirSync(safariExtensionsPath).filter(f => 
      f.endsWith('.appex') || f.endsWith('.safariextz')
    );
    
    for (const extFile of extensionFiles) {
      try {
        const extPath = path.join(safariExtensionsPath, extFile);
        
        // For .safariextz (older format), we'd need to extract it
        // For .appex (newer format), we need to look inside the bundle
        
        if (extFile.endsWith('.appex')) {
          // Look for the Info.plist file
          const infoPlistPath = path.join(extPath, 'Contents', 'Info.plist');
          
          if (!fs.existsSync(infoPlistPath)) {
            continue;
          }
          
          // Parse the Info.plist file
          // This requires the 'plist' npm package or using the 'plutil' command on macOS
          const { stdout } = await execAsync(`plutil -convert json -o - "${infoPlistPath}"`);
          const infoPlist = JSON.parse(stdout);
          
          const id = infoPlist.CFBundleIdentifier || extFile;
          const name = infoPlist.CFBundleDisplayName || infoPlist.CFBundleName || id;
          const version = infoPlist.CFBundleShortVersionString || infoPlist.CFBundleVersion || 'unknown';
          
          // Safari extensions have a different permissions model
          // We need to look at the entitlements
          const entitlementsPath = path.join(extPath, 'Contents', 'Resources', 'extension.entitlements');
          let permissions = [];
          
          if (fs.existsSync(entitlementsPath)) {
            try {
              const { stdout: entitlements } = await execAsync(`plutil -convert json -o - "${entitlementsPath}"`);
              const entitlementsData = JSON.parse(entitlements);
              
              // Extract permissions from entitlements
              for (const [key, value] of Object.entries(entitlementsData)) {
                if (key.includes('com.apple.security') || key.includes('com.apple.Safari')) {
                  permissions.push(key);
                }
              }
            } catch (entitlementError) {
              log.debug(`Error parsing entitlements for ${extFile}`, { error: entitlementError });
            }
          }
          
          const extension: ExtensionInfo = {
            id,
            name,
            version,
            browser: 'safari',
            manifestVersion: 3, // Safari uses a different manifest model
            description: infoPlist.NSHumanReadableCopyright,
            permissions,
            installType: 'normal',
            installedPath: extPath,
            manifestPath: infoPlistPath,
            manifestContent: infoPlist,
            homepageUrl: infoPlist.Website,
            storeUrl: `https://apps.apple.com/us/app/${id}`,
            author: infoPlist.NSHumanReadableCopyright
          };
          
          // Try to get install/update dates from filesystem
          try {
            const stats = fs.statSync(extPath);
            extension.installDate = stats.birthtime;
            extension.lastUpdateDate = stats.mtime;
          } catch (statsError) {
            log.debug(`Error getting stats for ${extPath}`, { error: statsError });
          }
          
          extensions.push(extension);
        }
      } catch (extError) {
        log.debug(`Error processing Safari extension ${extFile}`, { error: extError });
      }
    }
  } catch (error) {
    log.error('Error scanning Safari extensions', { error });
  }
  
  return extensions;
}

/**
 * Scan for Edge extensions (Chromium-based)
 */
async function scanEdgeExtensions(
  config: ExtensionScannerConfig
): Promise<ExtensionInfo[]> {
  const extensions: ExtensionInfo[] = [];
  
  try {
    // Determine Edge profile path based on platform
    let edgePath: string;
    const platform = os.platform();
    
    if (config.browserProfilePaths?.edge) {
      edgePath = config.browserProfilePaths.edge;
    } else if (platform === 'win32') {
      const userDataDir = path.join(os.homedir(), 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data');
      edgePath = path.join(userDataDir, 'Default');
    } else if (platform === 'darwin') {
      edgePath = path.join(os.homedir(), 'Library', 'Application Support', 'Microsoft Edge', 'Default');
    } else if (platform === 'linux') {
      edgePath = path.join(os.homedir(), '.config', 'microsoft-edge', 'Default');
    } else {
      throw new Error(`Unsupported platform: ${platform}`);
    }
    
    // Find all profiles directories
    const profileDirs = [edgePath];
    
    // Find other profiles if any (Profile 1, Profile 2, etc.)
    const userDataDir = path.dirname(edgePath);
    try {
      const items = fs.readdirSync(userDataDir);
      for (const item of items) {
        if (item.startsWith('Profile ') && fs.statSync(path.join(userDataDir, item)).isDirectory()) {
          profileDirs.push(path.join(userDataDir, item));
        }
      }
    } catch (profileError) {
      log.warn('Error finding Edge profiles', { error: profileError });
    }
    
    // Process each profile
    for (const profileDir of profileDirs) {
      log.debug(`Processing Edge profile at ${profileDir}`);
      
      // Load the Preferences file to get extension info
      const preferencesPath = path.join(profileDir, 'Preferences');
      
      try {
        const content = await readFileAsync(preferencesPath, 'utf8');
        const preferences = JSON.parse(content);
        
        // extensions key may be at different places depending on Edge version
        const extensionsData = preferences.extensions?.settings || preferences.extensions?.installations || {};
        
        // Iterate through installed extensions
        for (const [id, data] of Object.entries(extensionsData)) {
          // Skip entry if it's not an extension
          if (!id || id === 'theme' || id.startsWith('_')) {
            continue;
          }
          
          // Skip if no path (might be a removed extension)
          if (!data.path) {
            continue;
          }
          
          // Skip enterprise extensions if not included
          if (data.install_type === 'admin' && !config.includeEnterpriseManaged) {
            continue;
          }
          
          try {
            // Find the extension directory
            const extDir = path.join(userDataDir, data.path);
            
            // Read the manifest file for extension details
            const manifestPath = path.join(extDir, 'manifest.json');
            
            if (!fs.existsSync(manifestPath)) {
              continue; // Skip if manifest doesn't exist
            }
            
            const manifestContent = JSON.parse(await readFileAsync(manifestPath, 'utf8'));
            
            const extension: ExtensionInfo = {
              id,
              name: manifestContent.name || id,
              version: manifestContent.version || 'unknown',
              browser: 'edge',
              manifestVersion: manifestContent.manifest_version || 2,
              description: manifestContent.description,
              permissions: manifestContent.permissions || [],
              optionalPermissions: manifestContent.optional_permissions || [],
              hostPermissions: manifestContent.host_permissions || [],
              installType: data.install_type || 'unknown',
              installedPath: extDir,
              manifestPath,
              manifestContent,
              homepageUrl: manifestContent.homepage_url,
              updateUrl: manifestContent.update_url,
              storeUrl: `https://microsoftedge.microsoft.com/addons/detail/${id}`,
              author: manifestContent.author
            };
            
            // Try to get install/update dates from filesystem
            try {
              const stats = fs.statSync(extDir);
              extension.installDate = stats.birthtime;
              extension.lastUpdateDate = stats.mtime;
            } catch (statsError) {
              log.debug(`Error getting stats for ${extDir}`, { error: statsError });
            }
            
            extensions.push(extension);
          } catch (extError) {
            log.debug(`Error processing Edge extension ${id}`, { error: extError });
          }
        }
      } catch (preferencesError) {
        log.warn(`Error processing Edge preferences at ${preferencesPath}`, { error: preferencesError });
      }
    }
  } catch (error) {
    log.error('Error scanning Edge extensions', { error });
  }
  
  return extensions;
}

/**
 * Scan for Brave extensions (Chromium-based)
 */
async function scanBraveExtensions(
  config: ExtensionScannerConfig
): Promise<ExtensionInfo[]> {
  const extensions: ExtensionInfo[] = [];
  
  try {
    // Determine Brave profile path based on platform
    let bravePath: string;
    const platform = os.platform();
    
    if (config.browserProfilePaths?.brave) {
      bravePath = config.browserProfilePaths.brave;
    } else if (platform === 'win32') {
      const userDataDir = path.join(os.homedir(), 'AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data');
      bravePath = path.join(userDataDir, 'Default');
    } else if (platform === 'darwin') {
      bravePath = path.join(os.homedir(), 'Library', 'Application Support', 'BraveSoftware', 'Brave-Browser', 'Default');
    } else if (platform === 'linux') {
      bravePath = path.join(os.homedir(), '.config', 'BraveSoftware', 'Brave-Browser', 'Default');
    } else {
      throw new Error(`Unsupported platform: ${platform}`);
    }
    
    // Find all profiles directories
    const profileDirs = [bravePath];
    
    // Find other profiles if any (Profile 1, Profile 2, etc.)
    const userDataDir = path.dirname(bravePath);
    try {
      const items = fs.readdirSync(userDataDir);
      for (const item of items) {
        if (item.startsWith('Profile ') && fs.statSync(path.join(userDataDir, item)).isDirectory()) {
          profileDirs.push(path.join(userDataDir, item));
        }
      }
    } catch (profileError) {
      log.warn('Error finding Brave profiles', { error: profileError });
    }
    
    // Process each profile
    for (const profileDir of profileDirs) {
      log.debug(`Processing Brave profile at ${profileDir}`);
      
      // Load the Preferences file to get extension info
      const preferencesPath = path.join(profileDir, 'Preferences');
      
      try {
        const content = await readFileAsync(preferencesPath, 'utf8');
        const preferences = JSON.parse(content);
        
        // extensions key may be at different places depending on Brave version
        const extensionsData = preferences.extensions?.settings || preferences.extensions?.installations || {};
        
        // Iterate through installed extensions
        for (const [id, data] of Object.entries(extensionsData)) {
          // Skip entry if it's not an extension
          if (!id || id === 'theme' || id.startsWith('_')) {
            continue;
          }
          
          // Skip if no path (might be a removed extension)
          if (!data.path) {
            continue;
          }
          
          // Skip enterprise extensions if not included
          if (data.install_type === 'admin' && !config.includeEnterpriseManaged) {
            continue;
          }
          
          try {
            // Find the extension directory
            const extDir = path.join(userDataDir, data.path);
            
            // Read the manifest file for extension details
            const manifestPath = path.join(extDir, 'manifest.json');
            
            if (!fs.existsSync(manifestPath)) {
              continue; // Skip if manifest doesn't exist
            }
            
            const manifestContent = JSON.parse(await readFileAsync(manifestPath, 'utf8'));
            
            const extension: ExtensionInfo = {
              id,
              name: manifestContent.name || id,
              version: manifestContent.version || 'unknown',
              browser: 'brave',
              manifestVersion: manifestContent.manifest_version || 2,
              description: manifestContent.description,
              permissions: manifestContent.permissions || [],
              optionalPermissions: manifestContent.optional_permissions || [],
              hostPermissions: manifestContent.host_permissions || [],
              installType: data.install_type || 'unknown',
              installedPath: extDir,
              manifestPath,
              manifestContent,
              homepageUrl: manifestContent.homepage_url,
              updateUrl: manifestContent.update_url,
              storeUrl: `https://chrome.google.com/webstore/detail/${id}`,
              author: manifestContent.author
            };
            
            // Try to get install/update dates from filesystem
            try {
              const stats = fs.statSync(extDir);
              extension.installDate = stats.birthtime;
              extension.lastUpdateDate = stats.mtime;
            } catch (statsError) {
              log.debug(`Error getting stats for ${extDir}`, { error: statsError });
            }
            
            extensions.push(extension);
          } catch (extError) {
            log.debug(`Error processing Brave extension ${id}`, { error: extError });
          }
        }
      } catch (preferencesError) {
        log.warn(`Error processing Brave preferences at ${preferencesPath}`, { error: preferencesError });
      }
    }
  } catch (error) {
    log.error('Error scanning Brave extensions', { error });
  }
  
  return extensions;
}

/**
 * Scan for Opera extensions (Chromium-based)
 */
async function scanOperaExtensions(
  config: ExtensionScannerConfig
): Promise<ExtensionInfo[]> {
  const extensions: ExtensionInfo[] = [];
  
  try {
    // Determine Opera profile path based on platform
    let operaPath: string;
    const platform = os.platform();
    
    if (config.browserProfilePaths?.opera) {
      operaPath = config.browserProfilePaths.opera;
    } else if (platform === 'win32') {
      const userDataDir = path.join(os.homedir(), 'AppData', 'Roaming', 'Opera Software', 'Opera Stable');
      operaPath = userDataDir;
    } else if (platform === 'darwin') {
      operaPath = path.join(os.homedir(), 'Library', 'Application Support', 'com.operasoftware.Opera');
    } else if (platform === 'linux') {
      operaPath = path.join(os.homedir(), '.config', 'opera');
    } else {
      throw new Error(`Unsupported platform: ${platform}`);
    }
    
    // Opera uses a structure similar to Chrome
    log.debug(`Processing Opera profile at ${operaPath}`);
    
    // Load the Preferences file to get extension info
    const preferencesPath = path.join(operaPath, 'Preferences');
    
    try {
      const content = await readFileAsync(preferencesPath, 'utf8');
      const preferences = JSON.parse(content);
      
      // extensions key may be at different places depending on Opera version
      const extensionsData = preferences.extensions?.settings || preferences.extensions?.installations || {};
      
      // Iterate through installed extensions
      for (const [id, data] of Object.entries(extensionsData)) {
        // Skip entry if it's not an extension
        if (!id || id === 'theme' || id.startsWith('_')) {
          continue;
        }
        
        // Skip if no path (might be a removed extension)
        if (!data.path) {
          continue;
        }
        
        // Skip enterprise extensions if not included
        if (data.install_type === 'admin' && !config.includeEnterpriseManaged) {
          continue;
        }
        
        try {
          // Find the extension directory
          const extDir = path.join(operaPath, data.path);
          
          // Read the manifest file for extension details
          const manifestPath = path.join(extDir, 'manifest.json');
          
          if (!fs.existsSync(manifestPath)) {
            continue; // Skip if manifest doesn't exist
          }
          
          const manifestContent = JSON.parse(await readFileAsync(manifestPath, 'utf8'));
          
          const extension: ExtensionInfo = {
            id,
            name: manifestContent.name || id,
            version: manifestContent.version || 'unknown',
            browser: 'opera',
            manifestVersion: manifestContent.manifest_version || 2,
            description: manifestContent.description,
            permissions: manifestContent.permissions || [],
            optionalPermissions: manifestContent.optional_permissions || [],
            hostPermissions: manifestContent.host_permissions || [],
            installType: data.install_type || 'unknown',
            installedPath: extDir,
            manifestPath,
            manifestContent,
            homepageUrl: manifestContent.homepage_url,
            updateUrl: manifestContent.update_url,
            storeUrl: `https://addons.opera.com/en/extensions/details/${id}`,
            author: manifestContent.author
          };
          
          // Try to get install/update dates from filesystem
          try {
            const stats = fs.statSync(extDir);
            extension.installDate = stats.birthtime;
            extension.lastUpdateDate = stats.mtime;
          } catch (statsError) {
            log.debug(`Error getting stats for ${extDir}`, { error: statsError });
          }
          
          extensions.push(extension);
        } catch (extError) {
          log.debug(`Error processing Opera extension ${id}`, { error: extError });
        }
      }
    } catch (preferencesError) {
      log.warn(`Error processing Opera preferences at ${preferencesPath}`, { error: preferencesError });
    }
  } catch (error) {
    log.error('Error scanning Opera extensions', { error });
  }
  
  return extensions;
}

/**
 * Check extension for issues
 */
async function checkExtensionForIssues(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<void> {
  try {
    // Check for updates and latest version
    await checkForExtensionUpdates(ext, config);
    
    // Check for vulnerabilities if configured
    if (config.checkVulnerabilities) {
      await checkForExtensionVulnerabilities(ext, config);
    }
    
    // Check for permission issues if configured
    if (config.checkPermissions) {
      await checkExtensionPermissions(ext, config);
    }
    
    // Check for compatibility issues if configured
    if (config.checkCompatibility) {
      await checkExtensionCompatibility(ext, config);
    }
    
    // Check if extension is maintained if configured
    if (config.checkMaintained) {
      await checkIfExtensionMaintained(ext, config);
    }
    
    // Check for deprecated APIs if configured
    if (config.checkDeprecatedApis) {
      await checkForDeprecatedApis(ext, config);
    }
    
    // Check for alternatives if configured
    if (config.checkAlternatives) {
      await checkForExtensionAlternatives(ext, config);
    }
  } catch (error) {
    log.warn(`Error checking extension ${ext.name} for issues`, { error });
  }
}

/**
 * Check if extension has available updates
 */
async function checkForExtensionUpdates(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<void> {
  try {
    // Use different approaches based on browser and extension store
    switch (ext.browser) {
      case 'chrome':
      case 'brave':
      case 'edge':
        await checkChromeStoreUpdates(ext, config);
        break;
      case 'firefox':
        await checkFirefoxStoreUpdates(ext, config);
        break;
      case 'safari':
        await checkSafariStoreUpdates(ext, config);
        break;
      case 'opera':
        await checkOperaStoreUpdates(ext, config);
        break;
    }
  } catch (error) {
    log.warn(`Error checking updates for extension ${ext.name}`, { error });
  }
}

/**
 * Check for Chrome Web Store updates
 */
async function checkChromeStoreUpdates(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<void> {
  try {
    // Use the Chrome Web Store API to check for latest version
    // Note: This is a simplified approach - Chrome Web Store doesn't have a public API
    // In a real implementation, you might need to scrape the store page or use other methods
    
    // For demonstration purposes, we'll check a well-known database of extensions
    // In practice, you might connect to an enterprise API or use a service that tracks extensions
    
    // This is a placeholder - a real implementation would use a proper API or database
    const knownExtensions: Record<string, { version: string, lastUpdate: string }> = {
      'nkbihfbeogaeaoehlefnkodbefgpgknn': { version: '10.35.10', lastUpdate: '2023-08-15' }, // MetaMask
      'bkbeeeffjjeopflfhgeknacdieedcoml': { version: '22.8.0', lastUpdate: '2023-07-20' },  // Save to Google Drive
      'ghbmnnjooekpmoecnnnilnnbdlolhkhi': { version: '1.49.1', lastUpdate: '2023-09-01' }   // Google Docs Offline
    };
    
    if (knownExtensions[ext.id]) {
      ext.latestVersion = knownExtensions[ext.id].version;
      ext.latestReleaseDate = new Date(knownExtensions[ext.id].lastUpdate);
      
      // Compare versions to determine if outdated
      if (ext.version !== 'unknown' && ext.latestVersion !== ext.version) {
        // Use semver to compare versions if available
        try {
          const semver = require('semver');
          ext.isOutdated = semver.lt(ext.version, ext.latestVersion);
        } catch (semverError) {
          // Basic version comparison if semver is not available
          ext.isOutdated = ext.version !== ext.latestVersion;
        }
      }
    }
    
    // If not found in our database, check the Web Store directly
    // This would be done by scraping or calling an API in a real implementation
    if (!ext.latestVersion) {
      // For now, we'll just check if the extension is more than a year old, as a heuristic
      if (ext.lastUpdateDate) {
        const now = new Date();
        const oneYearAgo = new Date(now);
        oneYearAgo.setFullYear(now.getFullYear() - 1);
        
        if (ext.lastUpdateDate < oneYearAgo) {
          ext.isOutdated = true;
        }
      }
    }
  } catch (error) {
    log.warn(`Error checking Chrome store updates for ${ext.name}`, { error });
  }
}

/**
 * Check for Firefox Add-ons updates
 */
async function checkFirefoxStoreUpdates(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<void> {
  try {
    // Firefox has a public API for add-ons
    // In a real implementation, you would use this API
    // For demo purposes, we'll simulate the check
    
    // Check if the extension ID is in a format typically used for Firefox
    if (ext.id.includes('@') || ext.id.includes('{')) {
      // This would call the Firefox Add-ons API
      // For example: fetch(`https://addons.mozilla.org/api/v4/addons/addon/${encodeURIComponent(ext.id)}/`)
      
      // Simulate a response for demonstration
      const knownExtensions: Record<string, { version: string, lastUpdate: string }> = {
        'ublock0@raymondhill.net': { version: '1.49.2', lastUpdate: '2023-08-20' },
        '{73a6fe31-595d-460b-a920-fcc0f8843232}': { version: '2.1.1', lastUpdate: '2023-07-15' }
      };
      
      if (knownExtensions[ext.id]) {
        ext.latestVersion = knownExtensions[ext.id].version;
        ext.latestReleaseDate = new Date(knownExtensions[ext.id].lastUpdate);
        
        // Compare versions to determine if outdated
        if (ext.version !== 'unknown' && ext.latestVersion !== ext.version) {
          // Use semver to compare versions if available
          try {
            const semver = require('semver');
            ext.isOutdated = semver.lt(ext.version, ext.latestVersion);
          } catch (semverError) {
            // Basic version comparison if semver is not available
            ext.isOutdated = ext.version !== ext.latestVersion;
          }
        }
      }
    }
    
    // Same fallback as with Chrome
    if (!ext.latestVersion) {
      if (ext.lastUpdateDate) {
        const now = new Date();
        const oneYearAgo = new Date(now);
        oneYearAgo.setFullYear(now.getFullYear() - 1);
        
        if (ext.lastUpdateDate < oneYearAgo) {
          ext.isOutdated = true;
        }
      }
    }
  } catch (error) {
    log.warn(`Error checking Firefox store updates for ${ext.name}`, { error });
  }
}

/**
 * Check for Safari extensions updates
 */
async function checkSafariStoreUpdates(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<void> {
  try {
    // Safari extensions are updated through the App Store
    // This is much harder to check programmatically
    // We'll use a simple heuristic based on file dates
    
    if (ext.lastUpdateDate) {
      const now = new Date();
      const oneYearAgo = new Date(now);
      oneYearAgo.setFullYear(now.getFullYear() - 1);
      
      if (ext.lastUpdateDate < oneYearAgo) {
        ext.isOutdated = true;
      }
    }
  } catch (error) {
    log.warn(`Error checking Safari store updates for ${ext.name}`, { error });
  }
}

/**
 * Check for Opera Add-ons updates
 */
async function checkOperaStoreUpdates(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<void> {
  try {
    // Opera uses both its own store and the Chrome Web Store
    // For Opera-specific extensions, we'd need to check the Opera Add-ons store
    // For Chrome-compatible extensions, we can use the Chrome Web Store checks
    
    // For simplicity, we'll use the same approach as Chrome
    await checkChromeStoreUpdates(ext, config);
  } catch (error) {
    log.warn(`Error checking Opera store updates for ${ext.name}`, { error });
  }
}

/**
 * Check for extension vulnerabilities
 */
async function checkForExtensionVulnerabilities(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<void> {
  try {
    // Check custom database first if configured
    if (config.vulnerabilityDbPaths?.extensions && fs.existsSync(config.vulnerabilityDbPaths.extensions)) {
      try {
        const vulnDb = JSON.parse(await readFileAsync(config.vulnerabilityDbPaths.extensions, 'utf8'));
        
        // Normalize extension ID for lookup (case-insensitive)
        const normalizedId = ext.id.toLowerCase();
        
        // Check for vulnerabilities by extension ID
        const vulnEntries = vulnDb[normalizedId] || vulnDb[ext.name.toLowerCase()];
        
        if (vulnEntries) {
          processVulnerabilityData(ext, vulnEntries);
        }
      } catch (dbError) {
        log.warn(`Error reading extension vulnerability database`, { error: dbError });
      }
    }
    
    // Check for known vulnerable extensions
    // This is a simplified approach - a real implementation would use a comprehensive database
    await checkForKnownVulnerableExtensions(ext, config);
  } catch (error) {
    log.warn(`Error checking vulnerabilities for extension ${ext.name}`, { error });
  }
}

/**
 * Process vulnerability data from a database
 */
function processVulnerabilityData(
  ext: ExtensionInfo,
  vulnerabilities: Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    affected_versions: string;
    fixed_in_version?: string;
    cve_ids?: string[];
    url?: string;
  }>
): void {
  const affectedVulns = vulnerabilities.filter(vuln => 
    isVersionAffected(ext.version, vuln.affected_versions)
  );
  
  if (affectedVulns.length > 0) {
    ext.vulnerabilities = affectedVulns.map(vuln => ({
      severity: vuln.severity,
      description: vuln.description,
      affectedVersions: vuln.affected_versions,
      fixedInVersion: vuln.fixed_in_version,
      url: vuln.url,
      cveIds: vuln.cve_ids
    }));
    
    ext.isVulnerable = true;
  }
}

/**
 * Check for known vulnerable extensions
 */
async function checkForKnownVulnerableExtensions(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<void> {
  // This is a very simplified example - a real implementation would use a comprehensive database
  const knownVulnerableExtensions: Record<string, Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    affected_versions: string;
    fixed_in_version?: string;
    cve_ids?: string[];
    url?: string;
  }>> = {
    // Some historical examples
    'nkbihfbeogaeaoehlefnkodbefgpgknn': [{ // MetaMask
      severity: 'high',
      description: 'Potential data leak vulnerability',
      affected_versions: '<10.0.0',
      fixed_in_version: '10.0.0',
      url: 'https://github.com/MetaMask/metamask-extension/releases/tag/v10.0.0'
    }],
    'fheoggkfdfchfphceeifdbepaooicaho': [{ // JSONView Chrome extension
      severity: 'medium',
      description: 'Code injection vulnerability',
      affected_versions: '<0.0.33',
      fixed_in_version: '0.0.33',
      url: 'https://github.com/gildas-lormeau/JSONView-for-Chrome/issues/29'
    }]
  };
  
  if (knownVulnerableExtensions[ext.id]) {
    processVulnerabilityData(ext, knownVulnerableExtensions[ext.id]);
  }
  
  // Also check for permissions that indicate potential security issues
  if (ext.permissions && ext.permissions.length > 0) {
    const riskyPermissions = [
      'tabs',
      'history',
      'webNavigation',
      'cookies',
      'webRequest',
      'webRequestBlocking',
      '<all_urls>',
      'bookmarks',
      'management',
      'clipboardWrite',
      'clipboardRead',
      'geolocation',
      'declarativeNetRequest',
      'storage'
    ];
    
    const hasRiskyPermissions = ext.permissions.some(p => 
      riskyPermissions.includes(p) || p === '*' || p.includes('://')
    );
    
    // If it has more than 3-4 risky permissions and hasn't been updated in a while,
    // it might be a security risk
    if (hasRiskyPermissions && ext.isOutdated) {
      if (!ext.vulnerabilities) {
        ext.vulnerabilities = [];
      }
      
      ext.vulnerabilities.push({
        severity: 'medium',
        description: 'Extension has high-risk permissions and hasn\'t been updated recently.'
      });
      
      ext.isVulnerable = true;
    }
  }
}

/**
 * Check extension permissions for potential issues
 */
async function checkExtensionPermissions(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<void> {
  try {
    const permissionConcerns: {
      permission: string;
      level: 'low' | 'medium' | 'high';
      description: string;
    }[] = [];
    
    // Define permissions and their risk levels
    const permissionRisks: Record<string, { level: 'low' | 'medium' | 'high', description: string }> = {
      // High risk permissions
      '<all_urls>': { 
        level: 'high', 
        description: 'Can access all websites, read sensitive data, and modify content on any site.'
      },
      'webRequest': { 
        level: 'high', 
        description: 'Can intercept, block, or modify network requests.'
      },
      'webRequestBlocking': { 
        level: 'high', 
        description: 'Can block network requests, potentially breaking website functionality.'
      },
      'cookies': { 
        level: 'high', 
        description: 'Can read and modify browser cookies, potentially accessing user sessions.'
      },
      'tabs': { 
        level: 'medium', 
        description: 'Can access information about open tabs and their content.'
      },
      'history': { 
        level: 'medium', 
        description: 'Can access browsing history.'
      },
      'clipboardRead': { 
        level: 'medium', 
        description: 'Can read content from the clipboard.'
      },
      'clipboardWrite': { 
        level: 'medium', 
        description: 'Can write content to the clipboard.'
      },
      'bookmarks': { 
        level: 'medium', 
        description: 'Can read and modify bookmarks.'
      },
      'geolocation': { 
        level: 'medium', 
        description: 'Can access the user\'s geographical location.'
      },
      'storage': { 
        level: 'low', 
        description: 'Can store data persistently.'
      },
      'notifications': { 
        level: 'low', 
        description: 'Can display notifications.'
      }
    };
    
    // Check each permission
    if (ext.permissions) {
      for (const permission of ext.permissions) {
        // Check for host permissions (URLs) which can be risky
        if (permission.includes('://')) {
          if (permission.includes('*')) {
            permissionConcerns.push({
              permission,
              level: 'high',
              description: 'Wildcard host permission allows access to multiple websites.'
            });
          } else {
            permissionConcerns.push({
              permission,
              level: 'medium',
              description: 'Host permission allows access to specific website.'
            });
          }
          continue;
        }
        
        // Check for known permissions
        if (permissionRisks[permission]) {
          permissionConcerns.push({
            permission,
            level: permissionRisks[permission].level,
            description: permissionRisks[permission].description
          });
        }
      }
    }
    
    // Check host permissions separately (for manifest v3)
    if (ext.hostPermissions) {
      for (const hostPermission of ext.hostPermissions) {
        if (hostPermission.includes('*')) {
          permissionConcerns.push({
            permission: hostPermission,
            level: 'high',
            description: 'Wildcard host permission allows access to multiple websites.'
          });
        } else {
          permissionConcerns.push({
            permission: hostPermission,
            level: 'medium',
            description: 'Host permission allows access to specific website.'
          });
        }
      }
    }
    
    // Flag extensions with excessive permissions
    const highRiskCount = permissionConcerns.filter(p => p.level === 'high').length;
    const mediumRiskCount = permissionConcerns.filter(p => p.level === 'medium').length;
    
    if (highRiskCount >= 2 || (highRiskCount >= 1 && mediumRiskCount >= 2) || mediumRiskCount >= 4) {
      ext.hasExcessivePermissions = true;
      ext.permissionConcerns = permissionConcerns;
    }
  } catch (error) {
    log.warn(`Error checking permissions for extension ${ext.name}`, { error });
  }
}

/**
 * Check extension compatibility with current browser versions
 */
async function checkExtensionCompatibility(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<void> {
  try {
    const compatibilityIssues: {
      browserVersion: string;
      description: string;
      impact: 'low' | 'medium' | 'high';
    }[] = [];
    
    // Check manifest version compatibility
    if (ext.manifestVersion < 3) {
      // Manifest v2 is being deprecated
      switch (ext.browser) {
        case 'chrome':
        case 'edge':
          // Chrome and Edge are deprecating Manifest v2
          compatibilityIssues.push({
            browserVersion: 'Chrome/Edge 2024+',
            description: 'Uses Manifest V2 which is deprecated. Chrome and Edge plan to fully remove support for Manifest V2 extensions.',
            impact: 'high'
          });
          break;
        case 'firefox':
          // Firefox plans to support Manifest v2 longer
          compatibilityIssues.push({
            browserVersion: 'Firefox Future',
            description: 'Uses Manifest V2 which will eventually be deprecated, though Firefox will support it longer than Chrome.',
            impact: 'low'
          });
          break;
      }
    }
    
    // Check if extension uses deprecated APIs in its code
    // This would require static analysis of the extension code
    // Here we'll just check the manifest for obvious issues
    
    if (ext.manifestContent) {
      // Check for background page (deprecated in favor of background.service_worker)
      if (ext.manifestContent.background && ext.manifestContent.background.page) {
        compatibilityIssues.push({
          browserVersion: 'Chrome 2024+',
          description: 'Uses background pages which are deprecated in Manifest V3.',
          impact: 'high'
        });
      }
      
      // Check for browser_action or page_action (deprecated in favor of action)
      if (ext.manifestContent.browser_action || ext.manifestContent.page_action) {
        compatibilityIssues.push({
          browserVersion: 'Chrome 2024+',
          description: 'Uses browser_action/page_action which are deprecated in Manifest V3.',
          impact: 'high'
        });
      }
    }
    
    // Check for permissions that might be restricted in the future
    if (ext.permissions && ext.permissions.includes('webRequest') && ext.permissions.includes('webRequestBlocking')) {
      compatibilityIssues.push({
        browserVersion: 'Chrome 2024+',
        description: 'Uses webRequest and webRequestBlocking which are restricted in Manifest V3 (declarativeNetRequest is the replacement).',
        impact: 'high'
      });
    }
    
    // Set compatibility issue flag if issues found
    if (compatibilityIssues.length > 0) {
      ext.isCompatibilityIssue = true;
      ext.compatibilityIssues = compatibilityIssues;
    }
  } catch (error) {
    log.warn(`Error checking compatibility for extension ${ext.name}`, { error });
  }
}

/**
 * Check if extension is maintained
 */
async function checkIfExtensionMaintained(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<void> {
  try {
    // Consider an extension not maintained if it hasn't been updated in a long time
    if (ext.lastUpdateDate) {
      const now = new Date();
      const ageInDays = (now.getTime() - ext.lastUpdateDate.getTime()) / (1000 * 60 * 60 * 24);
      
      const maxAge = config.maxUpdateAge || 365; // Default to 1 year
      
      if (ageInDays > maxAge) {
        ext.isNotMaintained = true;
      }
    }
    
    // If no update date information is available, check if it's significantly behind latest version
    if (!ext.lastUpdateDate && ext.isOutdated && ext.latestVersion) {
      // If the extension is outdated by more than one major version, flag it
      try {
        const semver = require('semver');
        const currentMajor = semver.major(ext.version);
        const latestMajor = semver.major(ext.latestVersion);
        
        if (latestMajor - currentMajor >= 2) {
          ext.isNotMaintained = true;
        }
      } catch (semverError) {
        // If can't parse with semver, use a simple heuristic
        const currentMajor = parseInt(ext.version.split('.')[0], 10);
        const latestMajor = parseInt(ext.latestVersion.split('.')[0], 10);
        
        if (!isNaN(currentMajor) && !isNaN(latestMajor) && latestMajor - currentMajor >= 2) {
          ext.isNotMaintained = true;
        }
      }
    }
    
    // Check if manifest version is outdated
    if (ext.manifestVersion < 2) {
      ext.isNotMaintained = true;
    }
  } catch (error) {
    log.warn(`Error checking if extension ${ext.name} is maintained`, { error });
  }
}

/**
 * Check for deprecated APIs used in the extension
 */
async function checkForDeprecatedApis(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<void> {
  try {
    const deprecatedApis: {
      api: string;
      deprecatedSince: string;
      alternatives?: string;
      removalTimeline?: string;
    }[] = [];
    
    // Check for deprecated APIs based on the manifest
    if (ext.manifestContent) {
      // Chrome deprecated APIs
      if (ext.browser === 'chrome' || ext.browser === 'edge' || ext.browser === 'brave' || ext.browser === 'opera') {
        // Check for background page (deprecated in favor of service worker)
        if (ext.manifestContent.background && ext.manifestContent.background.page) {
          deprecatedApis.push({
            api: 'background.page',
            deprecatedSince: 'Chrome 88',
            alternatives: 'background.service_worker',
            removalTimeline: 'Manifest V3 migration'
          });
        }
        
        // Check for browser_action or page_action (deprecated in favor of action)
        if (ext.manifestContent.browser_action) {
          deprecatedApis.push({
            api: 'browser_action',
            deprecatedSince: 'Chrome 88',
            alternatives: 'action',
            removalTimeline: 'Manifest V3 migration'
          });
        }
        
        if (ext.manifestContent.page_action) {
          deprecatedApis.push({
            api: 'page_action',
            deprecatedSince: 'Chrome 88',
            alternatives: 'action',
            removalTimeline: 'Manifest V3 migration'
          });
        }
      }
      
      // Firefox specific deprecated APIs
      if (ext.browser === 'firefox') {
        // Firefox has its own set of deprecated APIs
        // Check for legacy XUL stuff
        if (ext.permissions && ext.permissions.includes('XUL')) {
          deprecatedApis.push({
            api: 'XUL',
            deprecatedSince: 'Firefox 57',
            alternatives: 'WebExtensions APIs',
            removalTimeline: 'Already removed'
          });
        }
      }
    }
    
    // More complete checking would require static analysis of JS files
    // For example, searching for chrome.webRequest.onBeforeRequest.addListener with blocking parameter
    
    // Set the flag if deprecated APIs found
    if (deprecatedApis.length > 0) {
      ext.usesDeprecatedApis = true;
      ext.deprecatedApis = deprecatedApis;
    }
  } catch (error) {
    log.warn(`Error checking for deprecated APIs in extension ${ext.name}`, { error });
  }
}

/**
 * Check for alternative extensions
 */
async function checkForExtensionAlternatives(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<void> {
  try {
    // This would typically use a database of recommended alternatives
    // For demonstration, we'll just check a few known cases
    
    // Define some known alternatives for extensions that might have issues
    const alternatives: Record<string, string> = {
      // Examples for abandoned or problematic extensions
      'fheoggkfdfchfphceeifdbepaooicaho': 'jsonvue', // JSONView -> JSONVue
      'gbmdgpbipfallnflgajpaliibnhdgobh': 'cjpalhdlnbpafiamejdnhcphjbkeiagm' // Adblock Plus -> uBlock Origin
    };
    
    // Check if there's a recommended alternative
    if (alternatives[ext.id]) {
      ext.recommandedAlternative = alternatives[ext.id];
    }
    
    // If extension has security issues or compatibility issues, try to suggest alternatives
    if ((ext.isVulnerable || ext.isCompatibilityIssue || ext.isNotMaintained) && !ext.recommandedAlternative) {
      // This is where you'd implement logic to find alternatives based on the extension's purpose
      // For example, if it's an ad blocker, suggest uBlock Origin
      // If it's a password manager, suggest Bitwarden, etc.
      
      // For demonstration, we'll just make some common suggestions based on category detection
      if (ext.name.toLowerCase().includes('password') || ext.name.toLowerCase().includes('pass')) {
        ext.recommandedAlternative = 'Bitwarden or 1Password';
      } else if (ext.name.toLowerCase().includes('ad') || ext.name.toLowerCase().includes('block')) {
        ext.recommandedAlternative = 'uBlock Origin';
      } else if (ext.name.toLowerCase().includes('screen') || ext.name.toLowerCase().includes('capture')) {
        ext.recommandedAlternative = 'Nimbus Screenshot';
      }
    }
  } catch (error) {
    log.warn(`Error checking for alternatives for extension ${ext.name}`, { error });
  }
}

/**
 * Calculate risk level for an extension issue
 */
function calculateRiskLevel(
  ext: ExtensionInfo
): 'low' | 'medium' | 'high' | 'critical' {
  // Start with low risk
  let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
  
  // Prioritize vulnerabilities
  if (ext.isVulnerable && ext.vulnerabilities && ext.vulnerabilities.length > 0) {
    // Use the highest vulnerability severity
    for (const vuln of ext.vulnerabilities) {
      if (vuln.severity === 'critical') {
        return 'critical';
      } else if (vuln.severity === 'high' && riskLevel !== 'critical') {
        riskLevel = 'high';
      } else if (vuln.severity === 'medium' && riskLevel !== 'critical' && riskLevel !== 'high') {
        riskLevel = 'medium';
      }
    }
  }
  
  // Consider compatibility issues
  if (ext.isCompatibilityIssue && ext.compatibilityIssues) {
    for (const issue of ext.compatibilityIssues) {
      if (issue.impact === 'high' && riskLevel !== 'critical') {
        riskLevel = 'high';
      } else if (issue.impact === 'medium' && riskLevel !== 'critical' && riskLevel !== 'high') {
        riskLevel = 'medium';
      }
    }
  }
  
  // Consider excess permissions
  if (ext.hasExcessivePermissions && ext.permissionConcerns) {
    const highRiskPermissions = ext.permissionConcerns.filter(p => p.level === 'high').length;
    
    if (highRiskPermissions >= 3) {
      if (riskLevel !== 'critical') riskLevel = 'high';
    } else if (highRiskPermissions >= 1) {
      if (riskLevel !== 'critical' && riskLevel !== 'high') riskLevel = 'medium';
    }
  }
  
  // Consider deprecated APIs
  if (ext.usesDeprecatedApis) {
    if (riskLevel === 'low') riskLevel = 'medium';
  }
  
  // Consider maintenance status
  if (ext.isNotMaintained) {
    if (riskLevel === 'low') riskLevel = 'medium';
    
    // If unmaintained extension has other issues, raise the risk level
    if ((ext.isVulnerable || ext.isCompatibilityIssue || ext.hasExcessivePermissions) && riskLevel === 'medium') {
      riskLevel = 'high';
    }
  }
  
  // Consider outdated status
  if (ext.isOutdated) {
    // Being outdated alone is low risk, but combined with other factors increases risk
    if (ext.isNotMaintained && riskLevel === 'medium') {
      riskLevel = 'high';
    }
  }
  
  return riskLevel;
}

/**
 * Generate tags for an extension issue
 */
function generateTags(ext: ExtensionInfo): string[] {
  const tags: string[] = [ext.browser];
  
  // Add tags based on issue type
  if (ext.isOutdated) {
    tags.push('outdated');
  }
  
  if (ext.isVulnerable) {
    tags.push('vulnerable');
    
    // Add highest severity level
    if (ext.vulnerabilities && ext.vulnerabilities.length > 0) {
      let highestSeverity = 'low';
      for (const vuln of ext.vulnerabilities) {
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
  }
  
  if (ext.isDeprecated) {
    tags.push('deprecated');
  }
  
  if (ext.isCompatibilityIssue) {
    tags.push('compatibility-issue');
  }
  
  if (ext.isNotMaintained) {
    tags.push('not-maintained');
  }
  
  if (ext.hasExcessivePermissions) {
    tags.push('excessive-permissions');
  }
  
  if (ext.usesDeprecatedApis) {
    tags.push('deprecated-apis');
  }
  
  // Add manifest version tag
  tags.push(`manifest-v${ext.manifestVersion}`);
  
  // Add install type if available
  if (ext.installType) {
    tags.push(`install:${ext.installType}`);
  }
  
  return tags;
}

/**
 * Generate a recommendation for an extension issue
 */
function generateRecommendation(ext: ExtensionInfo): string {
  const recommendations: string[] = [];
  
  // Handle vulnerable extensions with highest priority
  if (ext.isVulnerable && ext.vulnerabilities && ext.vulnerabilities.length > 0) {
    recommendations.push(
      `Found ${ext.vulnerabilities.length} ${ext.vulnerabilities.length === 1 ? 'vulnerability' : 'vulnerabilities'} in ${ext.name} v${ext.version} for ${ext.browser}.`
    );
    
    // Group vulnerabilities by severity for better readability
    const bySeverity: Record<string, any[]> = {};
    for (const vuln of ext.vulnerabilities) {
      if (!bySeverity[vuln.severity]) {
        bySeverity[vuln.severity] = [];
      }
      bySeverity[vuln.severity].push(vuln);
    }
    
    // Report vulnerabilities from highest to lowest severity
    for (const severity of ['critical', 'high', 'medium', 'low']) {
      if (bySeverity[severity] && bySeverity[severity].length > 0) {
        recommendations.push(
          `${bySeverity[severity].length} ${severity} severity ${bySeverity[severity].length === 1 ? 'issue' : 'issues'} found:`
        );
        
        // List the vulnerabilities at this severity
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
    
    // Recommend updating or replacing
    if (ext.latestVersion) {
      recommendations.push(
        `Update to the latest version (${ext.latestVersion}) to resolve these security issues.`
      );
    } else {
      recommendations.push(
        `Update to the latest version to resolve these security issues.`
      );
    }
    
    // Recommend alternatives if available
    if (ext.recommandedAlternative) {
      recommendations.push(
        `Consider replacing with ${ext.recommandedAlternative} as an alternative.`
      );
    }
  }
  
  // Handle compatibility issues
  if (ext.isCompatibilityIssue && ext.compatibilityIssues) {
    // Only add this header if not already covered by vulnerabilities
    if (recommendations.length === 0) {
      recommendations.push(
        `${ext.name} v${ext.version} for ${ext.browser} has compatibility issues.`
      );
    } else {
      recommendations.push(
        `Additionally, this extension has compatibility issues.`
      );
    }
    
    // List all compatibility issues
    for (const issue of ext.compatibilityIssues) {
      recommendations.push(`- ${issue.description} (Affected: ${issue.browserVersion}, Impact: ${issue.impact})`);
    }
    
    // Recommend alternatives if available
    if (ext.recommandedAlternative) {
      recommendations.push(
        `Consider replacing with ${ext.recommandedAlternative} as a compatible alternative.`
      );
    } else {
      // General advice for Manifest V2 -> V3 migration
      if (ext.manifestVersion < 3) {
        recommendations.push(
          'Check if the developer has released a Manifest V3 compatible version of this extension.'
        );
      }
    }
  }
  
  // Handle permission issues
  if (ext.hasExcessivePermissions && ext.permissionConcerns) {
    // Only add this header if not already covered by other issues
    if (recommendations.length === 0) {
      recommendations.push(
        `${ext.name} v${ext.version} for ${ext.browser} has excessive permissions.`
      );
    } else {
      recommendations.push(
        `Additionally, this extension has excessive permissions.`
      );
    }
    
    // Group permissions by risk level
    const highRiskPermissions = ext.permissionConcerns.filter(p => p.level === 'high');
    const mediumRiskPermissions = ext.permissionConcerns.filter(p => p.level === 'medium');
    
    if (highRiskPermissions.length > 0) {
      recommendations.push(`High-risk permissions (${highRiskPermissions.length}):`);
      for (const perm of highRiskPermissions) {
        recommendations.push(`- ${perm.permission}: ${perm.description}`);
      }
    }
    
    if (mediumRiskPermissions.length > 0) {
      recommendations.push(`Medium-risk permissions (${mediumRiskPermissions.length}):`);
      for (const perm of mediumRiskPermissions) {
        recommendations.push(`- ${perm.permission}: ${perm.description}`);
      }
    }
    
    recommendations.push(
      'Consider if these permissions are necessary for the extension\'s functionality. Replace with a more privacy-focused alternative if available.'
    );
    
    // Recommend alternatives if available
    if (ext.recommandedAlternative) {
      recommendations.push(
        `Consider replacing with ${ext.recommandedAlternative} which may require fewer permissions.`
      );
    }
  }
  
  // Handle deprecated APIs
  if (ext.usesDeprecatedApis && ext.deprecatedApis) {
    // Only add this header if not already covered by other issues
    if (recommendations.length === 0) {
      recommendations.push(
        `${ext.name} v${ext.version} for ${ext.browser} uses deprecated APIs.`
      );
    } else {
      recommendations.push(
        `Additionally, this extension uses deprecated APIs.`
      );
    }
    
    for (const api of ext.deprecatedApis) {
      let apiDesc = `- ${api.api}: Deprecated since ${api.deprecatedSince}`;
      
      if (api.alternatives) {
        apiDesc += `, use ${api.alternatives} instead`;
      }
      
      if (api.removalTimeline) {
        apiDesc += `. Removal: ${api.removalTimeline}`;
      }
      
      recommendations.push(apiDesc);
    }
    
    recommendations.push(
      'This extension may stop working in future browser versions. Check if the developer has released an updated version.'
    );
    
    // Recommend alternatives if available
    if (ext.recommandedAlternative) {
      recommendations.push(
        `Consider replacing with ${ext.recommandedAlternative} which uses modern APIs.`
      );
    }
  }
  
  // Handle unmaintained extensions
  if (ext.isNotMaintained) {
    // Only add this if not already covered by other issues
    if (recommendations.length === 0) {
      recommendations.push(
        `${ext.name} v${ext.version} for ${ext.browser} appears to be unmaintained or abandoned.`
      );
    } else {
      recommendations.push(
        `Additionally, this extension appears to be unmaintained or abandoned.`
      );
    }
    
    if (ext.lastUpdateDate) {
      recommendations.push(
        `Last update was on ${ext.lastUpdateDate.toISOString().split('T')[0]}, which is more than ${config.maxUpdateAge || 365} days ago.`
      );
    }
    
    recommendations.push(
      `Consider finding an alternative, actively maintained extension.`
    );
    
    // Recommend alternatives if available
    if (ext.recommandedAlternative) {
      recommendations.push(
        `Consider replacing with ${ext.recommandedAlternative}.`
      );
    }
  }
  
  // Handle outdated extensions
  if (ext.isOutdated && ext.latestVersion) {
    // Only add this if not already covered by other issues
    if (recommendations.length === 0) {
      recommendations.push(
        `${ext.name} v${ext.version} for ${ext.browser} is outdated. Latest version is ${ext.latestVersion}.`
      );
      
      recommendations.push(
        `Update to the latest version to receive bug fixes, security improvements, and new features.`
      );
    } else if (!recommendations.some(r => r.includes('Update to the latest version'))) {
      // Add update recommendation if not already present
      recommendations.push(
        `Update to ${ext.latestVersion} to receive the latest improvements and fixes.`
      );
    }
  }
  
  // Add store link for more information
  if (ext.storeUrl) {
    recommendations.push('');
    recommendations.push(`Extension store page: ${ext.storeUrl}`);
  }
  
  // If no specific recommendations were made, add generic advice
  if (recommendations.length === 0) {
    recommendations.push(
      `Review ${ext.name} v${ext.version} for ${ext.browser} as part of regular extension maintenance.`
    );
  }
  
  return recommendations.join('\n');
}

/**
 * Check if a version is affected by a specified range
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
    const ranges = affectedVersions.split(',');
    return ranges.some(range => isVersionAffected(version, range.trim()));
  }
  
  // Check range with operators (very simplified)
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