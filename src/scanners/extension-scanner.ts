import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { exec } from 'child_process';
import { glob } from 'glob';
import { log } from '../utils/logging';
import { ExtensionIssue, ScannerConfig } from '../types/scanning';

const readFileAsync = promisify(fs.readFile);
const execAsync = promisify(exec);

/**
 * Configuration specific to extension scanning
 */
export interface ExtensionScannerConfig extends ScannerConfig {
  // Browser types to include in scan
  browsers?: Array<'chrome' | 'firefox' | 'safari' | 'edge'>;
  
  // Whether to scan installed extensions (requires browser access)
  scanInstalledExtensions?: boolean;
  
  // Whether to scan for extension manifests in the codebase
  scanForManifests?: boolean;
  
  // Whether to check for vulnerabilities
  checkVulnerabilities?: boolean;
  
  // Categories to include in scan
  categories?: string[];
  
  // Profile directories for each browser (for installed extensions scan)
  browserProfiles?: {
    chrome?: string;
    firefox?: string;
    safari?: string;
    edge?: string;
  };
  
  // Custom vulnerability database paths
  vulnerabilityDbPaths?: {
    extensions?: string;
  };
  
  // Extensions to exclude
  excludeExtensions?: string[];
}

/**
 * Information about a browser extension
 */
interface ExtensionInfo {
  name: string;
  id: string;
  version: string;
  browser: 'chrome' | 'firefox' | 'safari' | 'edge';
  manifestPath?: string;
  manifestVersion?: number;
  permissions?: string[];
  description?: string;
  author?: string;
  homepageUrl?: string;
  installedPath?: string;
  isBuiltIn?: boolean;
  updateUrl?: string;
  lastUpdated?: Date;
  categories?: string[];
  rating?: number;
  userCount?: number;
  latestVersion?: string;
  isOutdated?: boolean;
  isVulnerable?: boolean;
  isDeprecated?: boolean;
  hasCompatibilityIssues?: boolean;
  vulnerabilities?: {
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    cveIds?: string[];
    affectedVersions?: string;
    fixedInVersion?: string;
    url?: string;
  }[];
  compatibilityIssues?: {
    type: 'api_deprecated' | 'browser_update_required' | 'permission_changes' | 'manifest_version';
    description: string;
    remediation?: string;
  }[];
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
    log.info(`Scanning for extensions in browsers: ${browsers.join(', ')}`);
    
    // Collect extensions from both installed profiles and manifest files
    const extensions: ExtensionInfo[] = [];
    
    // Scan for extension manifest files in the codebase
    if (config.scanForManifests !== false) {
      for (const browser of browsers) {
        try {
          log.info(`Collecting ${browser} extension manifests`);
          const manifestExtensions = await collectExtensionManifests(browser, config);
          extensions.push(...manifestExtensions);
          log.info(`Found ${manifestExtensions.length} ${browser} extension manifests`);
        } catch (manifestError) {
          log.error(`Error collecting ${browser} extension manifests`, { error: manifestError });
        }
      }
    }
    
    // Scan for installed extensions in browser profiles
    if (config.scanInstalledExtensions) {
      for (const browser of browsers) {
        try {
          log.info(`Collecting installed ${browser} extensions`);
          const installedExtensions = await collectInstalledExtensions(browser, config);
          extensions.push(...installedExtensions);
          log.info(`Found ${installedExtensions.length} installed ${browser} extensions`);
        } catch (installedError) {
          log.error(`Error collecting installed ${browser} extensions`, { error: installedError });
        }
      }
    }
    
    log.info(`Found total of ${extensions.length} extensions to analyze`);
    
    // Filter extensions based on categories if specified
    let filteredExtensions = extensions;
    if (config.categories && config.categories.length > 0) {
      filteredExtensions = filteredExtensions.filter(ext => {
        if (!ext.categories || ext.categories.length === 0) {
          return false;
        }
        return ext.categories.some(cat => config.categories!.includes(cat));
      });
      log.info(`Filtered to ${filteredExtensions.length} extensions in specified categories`);
    }
    
    // Filter out excluded extensions
    if (config.excludeExtensions && config.excludeExtensions.length > 0) {
      filteredExtensions = filteredExtensions.filter(ext => {
        return !config.excludeExtensions!.some(excluded => {
          if (excluded === ext.id) {
            return true;
          }
          if (excluded.includes('*')) {
            const pattern = excluded.replace(/\*/g, '.*');
            return new RegExp(`^${pattern}$`).test(ext.id) || new RegExp(`^${pattern}$`).test(ext.name);
          }
          return false;
        });
      });
      log.info(`Filtered out excluded extensions, ${filteredExtensions.length} remaining`);
    }
    
    // Process each extension
    for (const ext of filteredExtensions) {
      try {
        log.info(`Checking extension: ${ext.name} (${ext.id}) for ${ext.browser}`);
        
        // Check for issues
        await checkExtensionForIssues(ext, config);
        
        // Create issue for problematic extensions
        if (ext.isOutdated || 
            ext.isVulnerable || 
            ext.isDeprecated || 
            ext.hasCompatibilityIssues) {
          
          const issue: ExtensionIssue = {
            detectedAt: new Date(),
            name: ext.name,
            id: ext.id,
            currentVersion: ext.version,
            latestVersion: ext.latestVersion,
            browser: ext.browser,
            isOutdated: ext.isOutdated || false,
            isVulnerable: ext.isVulnerable || false,
            vulnerabilities: ext.vulnerabilities || [],
            hasCompatibilityIssues: ext.hasCompatibilityIssues || false,
            compatibilityIssues: ext.compatibilityIssues || [],
            isDeprecated: ext.isDeprecated || false,
            deprecationDetails: ext.deprecationDetails,
            permissions: ext.permissions,
            manifestPath: ext.manifestPath,
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
 * Collect extension manifests from codebase
 */
async function collectExtensionManifests(
  browser: 'chrome' | 'firefox' | 'safari' | 'edge',
  config: ExtensionScannerConfig
): Promise<ExtensionInfo[]> {
  const extensions: ExtensionInfo[] = [];
  
  try {
    // Different manifest patterns based on browser type
    let manifestPattern: string;
    switch (browser) {
      case 'chrome':
      case 'edge':
        manifestPattern = '**/manifest.json';
        break;
      case 'firefox':
        manifestPattern = '**/manifest.json';
        break;
      case 'safari':
        manifestPattern = '**/*.safariextension/Info.plist';
        break;
      default:
        manifestPattern = '**/manifest.json';
    }
    
    // Find all manifest files
    const manifestPaths = await glob(manifestPattern, {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/node_modules/**',
        '**/bower_components/**',
        '**/dist/**',
        '**/build/**'
      ]
    });
    
    for (const manifestPath of manifestPaths) {
      try {
        // Skip if the directory structure suggests it's not an extension
        // For example, avoid manifest.json in a web app which isn't an extension
        if (!isLikelyExtensionDirectory(manifestPath, browser)) {
          continue;
        }
        
        let extension: ExtensionInfo | null = null;
        
        switch (browser) {
          case 'chrome':
          case 'edge':
            extension = await parseChromiumManifest(manifestPath, browser);
            break;
          case 'firefox':
            extension = await parseFirefoxManifest(manifestPath);
            break;
          case 'safari':
            extension = await parseSafariManifest(manifestPath);
            break;
        }
        
        if (extension) {
          extensions.push(extension);
        }
      } catch (manifestError) {
        log.warn(`Error processing manifest at ${manifestPath}`, { error: manifestError });
      }
    }
  } catch (error) {
    log.error(`Error collecting ${browser} extension manifests`, { error });
  }
  
  return extensions;
}

/**
 * Collect installed extensions from browser profiles
 */
async function collectInstalledExtensions(
  browser: 'chrome' | 'firefox' | 'safari' | 'edge',
  config: ExtensionScannerConfig
): Promise<ExtensionInfo[]> {
  const extensions: ExtensionInfo[] = [];
  
  try {
    // Determine browser profile path from configuration or default locations
    let profilePath = config.browserProfiles?.[browser];
    
    if (!profilePath) {
      // Default profile locations by OS and browser
      const homeDir = process.env.HOME || process.env.USERPROFILE || '';
      
      if (process.platform === 'darwin') { // macOS
        switch (browser) {
          case 'chrome':
            profilePath = path.join(homeDir, 'Library/Application Support/Google/Chrome/Default');
            break;
          case 'firefox':
            profilePath = path.join(homeDir, 'Library/Application Support/Firefox/Profiles');
            break;
          case 'safari':
            profilePath = path.join(homeDir, 'Library/Safari/Extensions');
            break;
          case 'edge':
            profilePath = path.join(homeDir, 'Library/Application Support/Microsoft Edge/Default');
            break;
        }
      } else if (process.platform === 'win32') { // Windows
        const appData = process.env.APPDATA || '';
        const localAppData = process.env.LOCALAPPDATA || '';
        
        switch (browser) {
          case 'chrome':
            profilePath = path.join(localAppData, 'Google/Chrome/User Data/Default');
            break;
          case 'firefox':
            profilePath = path.join(appData, 'Mozilla/Firefox/Profiles');
            break;
          case 'safari':
            // Safari is not available on Windows
            return [];
          case 'edge':
            profilePath = path.join(localAppData, 'Microsoft/Edge/User Data/Default');
            break;
        }
      } else if (process.platform === 'linux') { // Linux
        switch (browser) {
          case 'chrome':
            profilePath = path.join(homeDir, '.config/google-chrome/Default');
            break;
          case 'firefox':
            profilePath = path.join(homeDir, '.mozilla/firefox');
            break;
          case 'safari':
            // Safari is not available on Linux
            return [];
          case 'edge':
            profilePath = path.join(homeDir, '.config/microsoft-edge/Default');
            break;
        }
      }
    }
    
    if (!profilePath || !fs.existsSync(profilePath)) {
      log.warn(`Browser profile path not found for ${browser}: ${profilePath}`);
      return [];
    }
    
    // Different approaches based on browser
    switch (browser) {
      case 'chrome':
      case 'edge':
        extensions.push(...await getChromiumInstalledExtensions(profilePath, browser));
        break;
      case 'firefox':
        extensions.push(...await getFirefoxInstalledExtensions(profilePath));
        break;
      case 'safari':
        extensions.push(...await getSafariInstalledExtensions(profilePath));
        break;
    }
  } catch (error) {
    log.error(`Error collecting installed ${browser} extensions`, { error });
  }
  
  return extensions;
}

/**
 * Check if a directory is likely to be a browser extension based on its structure
 */
function isLikelyExtensionDirectory(manifestPath: string, browser: string): boolean {
  const dirPath = path.dirname(manifestPath);
  
  // Check for common extension files based on browser type
  switch (browser) {
    case 'chrome':
    case 'edge': {
      // Chrome extensions typically have background.js or content scripts
      const hasBackgroundJs = fs.existsSync(path.join(dirPath, 'background.js')) || 
                             fs.existsSync(path.join(dirPath, 'background/background.js')) ||
                             fs.existsSync(path.join(dirPath, 'scripts/background.js'));
                             
      const hasContentScripts = fs.existsSync(path.join(dirPath, 'content.js')) || 
                               fs.existsSync(path.join(dirPath, 'content_scripts'));
                               
      const hasPopupHtml = fs.existsSync(path.join(dirPath, 'popup.html')) || 
                          fs.existsSync(path.join(dirPath, 'popup/popup.html'));
      
      return hasBackgroundJs || hasContentScripts || hasPopupHtml;
    }
    
    case 'firefox': {
      // Firefox extensions might have additional files
      const hasBackgroundJs = fs.existsSync(path.join(dirPath, 'background.js'));
      const hasContentScripts = fs.existsSync(path.join(dirPath, 'content_scripts')) || 
                               fs.existsSync(path.join(dirPath, 'content'));
      const hasOptionsHtml = fs.existsSync(path.join(dirPath, 'options.html'));
      
      return hasBackgroundJs || hasContentScripts || hasOptionsHtml;
    }
    
    case 'safari': {
      // Safari extension Info.plist file is more specific
      return true;
    }
    
    default:
      return false;
  }
}

/**
 * Parse Chrome/Edge extension manifest
 */
async function parseChromiumManifest(
  manifestPath: string,
  browser: 'chrome' | 'edge'
): Promise<ExtensionInfo | null> {
  try {
    const manifestContent = await readFileAsync(manifestPath, 'utf8');
    const manifest = JSON.parse(manifestContent);
    
    // Check if it's actually a browser extension manifest
    if (!manifest.manifest_version || !manifest.name) {
      return null;
    }
    
    const extension: ExtensionInfo = {
      name: manifest.name,
      id: manifest.key || path.basename(path.dirname(manifestPath)), // Fallback ID
      version: manifest.version || '0.0.0',
      browser,
      manifestPath,
      manifestVersion: manifest.manifest_version,
      permissions: manifest.permissions || [],
      description: manifest.description,
      author: manifest.author,
      homepageUrl: manifest.homepage_url,
      updateUrl: manifest.update_url
    };
    
    // Additional permissions from optional_permissions and host_permissions (Manifest V3)
    if (manifest.optional_permissions) {
      extension.permissions = [...extension.permissions, ...manifest.optional_permissions];
    }
    
    if (manifest.host_permissions) {
      extension.permissions = [...extension.permissions, ...manifest.host_permissions];
    }
    
    return extension;
  } catch (error) {
    log.warn(`Error parsing Chromium manifest at ${manifestPath}`, { error });
    return null;
  }
}

/**
 * Parse Firefox extension manifest
 */
async function parseFirefoxManifest(
  manifestPath: string
): Promise<ExtensionInfo | null> {
  try {
    const manifestContent = await readFileAsync(manifestPath, 'utf8');
    const manifest = JSON.parse(manifestContent);
    
    // Check if it's actually a browser extension manifest
    if (!manifest.manifest_version || !manifest.name) {
      return null;
    }
    
    // Firefox extension special handling
    const extension: ExtensionInfo = {
      name: manifest.name,
      id: manifest.browser_specific_settings?.gecko?.id || 
          manifest.applications?.gecko?.id || 
          path.basename(path.dirname(manifestPath)), // Fallback ID
      version: manifest.version || '0.0.0',
      browser: 'firefox',
      manifestPath,
      manifestVersion: manifest.manifest_version,
      permissions: manifest.permissions || [],
      description: manifest.description,
      author: manifest.author,
      homepageUrl: manifest.homepage_url
    };
    
    // Mozilla extensions may have additional update url
    if (manifest.applications?.gecko?.update_url || manifest.browser_specific_settings?.gecko?.update_url) {
      extension.updateUrl = manifest.applications?.gecko?.update_url || 
                           manifest.browser_specific_settings?.gecko?.update_url;
    }
    
    return extension;
  } catch (error) {
    log.warn(`Error parsing Firefox manifest at ${manifestPath}`, { error });
    return null;
  }
}

/**
 * Parse Safari extension manifest (Info.plist)
 */
async function parseSafariManifest(
  manifestPath: string
): Promise<ExtensionInfo | null> {
  try {
    // Safari uses XML plist format which is harder to parse in pure JS
    // For a complete implementation, you would use a plist parser
    // This is a simplified version that uses grep with exec
    
    const { stdout: name } = await execAsync(`grep -A 1 CFBundleDisplayName "${manifestPath}" | grep string | sed 's/.*>\(.*\)<\/string>.*/\1/'`);
    const { stdout: version } = await execAsync(`grep -A 1 CFBundleShortVersionString "${manifestPath}" | grep string | sed 's/.*>\(.*\)<\/string>.*/\1/'`);
    const { stdout: bundleId } = await execAsync(`grep -A 1 CFBundleIdentifier "${manifestPath}" | grep string | sed 's/.*>\(.*\)<\/string>.*/\1/'`);
    
    if (!name.trim() || !version.trim()) {
      return null;
    }
    
    // We can't easily get permissions from Info.plist without a proper parser
    const extension: ExtensionInfo = {
      name: name.trim(),
      id: bundleId.trim() || path.basename(path.dirname(manifestPath)),
      version: version.trim() || '0.0.0',
      browser: 'safari',
      manifestPath,
      permissions: []
    };
    
    return extension;
  } catch (error) {
    log.warn(`Error parsing Safari manifest at ${manifestPath}`, { error });
    return null;
  }
}

/**
 * Get Chrome/Edge installed extensions
 */
async function getChromiumInstalledExtensions(
  profilePath: string,
  browser: 'chrome' | 'edge'
): Promise<ExtensionInfo[]> {
  const extensions: ExtensionInfo[] = [];
  
  try {
    // Extensions are stored in the Extensions directory
    const extensionsDir = path.join(profilePath, 'Extensions');
    
    if (!fs.existsSync(extensionsDir)) {
      log.warn(`Extensions directory not found for ${browser}: ${extensionsDir}`);
      return [];
    }
    
    // Each subdirectory is an extension ID
    const extIds = fs.readdirSync(extensionsDir);
    
    for (const extId of extIds) {
      const extDir = path.join(extensionsDir, extId);
      
      if (fs.statSync(extDir).isDirectory()) {
        // Each extension can have multiple versions
        const versionDirs = fs.readdirSync(extDir);
        
        if (versionDirs.length > 0) {
          // Use the highest version number
          const latestVersion = versionDirs.sort().pop() || '';
          const manifestPath = path.join(extDir, latestVersion, 'manifest.json');
          
          if (fs.existsSync(manifestPath)) {
            try {
              const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
              
              const extension: ExtensionInfo = {
                name: manifest.name,
                id: extId,
                version: manifest.version || latestVersion,
                browser,
                manifestPath,
                manifestVersion: manifest.manifest_version,
                permissions: manifest.permissions || [],
                description: manifest.description,
                author: manifest.author,
                homepageUrl: manifest.homepage_url,
                installedPath: path.join(extDir, latestVersion)
              };
              
              // Additional permissions from optional_permissions and host_permissions (Manifest V3)
              if (manifest.optional_permissions) {
                extension.permissions = [...extension.permissions, ...manifest.optional_permissions];
              }
              
              if (manifest.host_permissions) {
                extension.permissions = [...extension.permissions, ...manifest.host_permissions];
              }
              
              // Determine if it's a built-in extension
              if (isBuiltInChromiumExtension(extId, browser)) {
                extension.isBuiltIn = true;
              }
              
              extensions.push(extension);
            } catch (manifestError) {
              log.warn(`Error parsing manifest for installed extension ${extId}`, { error: manifestError });
            }
          }
        }
      }
    }
  } catch (error) {
    log.error(`Error getting installed ${browser} extensions`, { error });
  }
  
  return extensions;
}

/**
 * Get Firefox installed extensions
 */
async function getFirefoxInstalledExtensions(
  profilePath: string
): Promise<ExtensionInfo[]> {
  const extensions: ExtensionInfo[] = [];
  
  try {
    // Firefox stores extensions in multiple ways
    // First, find all profile directories
    let profileDirs: string[] = [];
    
    if (fs.statSync(profilePath).isDirectory()) {
      // If path is a directory, look for profile directories or use it as is
      if (fs.existsSync(path.join(profilePath, 'extensions'))) {
        // It's a specific profile directory
        profileDirs = [profilePath];
      } else {
        // It's the profiles root, find all profiles
        const entries = fs.readdirSync(profilePath);
        for (const entry of entries) {
          const fullPath = path.join(profilePath, entry);
          if (fs.statSync(fullPath).isDirectory() && fs.existsSync(path.join(fullPath, 'extensions'))) {
            profileDirs.push(fullPath);
          }
        }
      }
    }
    
    // Process each profile directory
    for (const profileDir of profileDirs) {
      const extensionsDir = path.join(profileDir, 'extensions');
      
      if (fs.existsSync(extensionsDir)) {
        const extEntries = fs.readdirSync(extensionsDir);
        
        for (const entry of extEntries) {
          const extPath = path.join(extensionsDir, entry);
          
          if (fs.statSync(extPath).isDirectory() || fs.statSync(extPath).isFile()) {
            try {
              let manifestPath: string;
              
              if (fs.statSync(extPath).isFile() && extPath.endsWith('.xpi')) {
                // This is a packed extension, we can't easily read the manifest
                // For a full implementation, use a ZIP parser to extract the manifest.json
                continue;
              } else {
                // It's an unpacked extension directory
                manifestPath = path.join(extPath, 'manifest.json');
              }
              
              if (fs.existsSync(manifestPath)) {
                const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
                
                const extension: ExtensionInfo = {
                  name: manifest.name,
                  id: entry, // The directory name is usually the extension ID
                  version: manifest.version || '0.0.0',
                  browser: 'firefox',
                  manifestPath,
                  manifestVersion: manifest.manifest_version,
                  permissions: manifest.permissions || [],
                  description: manifest.description,
                  author: manifest.author,
                  installedPath: extPath
                };
                
                if (manifest.applications?.gecko?.id) {
                  extension.id = manifest.applications.gecko.id;
                }
                
                if (manifest.browser_specific_settings?.gecko?.id) {
                  extension.id = manifest.browser_specific_settings.gecko.id;
                }
                
                // Determine if it's a built-in extension
                if (isBuiltInFirefoxExtension(extension.id)) {
                  extension.isBuiltIn = true;
                }
                
                extensions.push(extension);
              }
            } catch (extError) {
              log.warn(`Error processing Firefox extension at ${extPath}`, { error: extError });
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
 * Get Safari installed extensions
 */
async function getSafariInstalledExtensions(
  profilePath: string
): Promise<ExtensionInfo[]> {
  const extensions: ExtensionInfo[] = [];
  
  try {
    // Safari extensions directory structure is different
    if (!fs.existsSync(profilePath)) {
      log.warn(`Safari extensions directory not found: ${profilePath}`);
      return [];
    }
    
    const entries = fs.readdirSync(profilePath);
    
    for (const entry of entries) {
      const extPath = path.join(profilePath, entry);
      
      if (fs.statSync(extPath).isDirectory() && entry.endsWith('.safariextz')) {
        // For safari extensions, we parse the Info.plist file
        const infoPlistPath = path.join(extPath, 'Info.plist');
        
        if (fs.existsSync(infoPlistPath)) {
          try {
            // Safari uses XML plist format which is harder to parse in pure JS
            // For a complete implementation, use a plist parser
            // This is a simplified version that uses grep with exec
            
            const { stdout: name } = await execAsync(`grep -A 1 CFBundleDisplayName "${infoPlistPath}" | grep string | sed 's/.*>\(.*\)<\/string>.*/\1/'`);
            const { stdout: version } = await execAsync(`grep -A 1 CFBundleShortVersionString "${infoPlistPath}" | grep string | sed 's/.*>\(.*\)<\/string>.*/\1/'`);
            const { stdout: bundleId } = await execAsync(`grep -A 1 CFBundleIdentifier "${infoPlistPath}" | grep string | sed 's/.*>\(.*\)<\/string>.*/\1/'`);
            
            if (!name.trim() || !version.trim()) {
              continue;
            }
            
            const extension: ExtensionInfo = {
              name: name.trim(),
              id: bundleId.trim() || path.basename(extPath, '.safariextz'),
              version: version.trim() || '0.0.0',
              browser: 'safari',
              manifestPath: infoPlistPath,
              permissions: [],
              installedPath: extPath
            };
            
            extensions.push(extension);
          } catch (plistError) {
            log.warn(`Error parsing Safari extension Info.plist at ${infoPlistPath}`, { error: plistError });
          }
        }
      }
    }
  } catch (error) {
    log.error('Error getting installed Safari extensions', { error });
  }
  
  return extensions;
}

/**
 * Check if an extension is a built-in Chrome/Edge extension
 */
function isBuiltInChromiumExtension(id: string, browser: 'chrome' | 'edge'): boolean {
  const chromeBuiltInExtensions = [
    'nmmhkkegccagdldgiimedpiccmgmieda', // Chrome Web Store Payments
    'pkedcjkdefgpdelpbcmbmeomcjbeemfm', // Chrome Cast
    'ghbmnnjooekpmoecnnnilnnbdlolhkhi', // Google Docs Offline
    'mhjfbmdgcfjbbpaeojofohoefgiehjai', // Chrome PDF Viewer
    'neajdppkdcdipfabeoofebfddakdcjhd', // Google Network Speech
    'aapocclcgogkmnckokdopfmhonfmgoek', // Slides
    'felcaaldnbdncclmgdcncolpebgiejap', // Sheets
    'aohghmighlieiainnegkcijnfilokake', // Docs
    'apdfllckaahabafndbhieahigkjlhalf', // Google Drive
    'blpcfgokakmgnkcojhhkbfbldkacnbeo'  // YouTube
  ];
  
  const edgeBuiltInExtensions = [
    'jmjflgjpcpepeafmmgdpfkogkghcpiha', // Microsoft Store
    'gpdjojdkbbmdfjfahjcgigfpmkopogic', // Edge PDF Viewer
    'ggjhpefgjjfobnfoldnjipclpcfbgbhl', // Microsoft Excel
    'efaidnbmnnnibpcajpcglclefindmkaj'  // Edge Adobe Acrobat
  ];
  
  if (browser === 'chrome') {
    return chromeBuiltInExtensions.includes(id);
  } else if (browser === 'edge') {
    return edgeBuiltInExtensions.includes(id);
  }
  
  return false;
}

/**
 * Check if an extension is a built-in Firefox extension
 */
function isBuiltInFirefoxExtension(id: string): boolean {
  const firefoxBuiltInExtensions = [
    'firefox@getpocket.com',
    'screenshots@mozilla.org',
    'webcompat-reporter@mozilla.org',
    'webcompat@mozilla.org',
    'default-theme@mozilla.org',
    'formautofill@mozilla.org'
  ];
  
  return firefoxBuiltInExtensions.includes(id);
}

/**
 * Check extension for issues
 */
async function checkExtensionForIssues(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<void> {
  try {
    // Check for updates
    await checkForExtensionUpdates(ext, config);
    
    // Check for vulnerabilities if configured
    if (config.checkVulnerabilities) {
      await checkForExtensionVulnerabilities(ext, config);
    }
    
    // Check for compatibility issues
    await checkForCompatibilityIssues(ext, config);
    
    // Check if deprecated
    await checkIfExtensionDeprecated(ext, config);
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
    // Different approach based on browser type
    switch (ext.browser) {
      case 'chrome':
      case 'edge':
        await checkChromeExtensionUpdates(ext, config);
        break;
      case 'firefox':
        await checkFirefoxExtensionUpdates(ext, config);
        break;
      case 'safari':
        await checkSafariExtensionUpdates(ext, config);
        break;
    }
  } catch (error) {
    log.warn(`Error checking updates for extension ${ext.name}`, { error });
  }
}

/**
 * Check for Chrome/Edge extension updates
 */
async function checkChromeExtensionUpdates(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<void> {
  try {
    // Chrome/Edge extensions can be checked in the Web Store
    // For a complete implementation, you would query the Chrome Web Store API
    // or scrape the store page. Here's a simplified version:
    
    if (ext.isBuiltIn) {
      // Built-in extensions are managed by the browser, so we assume they're current
      return;
    }
    
    // Try to get info from Chrome Web Store
    try {
      const { stdout } = await execAsync(`curl -s "https://chrome.google.com/webstore/detail/${ext.id}" | grep -o '"version": "[^"]*"' | head -1`);
      
      if (stdout.trim()) {
        const versionMatch = stdout.match(/"version":\s*"([^"]+)"/);
        if (versionMatch && versionMatch[1]) {
          ext.latestVersion = versionMatch[1];
          
          // Compare versions
          if (ext.version !== ext.latestVersion) {
            // Use semver for proper version comparison
            try {
              const semver = require('semver');
              ext.isOutdated = semver.lt(ext.version, ext.latestVersion);
            } catch (semverError) {
              // Simple string comparison if semver is not available
              ext.isOutdated = ext.version !== ext.latestVersion;
            }
          }
        }
      }
    } catch (storeError) {
      log.debug(`Could not get Chrome Web Store info for ${ext.id}`, { error: storeError });
    }
    
    // If we couldn't get the latest version from the store,
    // check if the extension has an update URL in the manifest
    if (!ext.latestVersion && ext.updateUrl) {
      try {
        // Most extensions use Chrome Web Store or custom update servers
        // For custom update servers, you would need to implement specific logic
        // based on the server format (usually XML-based)
        log.debug(`Extension ${ext.name} uses custom update URL: ${ext.updateUrl}`);
      } catch (updateError) {
        log.debug(`Error checking custom update for ${ext.name}`, { error: updateError });
      }
    }
  } catch (error) {
    log.warn(`Error checking Chrome/Edge extension updates for ${ext.name}`, { error });
  }
}

/**
 * Check for Firefox extension updates
 */
async function checkFirefoxExtensionUpdates(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<void> {
  try {
    // Firefox extensions can be checked in the Mozilla Add-ons site
    if (ext.isBuiltIn) {
      // Built-in extensions are managed by the browser
      return;
    }
    
    // Try to get info from Mozilla Add-ons
    try {
      const { stdout } = await execAsync(`curl -s "https://addons.mozilla.org/api/v4/addons/addon/${ext.id}"`);
      
      try {
        const addonInfo = JSON.parse(stdout);
        if (addonInfo && addonInfo.current_version) {
          ext.latestVersion = addonInfo.current_version.version;
          
          // Compare versions
          if (ext.version !== ext.latestVersion) {
            // Use semver for proper version comparison
            try {
              const semver = require('semver');
              ext.isOutdated = semver.lt(ext.version, ext.latestVersion);
            } catch (semverError) {
              // Simple string comparison if semver is not available
              ext.isOutdated = ext.version !== ext.latestVersion;
            }
          }
        }
      } catch (jsonError) {
        log.debug(`Error parsing Mozilla Add-ons API response for ${ext.id}`, { error: jsonError });
      }
    } catch (addonError) {
      log.debug(`Could not get Mozilla Add-ons info for ${ext.id}`, { error: addonError });
    }
    
    // If we couldn't get the latest version from the store,
    // check if the extension has an update URL in the manifest
    if (!ext.latestVersion && ext.updateUrl) {
      try {
        // Mozilla extensions might use custom update servers
        log.debug(`Extension ${ext.name} uses custom update URL: ${ext.updateUrl}`);
      } catch (updateError) {
        log.debug(`Error checking custom update for ${ext.name}`, { error: updateError });
      }
    }
  } catch (error) {
    log.warn(`Error checking Firefox extension updates for ${ext.name}`, { error });
  }
}

/**
 * Check for Safari extension updates
 */
async function checkSafariExtensionUpdates(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<void> {
  try {
    // Safari extensions are typically distributed through the App Store
    // which makes programmatic checking more challenging
    log.debug(`Safari extension update checking is limited: ${ext.name}`);
    
    // For installed extensions, we might check the last modification date
    // as a proxy for update recency
    if (ext.installedPath) {
      try {
        const stats = fs.statSync(ext.installedPath);
        const lastModified = stats.mtime;
        const sixMonthsAgo = new Date();
        sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
        
        // If the extension hasn't been updated in 6+ months, it might be outdated
        if (lastModified < sixMonthsAgo) {
          ext.isOutdated = true;
          ext.latestVersion = 'unknown'; // We don't know what the latest version is
        }
      } catch (statError) {
        log.debug(`Error checking last modified date for ${ext.name}`, { error: statError });
      }
    }
  } catch (error) {
    log.warn(`Error checking Safari extension updates for ${ext.name}`, { error });
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
        
        // Check by extension ID
        if (vulnDb[ext.id]) {
          const vulnerabilities = [];
          
          for (const vuln of vulnDb[ext.id]) {
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
          
          if (vulnerabilities.length > 0) {
            ext.vulnerabilities = vulnerabilities;
            ext.isVulnerable = true;
          }
        }
      } catch (dbError) {
        log.warn(`Error reading extension vulnerability database`, { error: dbError });
      }
    }
    
    // Check for known vulnerable extensions
    // This is a basic implementation - a real system would use a proper vulnerability database
    checkForKnownVulnerableExtensions(ext);
    
    // If extension has high-risk permissions, add a low severity issue
    if (!ext.isVulnerable && hasHighRiskPermissions(ext)) {
      ext.isVulnerable = true;
      ext.vulnerabilities = [{
        severity: 'low',
        description: 'Extension requests high-risk permissions that could pose a security risk if compromised',
        affectedVersions: '*',
        fixedInVersion: undefined
      }];
    }
  } catch (error) {
    log.warn(`Error checking vulnerabilities for extension ${ext.name}`, { error });
  }
}

/**
 * Check for compatibility issues
 */
async function checkForCompatibilityIssues(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<void> {
  try {
    const compatIssues: {
      type: 'api_deprecated' | 'browser_update_required' | 'permission_changes' | 'manifest_version';
      description: string;
      remediation?: string;
    }[] = [];
    
    // Check for manifest version issues
    if ((ext.browser === 'chrome' || ext.browser === 'edge') && 
        ext.manifestVersion && ext.manifestVersion < 3) {
      compatIssues.push({
        type: 'manifest_version',
        description: 'Extension uses Manifest V2 which is being deprecated by Chrome/Edge',
        remediation: 'Migrate to Manifest V3 format'
      });
    }
    
    // Check for deprecated permissions
    if (ext.permissions && ext.permissions.length > 0) {
      const deprecatedPermissions = getDeprecatedPermissions(ext);
      
      if (deprecatedPermissions.length > 0) {
        compatIssues.push({
          type: 'permission_changes',
          description: `Extension uses deprecated permissions: ${deprecatedPermissions.join(', ')}`,
          remediation: 'Update extension to use alternative APIs for these permissions'
        });
      }
    }
    
    // Check for deprecated APIs based on permissions
    // This would require a comprehensive database of deprecated APIs
    // This is a simplified check for common cases
    if (ext.permissions && ext.permissions.some(p => p === 'webRequest' || p === 'webRequestBlocking')) {
      if (ext.browser === 'chrome' || ext.browser === 'edge') {
        compatIssues.push({
          type: 'api_deprecated',
          description: 'Extension uses webRequest/webRequestBlocking which is being restricted in Manifest V3',
          remediation: 'Migrate to declarativeNetRequest API'
        });
      }
    }
    
    // If there are any compatibility issues, update the extension info
    if (compatIssues.length > 0) {
      ext.hasCompatibilityIssues = true;
      ext.compatibilityIssues = compatIssues;
    }
  } catch (error) {
    log.warn(`Error checking compatibility issues for extension ${ext.name}`, { error });
  }
}

/**
 * Check if an extension is deprecated
 */
async function checkIfExtensionDeprecated(
  ext: ExtensionInfo,
  config: ExtensionScannerConfig
): Promise<void> {
  try {
    // Check for known deprecated extensions
    if (isKnownDeprecatedExtension(ext)) {
      ext.isDeprecated = true;
      ext.deprecationDetails = getDeprecationDetails(ext);
      return;
    }
    
    // Check for signs of abandonment
    if (ext.latestVersion) {
      // If the extension hasn't been updated in years, it might be abandoned
      // We would need to get the last update date from the store
      // This is a placeholder for that logic
    }
    
    // For Chrome/Edge, check if it's explicitly marked as deprecated in the Web Store
    if ((ext.browser === 'chrome' || ext.browser === 'edge') && ext.id) {
      try {
        const { stdout } = await execAsync(`curl -s "https://chrome.google.com/webstore/detail/${ext.id}" | grep -i deprecated`);
        
        if (stdout.trim() && (stdout.includes('deprecated') || stdout.includes('Deprecated'))) {
          ext.isDeprecated = true;
          ext.deprecationDetails = {
            reason: 'Extension appears to be marked as deprecated in the Chrome Web Store'
          };
        }
      } catch (storeError) {
        // Grep will exit with non-zero if nothing is found, which is normal
      }
    }
    
    // For Firefox, check if it's marked as discontinued on AMO
    if (ext.browser === 'firefox' && ext.id) {
      try {
        const { stdout } = await execAsync(`curl -s "https://addons.mozilla.org/api/v4/addons/addon/${ext.id}"`);
        
        try {
          const addonInfo = JSON.parse(stdout);
          if (addonInfo && addonInfo.status === 'discontinued') {
            ext.isDeprecated = true;
            ext.deprecationDetails = {
              reason: 'Extension is marked as discontinued on Mozilla Add-ons'
            };
          }
        } catch (jsonError) {
          log.debug(`Error parsing Mozilla Add-ons API response for deprecated check`, { error: jsonError });
        }
      } catch (addonError) {
        log.debug(`Could not check if Firefox extension is deprecated`, { error: addonError });
      }
    }
  } catch (error) {
    log.warn(`Error checking if extension ${ext.name} is deprecated`, { error });
  }
}

/**
 * Check if extension is among known vulnerable extensions
 */
function checkForKnownVulnerableExtensions(ext: ExtensionInfo): void {
  // This is a very simplified list for demonstration
  // A real implementation would use a comprehensive vulnerability database
  const knownVulnerableExtensions: Record<string, {
    id: string;
    browser: string;
    affectedVersions: string;
    fixedInVersion?: string;
    description: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    cveIds?: string[];
  }[]> = {
    // Examples of vulnerable extensions (hypothetical examples)
    'fheoggkfdfchfphceeifdbepaooicaho': [{
      id: 'fheoggkfdfchfphceeifdbepaooicaho',
      browser: 'chrome',
      affectedVersions: '<1.2.0',
      fixedInVersion: '1.2.0',
      description: 'Vulnerable to cross-site scripting attacks',
      severity: 'high',
      cveIds: ['CVE-2023-12345']
    }],
    'jid1-KKzOGWgsW3Ao4Q': [{
      id: 'jid1-KKzOGWgsW3Ao4Q',
      browser: 'firefox',
      affectedVersions: '<2.0.0',
      fixedInVersion: '2.0.0',
      description: 'Allows unauthorized access to browser data',
      severity: 'critical',
      cveIds: ['CVE-2023-54321']
    }]
  };
  
  if (knownVulnerableExtensions[ext.id]) {
    for (const vuln of knownVulnerableExtensions[ext.id]) {
      if (vuln.browser === ext.browser && isVersionAffected(ext.version, vuln.affectedVersions)) {
        ext.isVulnerable = true;
        ext.vulnerabilities = ext.vulnerabilities || [];
        ext.vulnerabilities.push({
          severity: vuln.severity,
          description: vuln.description,
          affectedVersions: vuln.affectedVersions,
          fixedInVersion: vuln.fixedInVersion,
          cveIds: vuln.cveIds
        });
      }
    }
  }
}

/**
 * Check if extension has high-risk permissions
 */
function hasHighRiskPermissions(ext: ExtensionInfo): boolean {
  if (!ext.permissions || ext.permissions.length === 0) {
    return false;
  }
  
  const highRiskPermissions = [
    'tabs', // Can access tab information
    '<all_urls>', // Can access all websites
    'http://*/*', // Can access all HTTP sites
    'https://*/*', // Can access all HTTPS sites
    'history', // Can access browsing history
    'webRequest', // Can intercept network requests
    'webRequestBlocking', // Can block network requests
    'proxy', // Can control proxy settings
    'privacy', // Can control privacy settings
    'cookies', // Can access cookies
    'downloads', // Can access downloads
    'clipboardWrite', // Can write to clipboard
    'clipboardRead', // Can read from clipboard
    'bookmarks', // Can access bookmarks
    'management', // Can manage extensions
    'nativeMessaging' // Can communicate with native apps
  ];
  
  return ext.permissions.some(p => highRiskPermissions.includes(p) || p.includes('://') || p.includes('*'));
}

/**
 * Get list of deprecated permissions for an extension
 */
function getDeprecatedPermissions(ext: ExtensionInfo): string[] {
  const deprecatedPermissions: Record<string, string[]> = {
    chrome: [
      'background', // Deprecated in Manifest V3
      'webRequest.RequestFilter', // Restricted in Manifest V3
      'webRequestBlocking' // Deprecated in Manifest V3
    ],
    edge: [
      'background', // Deprecated in Manifest V3
      'webRequest.RequestFilter', // Restricted in Manifest V3
      'webRequestBlocking' // Deprecated in Manifest V3
    ],
    firefox: [
      'experiments.clipboard', // Deprecated
      'experiments.identity' // Deprecated
    ],
    safari: [
      // Safari-specific deprecated permissions would go here
    ]
  };
  
  if (!ext.permissions || !deprecatedPermissions[ext.browser]) {
    return [];
  }
  
  return ext.permissions.filter(p => deprecatedPermissions[ext.browser].includes(p));
}

/**
 * Check if extension is known to be deprecated
 */
function isKnownDeprecatedExtension(ext: ExtensionInfo): boolean {
  // This is a simplified list for demonstration
  // A real implementation would use a comprehensive database
  const knownDeprecatedExtensions: Record<string, {
    id: string;
    browser: string;
    reason?: string;
    alternatives?: string[];
  }[]> = {
    // Examples of deprecated extensions (hypothetical examples)
    'nkbihfbeogaeaoehlefnkodbefgpgknn': [{
      id: 'nkbihfbeogaeaoehlefnkodbefgpgknn',
      browser: 'chrome',
      reason: 'Replaced by newer extension',
      alternatives: ['MetaMask: Ethereum Wallet']
    }],
    'firefox@getpocket.com': [{
      id: 'firefox@getpocket.com',
      browser: 'firefox',
      reason: 'Functionality integrated into browser',
      alternatives: ['Built-in Pocket feature']
    }]
  };
  
  return !!knownDeprecatedExtensions[ext.id]?.some(d => d.browser === ext.browser);
}

/**
 * Get deprecation details for a known deprecated extension
 */
function getDeprecationDetails(ext: ExtensionInfo): {
  deprecationDate?: Date;
  endOfSupportDate?: Date;
  reason?: string;
  alternatives?: string[];
} {
  // This is a simplified list for demonstration
  // A real implementation would use a comprehensive database
  const knownDeprecatedExtensions: Record<string, {
    id: string;
    browser: string;
    deprecationDate?: string;
    endOfSupportDate?: string;
    reason?: string;
    alternatives?: string[];
  }[]> = {
    // Examples of deprecated extensions (hypothetical examples)
    'nkbihfbeogaeaoehlefnkodbefgpgknn': [{
      id: 'nkbihfbeogaeaoehlefnkodbefgpgknn',
      browser: 'chrome',
      deprecationDate: '2022-06-01',
      endOfSupportDate: '2022-12-31',
      reason: 'Replaced by newer extension',
      alternatives: ['MetaMask: Ethereum Wallet']
    }],
    'firefox@getpocket.com': [{
      id: 'firefox@getpocket.com',
      browser: 'firefox',
      deprecationDate: '2023-01-15',
      reason: 'Functionality integrated into browser',
      alternatives: ['Built-in Pocket feature']
    }]
  };
  
  if (!knownDeprecatedExtensions[ext.id]) {
    return {
      reason: 'Extension appears to be deprecated or abandoned'
    };
  }
  
  const depInfo = knownDeprecatedExtensions[ext.id].find(d => d.browser === ext.browser);
  
  if (!depInfo) {
    return {
      reason: 'Extension appears to be deprecated or abandoned'
    };
  }
  
  return {
    deprecationDate: depInfo.deprecationDate ? new Date(depInfo.deprecationDate) : undefined,
    endOfSupportDate: depInfo.endOfSupportDate ? new Date(depInfo.endOfSupportDate) : undefined,
    reason: depInfo.reason,
    alternatives: depInfo.alternatives
  };
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
  if (ext.vulnerabilities && ext.vulnerabilities.length > 0) {
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
  
  // Then consider deprecation
  if (ext.isDeprecated) {
    // Deprecated extensions are at least medium risk
    if (riskLevel === 'low') riskLevel = 'medium';
    
    // If already has vulnerabilities and is deprecated, raise to high
    if (ext.vulnerabilities && ext.vulnerabilities.length > 0 && riskLevel === 'medium') {
      riskLevel = 'high';
    }
  }
  
  // Consider compatibility issues
  if (ext.hasCompatibilityIssues) {
    // Compatibility issues are at least medium risk
    if (riskLevel === 'low') riskLevel = 'medium';
    
    // Check for manifest version issues which could be higher risk
    if (ext.compatibilityIssues && ext.compatibilityIssues.some(i => i.type === 'manifest_version')) {
      if (riskLevel === 'medium') riskLevel = 'high';
    }
  }
  
  // Consider how outdated the extension is
  if (ext.isOutdated && ext.version && ext.latestVersion) {
    try {
      // Check if it's a major version behind
      if (isMajorVersionUpdate(ext.version, ext.latestVersion)) {
        // Being a major version behind is at least medium risk
        if (riskLevel === 'low') riskLevel = 'medium';
        
        // Multiple major versions behind is high risk
        const currentMajor = parseInt(ext.version.split('.')[0], 10);
        const latestMajor = parseInt(ext.latestVersion.split('.')[0], 10);
        
        if (latestMajor - currentMajor >= 2) {
          if (riskLevel === 'medium') riskLevel = 'high';
        }
      }
    } catch (parseError) {
      // If version parsing fails, default to medium for outdated extensions
      if (riskLevel === 'low') riskLevel = 'medium';
    }
  }
  
  // Consider high-risk permissions
  if (hasHighRiskPermissions(ext)) {
    // Having high-risk permissions increases the risk level
    if (riskLevel === 'low') riskLevel = 'medium';
    if (ext.isVulnerable && riskLevel === 'medium') riskLevel = 'high';
  }
  
  return riskLevel;
}

/**
 * Generate tags for an extension issue
 */
function generateTags(ext: ExtensionInfo): string[] {
  const tags: string[] = [ext.browser];
  
  // Add descriptive tags based on issue type
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
  
  if (ext.hasCompatibilityIssues) {
    tags.push('compatibility');
    
    // Add specific compatibility issue types
    if (ext.compatibilityIssues) {
      for (const issue of ext.compatibilityIssues) {
        tags.push(`compatibility:${issue.type}`);
      }
    }
  }
  
  // Add tag for built-in extensions
  if (ext.isBuiltIn) {
    tags.push('built-in');
  }
  
  // Add tag if the extension has high-risk permissions
  if (hasHighRiskPermissions(ext)) {
    tags.push('high-risk-permissions');
  }
  
  // Add tags based on what the extension had access to
  if (ext.permissions) {
    const permissionTags = getPermissionTags(ext.permissions);
    tags.push(...permissionTags);
  }
  
  return tags;
}

/**
 * Get tags based on extension permissions
 */
function getPermissionTags(permissions: string[]): string[] {
  const tags: string[] = [];
  
  // Map common permissions to meaningful tags
  if (permissions.some(p => p === '<all_urls>' || p === 'http://*/*' || p === 'https://*/*')) {
    tags.push('all-sites-access');
  }
  
  if (permissions.includes('webRequest') || permissions.includes('webRequestBlocking')) {
    tags.push('network-interceptor');
  }
  
  if (permissions.includes('tabs')) {
    tags.push('tab-access');
  }
  
  if (permissions.includes('cookies')) {
    tags.push('cookie-access');
  }
  
  if (permissions.includes('history')) {
    tags.push('history-access');
  }
  
  if (permissions.includes('storage')) {
    tags.push('storage-access');
  }
  
  if (permissions.includes('bookmarks')) {
    tags.push('bookmark-access');
  }
  
  if (permissions.includes('downloads')) {
    tags.push('download-access');
  }
  
  if (permissions.includes('clipboardRead') || permissions.includes('clipboardWrite')) {
    tags.push('clipboard-access');
  }
  
  if (permissions.includes('nativeMessaging')) {
    tags.push('native-messaging');
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
      `Found ${ext.vulnerabilities.length} ${ext.vulnerabilities.length === 1 ? 'vulnerability' : 'vulnerabilities'} in ${ext.browser} extension "${ext.name}" (${ext.id}).`
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
    
    // Recommend updating or removing
    if (ext.latestVersion && ext.latestVersion !== ext.version) {
      recommendations.push(
        `Update to the latest version (${ext.latestVersion}) to resolve these security issues.`
      );
    } else {
      recommendations.push(
        `Remove this extension immediately due to security concerns.`
      );
    }
  }
  
  // Handle deprecated extensions
  if (ext.isDeprecated) {
    if (recommendations.length === 0) { // Only add if not already covered by vulnerabilities
      recommendations.push(
        `The ${ext.browser} extension "${ext.name}" (${ext.id}) is deprecated.`
      );
    }
    
    if (ext.deprecationDetails) {
      if (ext.deprecationDetails.reason) {
        recommendations.push(`Deprecation reason: ${ext.deprecationDetails.reason}`);
      }
      
      if (ext.deprecationDetails.endOfSupportDate) {
        recommendations.push(`End of support date: ${ext.deprecationDetails.endOfSupportDate.toISOString().split('T')[0]}`);
      }
      
      if (ext.deprecationDetails.alternatives && ext.deprecationDetails.alternatives.length > 0) {
        recommendations.push(`Alternative extensions: ${ext.deprecationDetails.alternatives.join(', ')}`);
      }
    }
    
    if (!recommendations.some(r => r.includes('Remove'))) {
      recommendations.push(
        `Find and migrate to an actively maintained alternative extension.`
      );
    }
  }
  
  // Handle compatibility issues
  if (ext.hasCompatibilityIssues && ext.compatibilityIssues) {
    if (recommendations.length === 0) { // Only add if not already covered by vulnerabilities or deprecation
      recommendations.push(
        `The ${ext.browser} extension "${ext.name}" (${ext.id}) has compatibility issues.`
      );
    }
    
    for (const issue of ext.compatibilityIssues) {
      let issueDesc = `- ${issue.description}`;
      
      if (issue.remediation) {
        issueDesc += ` - Remediation: ${issue.remediation}`;
      }
      
      recommendations.push(issueDesc);
    }
  }
  
  // Handle outdated extensions
  if (ext.isOutdated && ext.latestVersion) {
    // Only add if not already covered by vulnerabilities, deprecation, or compatibility
    if (recommendations.length === 0) {
      recommendations.push(
        `The ${ext.browser} extension "${ext.name}" (${ext.id}) is outdated. Current version: ${ext.version}, latest version: ${ext.latestVersion}.`
      );
      
      // Check if it's a major version update
      try {
        if (isMajorVersionUpdate(ext.version, ext.latestVersion)) {
          recommendations.push(
            `This is a major version update which may include significant changes. Review the changelog before updating.`
          );
        } else {
          recommendations.push(
            `Update to the latest version to receive bug fixes and enhancements.`
          );
        }
      } catch (versionError) {
        recommendations.push(
          `Update to the latest version to receive bug fixes and enhancements.`
        );
      }
    } else if (!recommendations.some(r => r.includes('Update to'))) {
      // If we've recommended removal, don't also recommend updating
      recommendations.push(
        `Update to the latest version (${ext.latestVersion}) if continuing to use this extension.`
      );
    }
  }
  
  // If no specific recommendations were made, add generic advice
  if (recommendations.length === 0) {
    recommendations.push(
      `Review ${ext.browser} extension "${ext.name}" (${ext.id}) for potential updates or replacements as part of regular maintenance.`
    );
  }
  
  // Add browser store links
  recommendations.push(getBrowserStoreLink(ext));
  
  return recommendations.join('\n');
}

/**
 * Get browser store link for an extension
 */
function getBrowserStoreLink(ext: ExtensionInfo): string {
  switch (ext.browser) {
    case 'chrome':
      return `Chrome Web Store: https://chrome.google.com/webstore/detail/${ext.id}`;
    
    case 'firefox':
      return `Mozilla Add-ons: https://addons.mozilla.org/firefox/addon/${ext.id}/`;
    
    case 'edge':
      return `Microsoft Edge Add-ons: https://microsoftedge.microsoft.com/addons/detail/${ext.id}`;
    
    case 'safari':
      return `Review this Safari extension in the App Store or Safari preferences.`;
    
    default:
      return '';
  }
}

/**
 * Check if a version update is a major version change
 * This is a simplified implementation - in a real system, use semver
 */
function isMajorVersionUpdate(currentVersion: string, latestVersion: string): boolean {
  try {
    const current = currentVersion.split('.');
    const latest = latestVersion.split('.');
    
    // If major version number changed, it's a major update
    if (parseInt(current[0], 10) < parseInt(latest[0], 10)) {
      return true;
    }
    
    return false;
  } catch (error) {
    // If can't parse, assume it's a major update to be safe
    return true;
  }
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