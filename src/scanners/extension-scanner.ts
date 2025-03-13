import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { promisify } from 'util';
import { glob } from 'glob';
import * as semver from 'semver';
import { log } from '../utils/logging';
import { ExtensionIssue } from '../types/scanning';

const readFileAsync = promisify(fs.readFile);
const readDirAsync = promisify(fs.readdir);
const statAsync = promisify(fs.stat);

/**
 * Configuration for browser extension scanning
 */
export interface ExtensionScannerConfig {
  // Browsers to scan
  browsers: {
    chrome: boolean;
    firefox: boolean;
    edge: boolean;
    safari: boolean;
  };
  
  // Custom extension paths (by browser)
  customPaths?: {
    chrome?: string;
    firefox?: string;
    edge?: string;
    safari?: string;
  };
  
  // List of approved extensions (by ID)
  approvedExtensions?: string[];
  
  // List of extensions to ignore (by ID)
  ignoreExtensions?: string[];
  
  // API timeout in milliseconds
  apiTimeoutMs: number;
  
  // Directory to store cached data
  cacheDir?: string;
  
  // Custom rules file path
  customRulesPath?: string;
  
  // Risk assessment configuration
  riskAssessment: {
    // Whether to assess extension permissions for risk
    assessPermissions: boolean;
    
    // Whether to assess extension age
    assessAge: boolean;
    
    // Whether to assess extension update frequency
    assessUpdateFrequency: boolean;
    
    // Whether to assess extension store metrics
    assessStoreMetrics: boolean;
  };
}

/**
 * Browser extension metadata from stores
 */
interface ExtensionMetadata {
  // Extension ID
  id: string;
  
  // Extension name
  name: string;
  
  // Latest version
  latestVersion: string;
  
  // Whether the extension is deprecated
  isDeprecated: boolean;
  
  // Whether the extension has security issues
  hasSecurityIssues: boolean;
  
  // Store URL
  storeUrl?: string;
  
  // Compatibility issues with browser versions
  compatibilityIssues?: string[];
  
  // Whether the extension is removed from store
  removedFromStore?: boolean;
  
  // Security issues details
  securityIssues?: Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    cve?: string;
  }>;
  
  // Download count
  downloadCount?: number;
  
  // User rating (0-5)
  rating?: number;
  
  // Last update date
  lastUpdated?: Date;
  
  // Author or publisher
  author?: string;
  
  // Required permissions
  permissions?: string[];
  
  // High-risk permissions
  highRiskPermissions?: string[];
}

/**
 * Format of a manifest file common to browser extensions
 */
interface ExtensionManifest {
  name: string;
  version: string;
  description?: string;
  author?: string;
  permissions?: string[];
  optional_permissions?: string[];
  host_permissions?: string[];
  manifest_version: number;
  browser_specific_settings?: any;
  background?: any;
  content_scripts?: any[];
  web_accessible_resources?: any;
  icons?: Record<string, string>;
}

/**
 * High-risk permission patterns by browser
 */
const HIGH_RISK_PERMISSIONS: Record<string, string[]> = {
  chrome: [
    '<all_urls>',
    'tabs',
    'webNavigation',
    'webRequest',
    'downloads',
    'history',
    'browsingData',
    'cookies',
    'topSites',
    'proxy',
    'enterprise',
    'declarativeNetRequest',
    'declarativeNetRequestFeedback',
    'declarativeWebRequest',
    'debugger',
    'privacy',
    'contentSettings'
  ],
  firefox: [
    '<all_urls>',
    'tabs',
    'webNavigation',
    'webRequest',
    'downloads',
    'history',
    'browsingData',
    'cookies',
    'topSites',
    'proxy',
    'management',
    'debugger',
    'privacy',
    'browserSettings'
  ],
  edge: [
    '<all_urls>',
    'tabs',
    'webNavigation',
    'webRequest',
    'downloads',
    'history',
    'browsingData',
    'cookies',
    'topSites',
    'proxy',
    'enterprise',
    'declarativeNetRequest',
    'declarativeNetRequestFeedback',
    'contentSettings'
  ],
  safari: [
    'all-pages',
    'browser',
    'tab',
    'script',
    'downloads',
    'cookies',
    'history'
  ]
};

/**
 * Default browser extension paths by OS and browser
 */
const DEFAULT_EXTENSION_PATHS: Record<string, Record<string, string>> = {
  win32: {
    chrome: '%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Extensions',
    firefox: '%APPDATA%\\Mozilla\\Firefox\\Profiles',
    edge: '%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Extensions',
    safari: null // Safari not available on Windows
  },
  darwin: {
    chrome: '~/Library/Application Support/Google/Chrome/Default/Extensions',
    firefox: '~/Library/Application Support/Firefox/Profiles',
    edge: '~/Library/Application Support/Microsoft Edge/Default/Extensions',
    safari: '~/Library/Safari/Extensions'
  },
  linux: {
    chrome: '~/.config/google-chrome/Default/Extensions',
    firefox: '~/.mozilla/firefox',
    edge: '~/.config/microsoft-edge/Default/Extensions',
    safari: null // Safari not available on Linux
  }
};

/**
 * Scanner for detecting browser extension issues
 */
export async function scanExtensions(
  config: ExtensionScannerConfig
): Promise<ExtensionIssue[]> {
  try {
    log.info('Starting browser extension scanner');
    const issues: ExtensionIssue[] = [];
    
    // Ensure we have access to the required file system paths
    const platform = os.platform();
    if (!DEFAULT_EXTENSION_PATHS[platform]) {
      log.warn(`Unsupported platform: ${platform}`);
      return [];
    }
    
    // Scan each enabled browser
    const browsers = Object.entries(config.browsers)
      .filter(([_, enabled]) => enabled)
      .map(([browser]) => browser);
    
    log.info(`Scanning extensions for browsers: ${browsers.join(', ')}`);
    
    for (const browser of browsers) {
      try {
        // Get the path for this browser's extensions
        const extensionPath = getExtensionPath(browser, platform, config.customPaths);
        
        if (!extensionPath) {
          log.warn(`No extension path available for ${browser} on ${platform}`);
          continue;
        }
        
        // Expand environment variables and tilde in path
        const expandedPath = expandPath(extensionPath);
        
        // Check if path exists
        if (!fs.existsSync(expandedPath)) {
          log.warn(`Extension path does not exist: ${expandedPath}`);
          continue;
        }
        
        log.info(`Scanning ${browser} extensions at: ${expandedPath}`);
        
        // Find and analyze installed extensions
        const extensions = await findInstalledExtensions(expandedPath, browser);
        log.info(`Found ${extensions.length} ${browser} extensions`);
        
        // Check each extension
        for (const extension of extensions) {
          // Skip ignored extensions
          if (config.ignoreExtensions?.includes(extension.id)) {
            log.info(`Skipping ignored extension: ${extension.name} (${extension.id})`);
            continue;
          }
          
          try {
            // Get metadata from store
            const metadata = await getExtensionMetadata(
              extension.id,
              extension.name,
              extension.version,
              browser,
              config.apiTimeoutMs,
              config.cacheDir,
              config.riskAssessment
            );
            
            // Compare versions to check if outdated
            const isOutdated = isOutdatedVersion(extension.version, metadata.latestVersion);
            
            // Check if extension has issues
            if (isOutdated || metadata.isDeprecated || metadata.hasSecurityIssues ||
                metadata.removedFromStore || metadata.compatibilityIssues?.length) {
              
              // Determine risk level
              const riskLevel = assessRiskLevel(
                extension,
                metadata,
                isOutdated,
                browser,
                config.approvedExtensions
              );
              
              // Determine update urgency
              const updateUrgency = assessUpdateUrgency(
                isOutdated,
                metadata,
                riskLevel
              );
              
              // Create extension issue
              const issue: ExtensionIssue = {
                detectedAt: new Date(),
                id: extension.id,
                name: extension.name,
                browser,
                currentVersion: extension.version,
                latestVersion: metadata.latestVersion,
                path: extension.path,
                isOutdated,
                isDeprecated: metadata.isDeprecated,
                hasSecurityIssues: metadata.hasSecurityIssues,
                storeUrl: metadata.storeUrl,
                isApproved: config.approvedExtensions?.includes(extension.id) || false,
                removedFromStore: metadata.removedFromStore,
                riskLevel,
                updateUrgency,
                tags: generateTags(
                  extension,
                  metadata,
                  isOutdated,
                  browser,
                  config.approvedExtensions
                ),
                recommendation: generateRecommendation(
                  extension,
                  metadata,
                  isOutdated,
                  riskLevel,
                  updateUrgency
                )
              };
              
              // Add compatibility issues if any
              if (metadata.compatibilityIssues?.length) {
                issue.compatibilityIssues = metadata.compatibilityIssues;
              }
              
              // Add security issues if any
              if (metadata.securityIssues?.length) {
                issue.securityIssues = metadata.securityIssues;
              }
              
              issues.push(issue);
              log.info(`Added issue for extension ${extension.name} ${extension.version}`);
            }
          } catch (extError) {
            log.warn(`Error checking extension ${extension.name}`, { error: extError });
          }
        }
      } catch (browserError) {
        log.warn(`Error scanning ${browser} extensions`, { error: browserError });
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
 * Get the path for a browser's extensions
 */
function getExtensionPath(
  browser: string,
  platform: string,
  customPaths?: { chrome?: string; firefox?: string; edge?: string; safari?: string; }
): string | null {
  // Use custom path if provided
  if (customPaths && customPaths[browser]) {
    return customPaths[browser];
  }
  
  // Use default path for platform and browser
  return DEFAULT_EXTENSION_PATHS[platform]?.[browser] || null;
}

/**
 * Expand environment variables and tilde in a path
 */
function expandPath(pathString: string): string {
  // Expand environment variables (Windows style %VAR%)
  let expandedPath = pathString.replace(/%([^%]+)%/g, (_, varName) => {
    return process.env[varName] || '';
  });
  
  // Expand tilde to home directory
  if (expandedPath.startsWith('~')) {
    expandedPath = path.join(os.homedir(), expandedPath.substring(1));
  }
  
  return expandedPath;
}

/**
 * Find installed browser extensions
 */
async function findInstalledExtensions(
  extensionPath: string,
  browser: string
): Promise<Array<{
  id: string;
  name: string;
  version: string;
  path: string;
  manifest?: ExtensionManifest;
}>> {
  const extensions = [];
  
  try {
    // Different browsers store extensions differently
    switch (browser) {
      case 'chrome':
      case 'edge':
        // Chrome/Edge: extensionId/versionName/
        const extensionDirs = await readDirAsync(extensionPath);
        
        for (const extensionId of extensionDirs) {
          try {
            const extensionDirPath = path.join(extensionPath, extensionId);
            const stats = await statAsync(extensionDirPath);
            
            if (stats.isDirectory()) {
              // Get version directories
              const versionDirs = await readDirAsync(extensionDirPath);
              if (versionDirs.length > 0) {
                // Use the directory with the highest version number
                const latestVersionDir = versionDirs.sort(semverDirectorySort).pop();
                const manifestPath = path.join(extensionDirPath, latestVersionDir, 'manifest.json');
                
                if (fs.existsSync(manifestPath)) {
                  const manifestContent = await readFileAsync(manifestPath, 'utf8');
                  const manifest = JSON.parse(manifestContent) as ExtensionManifest;
                  
                  extensions.push({
                    id: extensionId,
                    name: manifest.name,
                    version: manifest.version,
                    path: path.join(extensionDirPath, latestVersionDir),
                    manifest
                  });
                }
              }
            }
          } catch (extError) {
            log.warn(`Error processing ${browser} extension ${extensionId}`, { error: extError });
          }
        }
        break;
        
      case 'firefox':
        // Firefox: need to scan profiles, then extensions.json in each profile
        const profileDirs = await readDirAsync(extensionPath);
        
        for (const profileDir of profileDirs) {
          try {
            const profilePath = path.join(extensionPath, profileDir);
            const stats = await statAsync(profilePath);
            
            if (stats.isDirectory()) {
              // Check for extensions.json
              const extensionsJsonPath = path.join(profilePath, 'extensions.json');
              if (fs.existsSync(extensionsJsonPath)) {
                const extensionsJson = JSON.parse(await readFileAsync(extensionsJsonPath, 'utf8'));
                
                if (extensionsJson.addons) {
                  // Process each addon in extensions.json
                  for (const addon of extensionsJson.addons) {
                    // Check if the extension is installed and has a manifest file
                    if (addon.path && fs.existsSync(addon.path)) {
                      const manifestPath = path.join(addon.path, 'manifest.json');
                      
                      if (fs.existsSync(manifestPath)) {
                        const manifestContent = await readFileAsync(manifestPath, 'utf8');
                        const manifest = JSON.parse(manifestContent) as ExtensionManifest;
                        
                        extensions.push({
                          id: addon.id,
                          name: manifest.name,
                          version: manifest.version,
                          path: addon.path,
                          manifest
                        });
                      }
                    }
                  }
                }
              }
              
              // Also check the extensions folder
              const extFolder = path.join(profilePath, 'extensions');
              if (fs.existsSync(extFolder)) {
                const extFiles = await readDirAsync(extFolder);
                
                for (const extFile of extFiles) {
                  try {
                    // Firefox unpacked extensions are in the format id.xpi
                    const extPath = path.join(extFolder, extFile);
                    const stats = await statAsync(extPath);
                    
                    if (stats.isDirectory()) {
                      const manifestPath = path.join(extPath, 'manifest.json');
                      
                      if (fs.existsSync(manifestPath)) {
                        const manifestContent = await readFileAsync(manifestPath, 'utf8');
                        const manifest = JSON.parse(manifestContent) as ExtensionManifest;
                        
                        extensions.push({
                          id: extFile.endsWith('.xpi') ? extFile.slice(0, -4) : extFile,
                          name: manifest.name,
                          version: manifest.version,
                          path: extPath,
                          manifest
                        });
                      }
                    }
                  } catch (extError) {
                    log.warn(`Error processing Firefox extension ${extFile}`, { error: extError });
                  }
                }
              }
            }
          } catch (profileError) {
            log.warn(`Error processing Firefox profile ${profileDir}`, { error: profileError });
          }
        }
        break;
        
      case 'safari':
        // Safari: extensions are .appex bundles in the Extensions directory
        const extFiles = await readDirAsync(extensionPath);
        
        for (const extFile of extFiles) {
          try {
            if (extFile.endsWith('.appex')) {
              const extPath = path.join(extensionPath, extFile);
              const infoPath = path.join(extPath, 'Info.plist');
              
              // Parse Info.plist to get extension info (simplified for demo)
              // In a real implementation, we'd use a proper plist parser
              if (fs.existsSync(infoPath)) {
                const infoContent = await readFileAsync(infoPath, 'utf8');
                
                // Very simplistic parsing - real implementation should use a proper plist parser
                const bundleIdMatch = infoContent.match(/<key>CFBundleIdentifier<\/key>\s*<string>([^<]+)<\/string>/);
                const versionMatch = infoContent.match(/<key>CFBundleShortVersionString<\/key>\s*<string>([^<]+)<\/string>/);
                const nameMatch = infoContent.match(/<key>CFBundleDisplayName<\/key>\s*<string>([^<]+)<\/string>/);
                
                if (bundleIdMatch && versionMatch) {
                  extensions.push({
                    id: bundleIdMatch[1],
                    name: nameMatch ? nameMatch[1] : bundleIdMatch[1],
                    version: versionMatch[1],
                    path: extPath
                  });
                }
              }
            }
          } catch (extError) {
            log.warn(`Error processing Safari extension ${extFile}`, { error: extError });
          }
        }
        break;
    }
    
    return extensions;
  } catch (error) {
    log.error(`Error finding installed ${browser} extensions`, { error });
    return [];
  }
}

/**
 * Sort function for version directories
 */
function semverDirectorySort(a: string, b: string): number {
  // Try to parse as semver
  const aVer = semver.coerce(a);
  const bVer = semver.coerce(b);
  
  if (aVer && bVer) {
    return semver.compare(aVer, bVer);
  }
  
  // Fallback to string comparison
  return a.localeCompare(b);
}

/**
 * Get extension metadata from store
 */
async function getExtensionMetadata(
  id: string,
  name: string,
  version: string,
  browser: string,
  timeoutMs: number,
  cacheDir?: string,
  riskAssessment?: {
    assessPermissions: boolean;
    assessAge: boolean;
    assessUpdateFrequency: boolean;
    assessStoreMetrics: boolean;
  }
): Promise<ExtensionMetadata> {
  // Check cache first
  if (cacheDir) {
    const cacheFile = path.join(
      cacheDir, 
      `ext-${browser}-${id.replace(/[^a-z0-9]/gi, '-').toLowerCase()}.json`
    );
    
    if (fs.existsSync(cacheFile)) {
      try {
        const cacheContent = await readFileAsync(cacheFile, 'utf8');
        const cachedInfo = JSON.parse(cacheContent) as ExtensionMetadata;
        log.info(`Loaded ${name} extension info from cache`);
        return cachedInfo;
      } catch (cacheError) {
        log.warn(`Error reading extension cache for ${name}`, { error: cacheError });
      }
    }
  }
  
  // In a real implementation, we would query extension stores
  // For this example, we'll use mock data to simulate API responses
  try {
    log.info(`Querying info for extension: ${name} (${id}) ${version} (${browser})`);
    
    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 50 + Math.random() * 100));
    
    // Create metadata with defaults
    const metadata: ExtensionMetadata = {
      id,
      name,
      latestVersion: incrementVersion(version),
      isDeprecated: Math.random() < 0.1, // 10% chance of being deprecated
      hasSecurityIssues: Math.random() < 0.15, // 15% chance of having security issues
      storeUrl: getExtensionStoreUrl(id, browser),
      removedFromStore: Math.random() < 0.05, // 5% chance of being removed
      downloadCount: Math.floor(Math.random() * 1000000),
      rating: 1 + Math.random() * 4, // 1-5 rating
      lastUpdated: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000), // Up to 1 year ago
      author: `Developer ${Math.floor(Math.random() * 100)}`
    };
    
    // Add compatibility issues for some extensions
    if (Math.random() < 0.2) { // 20% chance of compatibility issues
      metadata.compatibilityIssues = [
        `Not compatible with ${browser} ${getBrowserLatestVersion(browser)}`
      ];
    }
    
    // Add security issues if flagged
    if (metadata.hasSecurityIssues) {
      metadata.securityIssues = [
        {
          severity: getRandomSeverity(),
          description: `${getRandomVulnerabilityType()} vulnerability in ${name}`,
          cve: `CVE-${new Date().getFullYear()}-${Math.floor(Math.random() * 10000)}`
        }
      ];
      
      // Sometimes add a second vulnerability
      if (Math.random() < 0.3) {
        metadata.securityIssues.push({
          severity: getRandomSeverity(),
          description: `${getRandomVulnerabilityType()} vulnerability in ${name}`,
          cve: `CVE-${new Date().getFullYear()}-${Math.floor(Math.random() * 10000)}`
        });
      }
    }
    
    // Add known high-risk permissions for risk assessment
    if (riskAssessment?.assessPermissions) {
      // In a real implementation, these would come from the manifest
      const fakePermissions = getFakePermissions(browser);
      metadata.permissions = fakePermissions;
      
      // Identify high-risk permissions
      const highRiskPatterns = HIGH_RISK_PERMISSIONS[browser] || [];
      metadata.highRiskPermissions = fakePermissions.filter(perm => 
        highRiskPatterns.some(pattern => 
          perm.includes(pattern) || pattern.includes(perm)
        )
      );
    }
    
    // Customize some well-known problematic extensions for more realistic examples
    customizeExtensionMetadata(metadata, id, browser);
    
    // Save to cache if cacheDir is provided
    if (cacheDir) {
      try {
        if (!fs.existsSync(cacheDir)) {
          fs.mkdirSync(cacheDir, { recursive: true });
        }
        
        const cacheFile = path.join(
          cacheDir, 
          `ext-${browser}-${id.replace(/[^a-z0-9]/gi, '-').toLowerCase()}.json`
        );
        
        await fs.promises.writeFile(
          cacheFile, 
          JSON.stringify(metadata, null, 2), 
          'utf8'
        );
        
        log.info(`Cached ${name} extension info`);
      } catch (cacheError) {
        log.warn(`Error writing extension cache for ${name}`, { error: cacheError });
      }
    }
    
    return metadata;
  } catch (error) {
    log.error(`Error querying info for extension ${name}`, { error });
    
    // Return default info if query fails
    return {
      id,
      name,
      latestVersion: version,
      isDeprecated: false,
      hasSecurityIssues: false
    };
  }
}

/**
 * Get a URL to the extension in its store
 */
function getExtensionStoreUrl(id: string, browser: string): string {
  switch (browser) {
    case 'chrome':
      return `https://chrome.google.com/webstore/detail/${id}`;
    case 'firefox':
      return `https://addons.mozilla.org/en-US/firefox/addon/${id}`;
    case 'edge':
      return `https://microsoftedge.microsoft.com/addons/detail/${id}`;
    case 'safari':
      return `https://apps.apple.com/app/${id}`;
    default:
      return '';
  }
}

/**
 * Get fake browser latest version for demo purposes
 */
function getBrowserLatestVersion(browser: string): string {
  switch (browser) {
    case 'chrome':
      return '112.0.5615.121';
    case 'firefox':
      return '102.10.0';
    case 'edge':
      return '112.0.1722.48';
    case 'safari':
      return '16.4';
    default:
      return '1.0.0';
  }
}

/**
 * Get fake permissions for demo purposes
 */
function getFakePermissions(browser: string): string[] {
  const commonPermissions = [
    'storage',
    'activeTab'
  ];
  
  const highRiskPermissions = HIGH_RISK_PERMISSIONS[browser] || [];
  
  // 30% chance of having a high-risk permission
  if (Math.random() < 0.3) {
    return [
      ...commonPermissions,
      highRiskPermissions[Math.floor(Math.random() * highRiskPermissions.length)]
    ];
  }
  
  return commonPermissions;
}

/**
 * Customize metadata for known problematic extensions
 */
function customizeExtensionMetadata(
  metadata: ExtensionMetadata,
  id: string,
  browser: string
): void {
  // List of known problematic extensions (IDs are made up for this example)
  const problematicExtensions: Record<string, Partial<ExtensionMetadata>> = {
    'data-scraper-extension': {
      isDeprecated: true,
      hasSecurityIssues: true,
      securityIssues: [{
        severity: 'critical',
        description: 'Data exfiltration vulnerability allowing unauthorized access to browsing history',
        cve: `CVE-${new Date().getFullYear()}-11223`
      }],
      removedFromStore: true,
      highRiskPermissions: ['<all_urls>', 'tabs', 'webNavigation', 'history', 'cookies']
    },
    'old-password-manager': {
      isDeprecated: true,
      hasSecurityIssues: true,
      securityIssues: [{
        severity: 'high',
        description: 'Insecure password storage vulnerability',
        cve: `CVE-${new Date().getFullYear() - 1}-98765`
      }],
      latestVersion: '2.5.1',
      compatibilityIssues: [`Not compatible with ${browser} updates after 2023`]
    },
    'abandoned-youtube-downloader': {
      isDeprecated: true,
      removedFromStore: true,
      lastUpdated: new Date(2021, 1, 1)
    },
    'known-malicious-extension': {
      hasSecurityIssues: true,
      securityIssues: [{
        severity: 'critical',
        description: 'Contains malicious code that steals user data',
        cve: `CVE-${new Date().getFullYear()}-54321`
      }],
      removedFromStore: true
    }
  };
  
  // Check if this is a known problematic extension
  if (id.toLowerCase().includes('scraper') || id.toLowerCase().includes('harvester')) {
    Object.assign(metadata, problematicExtensions['data-scraper-extension']);
  } else if (id.toLowerCase().includes('password') && Math.random() < 0.5) {
    Object.assign(metadata, problematicExtensions['old-password-manager']);
  } else if (id.toLowerCase().includes('download') && Math.random() < 0.5) {
    Object.assign(metadata, problematicExtensions['abandoned-youtube-downloader']);
  } else if (Math.random() < 0.02) { // 2% chance any extension is actually malicious
    Object.assign(metadata, problematicExtensions['known-malicious-extension']);
  }
}

/**
 * Check if a version is outdated
 */
function isOutdatedVersion(currentVersion: string, latestVersion: string): boolean {
  try {
    const current = semver.coerce(currentVersion);
    const latest = semver.coerce(latestVersion);
    
    if (current && latest) {
      return semver.lt(current, latest);
    }
    
    // Fallback for non-semver versions
    return currentVersion !== latestVersion;
  } catch (error) {
    log.warn(`Error comparing versions: ${currentVersion} vs ${latestVersion}`, { error });
    return false;
  }
}

/**
 * Assess the risk level of an extension
 */
function assessRiskLevel(
  extension: {
    id: string;
    name: string;
    version: string;
    path: string;
    manifest?: ExtensionManifest;
  },
  metadata: ExtensionMetadata,
  isOutdated: boolean,
  browser: string,
  approvedExtensions?: string[]
): 'low' | 'medium' | 'high' | 'critical' {
  // Critical conditions first
  if (
    metadata.removedFromStore ||
    (metadata.securityIssues?.some(issue => issue.severity === 'critical')) ||
    metadata.hasSecurityIssues && isOutdated
  ) {
    return 'critical';
  }
  
  // High risk conditions
  if (
    metadata.securityIssues?.some(issue => issue.severity === 'high') ||
    (metadata.isDeprecated && isOutdated) ||
    (metadata.highRiskPermissions?.length > 2 && !approvedExtensions?.includes(extension.id))
  ) {
    return 'high';
  }
  
  // Medium risk conditions
  if (
    metadata.securityIssues?.some(issue => issue.severity === 'medium') ||
    metadata.isDeprecated ||
    isOutdated ||
    metadata.compatibilityIssues?.length > 0 ||
    (metadata.highRiskPermissions?.length > 0 && !approvedExtensions?.includes(extension.id))
  ) {
    return 'medium';
  }
  
  // Everything else is low risk
  return 'low';
}

/**
 * Assess the urgency for updating an extension
 */
function assessUpdateUrgency(
  isOutdated: boolean,
  metadata: ExtensionMetadata,
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
): 'low' | 'medium' | 'high' | 'critical' {
  // Critical urgency conditions
  if (
    metadata.securityIssues?.some(issue => issue.severity === 'critical') ||
    riskLevel === 'critical'
  ) {
    return 'critical';
  }
  
  // High urgency conditions
  if (
    metadata.securityIssues?.some(issue => issue.severity === 'high') ||
    (metadata.isDeprecated && metadata.removedFromStore) ||
    riskLevel === 'high'
  ) {
    return 'high';
  }
  
  // Medium urgency conditions
  if (
    metadata.securityIssues?.some(issue => issue.severity === 'medium') ||
    (isOutdated && metadata.isDeprecated) ||
    metadata.compatibilityIssues?.length > 0 ||
    riskLevel === 'medium'
  ) {
    return 'medium';
  }
  
  // Low urgency for everything else
  return 'low';
}

/**
 * Generate tags for an extension issue
 */
function generateTags(
  extension: {
    id: string;
    name: string;
    version: string;
    path: string;
    manifest?: ExtensionManifest;
  },
  metadata: ExtensionMetadata,
  isOutdated: boolean,
  browser: string,
  approvedExtensions?: string[]
): string[] {
  const tags: string[] = [browser];
  
  if (isOutdated) tags.push('outdated');
  if (metadata.isDeprecated) tags.push('deprecated');
  if (metadata.hasSecurityIssues) tags.push('security-issue');
  if (metadata.removedFromStore) tags.push('removed-from-store');
  if (metadata.compatibilityIssues?.length) tags.push('compatibility-issue');
  if (approvedExtensions?.includes(extension.id)) tags.push('approved');
  else tags.push('unapproved');
  
  // Add severity tag for security issues
  if (metadata.securityIssues?.length) {
    const severities = metadata.securityIssues.map(issue => issue.severity);
    if (severities.includes('critical')) tags.push('critical-severity');
    else if (severities.includes('high')) tags.push('high-severity');
    else if (severities.includes('medium')) tags.push('medium-severity');
    else if (severities.includes('low')) tags.push('low-severity');
  }
  
  // Add permission tags
  if (metadata.highRiskPermissions?.length) {
    tags.push('high-risk-permissions');
    
    if (metadata.highRiskPermissions.includes('<all_urls>') ||
        metadata.highRiskPermissions.includes('all-pages')) {
      tags.push('all-urls-access');
    }
  }
  
  return tags;
}

/**
 * Generate a recommendation for the extension issue
 */
function generateRecommendation(
  extension: {
    id: string;
    name: string;
    version: string;
    path: string;
    manifest?: ExtensionManifest;
  },
  metadata: ExtensionMetadata,
  isOutdated: boolean,
  riskLevel: 'low' | 'medium' | 'high' | 'critical',
  updateUrgency: 'low' | 'medium' | 'high' | 'critical'
): string {
  const recommendations: string[] = [];
  
  if (metadata.removedFromStore) {
    recommendations.push(
      `Remove extension ${extension.name} immediately as it has been removed from the ${getBrowserName(metadata.browser)} store`
    );
  } else if (metadata.securityIssues?.length) {
    // Find the highest severity
    const highestSeverity = metadata.securityIssues.reduce(
      (highest, current) => {
        const severityRank = { 'low': 1, 'medium': 2, 'high': 3, 'critical': 4 };
        const currentRank = severityRank[current.severity] || 0;
        const highestRank = severityRank[highest] || 0;
        return currentRank > highestRank ? current.severity : highest;
      },
      'low' as 'low' | 'medium' | 'high' | 'critical'
    );
    
    const issueCount = metadata.securityIssues.length;
    
    recommendations.push(
      `Update ${extension.name} immediately from ${extension.version} to ${metadata.latestVersion} to fix ${issueCount} ${highestSeverity} severity security ${issueCount === 1 ? 'issue' : 'issues'}`
    );
  } else if (metadata.isDeprecated) {
    if (metadata.compatibilityIssues?.length) {
      recommendations.push(
        `Replace deprecated extension ${extension.name} due to compatibility issues with current browser version`
      );
    } else {
      recommendations.push(
        `Plan replacement of deprecated extension ${extension.name}`
      );
    }
  } else if (isOutdated) {
    const urgencyText = updateUrgency === 'critical' ? 'immediately' :
                      updateUrgency === 'high' ? 'as soon as possible' :
                      updateUrgency === 'medium' ? 'in the next update cycle' :
                      'when convenient';
    
    recommendations.push(
      `Update ${extension.name} from ${extension.version} to ${metadata.latestVersion} ${urgencyText}`
    );
  } else if (metadata.compatibilityIssues?.length) {
    recommendations.push(
      `Test and resolve compatibility issues with ${extension.name}: ${metadata.compatibilityIssues.join(', ')}`
    );
  }
  
  // Add high risk permissions warning if applicable
  if (metadata.highRiskPermissions?.length && riskLevel !== 'low') {
    recommendations.push(
      `Review high risk permissions used by this extension: ${metadata.highRiskPermissions.join(', ')}`
    );
  }
  
  // If we have no recommendations yet, add a general one
  if (recommendations.length === 0) {
    recommendations.push(
      `No immediate actions needed for ${extension.name} ${extension.version}`
    );
  }
  
  return recommendations.join('. ');
}

/**
 * Get browser full name
 */
function getBrowserName(browser: string): string {
  switch (browser) {
    case 'chrome': return 'Google Chrome';
    case 'firefox': return 'Mozilla Firefox';
    case 'edge': return 'Microsoft Edge';
    case 'safari': return 'Apple Safari';
    default: return browser;
  }
}

/* ---- Helper Functions ---- */

/**
 * Increment a version for demonstration purposes
 */
function incrementVersion(version: string): string {
  try {
    // Clean up version string to ensure it's parseable
    const cleanVersion = version.replace(/[^0-9.]/g, '');
    const parts = cleanVersion.split('.');
    
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
    'cross-site scripting',
    'data exfiltration',
    'privilege escalation',
    'information disclosure',
    'authentication bypass',
    'code injection',
    'unauthorized API access',
    'insecure storage',
    'browser fingerprinting',
    'clickjacking',
    'session hijacking',
    'request forgery',
    'cookie manipulation'
  ];
  return types[Math.floor(Math.random() * types.length)];
}
