import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { promisify } from 'util';
import { glob } from 'glob';
import { log } from '../utils/logging';
import { ExtensionIssue } from '../types/scanning';
import { compareVersions } from '../utils/scanner-utils';

const readFileAsync = promisify(fs.readFile);

/**
 * Configuration for browser extension scanning
 */
export interface ExtensionScannerConfig {
  // Which browsers to check
  browsers: Array<'chrome' | 'firefox' | 'edge' | 'safari'>;
  
  // Whether to use offline mode (don't make API calls)
  offlineMode: boolean;
  
  // Whether to check for security vulnerabilities
  checkVulnerabilities: boolean;
  
  // Skip extensions with specific IDs
  ignoreExtensions?: string[];
  
  // API timeout in milliseconds
  apiTimeoutMs: number;
  
  // Directory to store cached data
  cacheDir?: string;
  
  // Minimum user count for extension to be considered important
  minUserCount?: number;
  
  // Check if extension was recently updated
  checkUpdateFrequency?: boolean;
  
  // Max months since last update to flag as concern
  maxMonthsSinceUpdate?: number;
}

/**
 * Detected browser extension
 */
interface DetectedExtension {
  id: string;
  name: string;
  browser: string;
  version: string;
  path: string;
  userCount?: number;
  enabled: boolean;
}

/**
 * Extension information from online source
 */
interface ExtensionInfo {
  latestVersion: string;
  isOutdated: boolean;
  isDeprecated: boolean;
  isRemoved: boolean;
  userCount?: number;
  rating?: number;
  lastUpdated?: Date;
  storeUrl?: string;
  vulnerabilities?: Array<{
    id: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    fixedInVersion?: string;
  }>;
}

/**
 * Scanner for browser extensions
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
          extension.name,
          extension.browser,
          extension.version,
          config.offlineMode,
          config.checkVulnerabilities,
          config.cacheDir
        );
        
        // Only create an issue if there's at least one problem
        if (extensionInfo.isOutdated || extensionInfo.isDeprecated || 
            extensionInfo.isRemoved || extensionInfo.vulnerabilities?.length) {
          
          // Calculate business impact
          const businessImpact = calculateBusinessImpact(
            extension,
            extensionInfo
          );
          
          // Create the issue
          const issue: ExtensionIssue = {
            id: extension.id,
            name: extension.name,
            browser: extension.browser,
            currentVersion: extension.version,
            latestVersion: extensionInfo.latestVersion,
            isOutdated: extensionInfo.isOutdated,
            isDeprecated: extensionInfo.isDeprecated,
            isRemoved: extensionInfo.isRemoved,
            location: extension.path,
            detectedAt: new Date(),
            businessImpact,
            userCount: extension.userCount || extensionInfo.userCount,
            rating: extensionInfo.rating,
            storeUrl: extensionInfo.storeUrl,
            lastUpdated: extensionInfo.lastUpdated
          };
          
          // Add vulnerabilities if any exist
          if (extensionInfo.vulnerabilities?.length) {
            issue.vulnerabilities = extensionInfo.vulnerabilities;
          }
          
          // Generate recommendation
          issue.recommendation = generateRecommendation(
            extension,
            extensionInfo
          );
          
          // Add tags
          issue.tags = generateTags(extension, extensionInfo);
          
          // Add to issues list
          issues.push(issue);
          log.info(`Added issue for extension ${extension.name} (${extension.id})`);
        }
      } catch (extError) {
        log.warn(`Error processing extension: ${extension.name} (${extension.id})`, { error: extError });
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
 * Detect browser extensions installed on the system
 */
async function detectExtensions(
  config: ExtensionScannerConfig
): Promise<DetectedExtension[]> {
  const extensions: DetectedExtension[] = [];
  
  for (const browser of config.browsers) {
    try {
      log.info(`Detecting ${browser} extensions`);
      
      // Get browser extension paths
      const extensionPaths = await getBrowserExtensionPaths(browser);
      
      for (const extensionPath of extensionPaths) {
        try {
          const extension = await parseExtensionData(extensionPath, browser);
          if (extension) {
            extensions.push(extension);
          }
        } catch (extensionError) {
          log.warn(`Error parsing extension at ${extensionPath}`, { error: extensionError });
        }
      }
    } catch (browserError) {
      log.warn(`Error detecting ${browser} extensions`, { error: browserError });
    }
  }
  
  return extensions;
}

/**
 * Get all extension paths for a specific browser
 */
async function getBrowserExtensionPaths(browser: string): Promise<string[]> {
  const platform = os.platform();
  let basePaths: string[] = [];
  
  // Define paths for different browsers and platforms
  switch (platform) {
    case 'win32': // Windows
      switch (browser) {
        case 'chrome':
          basePaths = [
            path.join(os.homedir(), 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Extensions'),
            path.join(os.homedir(), 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Profile *', 'Extensions')
          ];
          break;
        case 'firefox':
          basePaths = [
            path.join(os.homedir(), 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles', '*', 'extensions')
          ];
          break;
        case 'edge':
          basePaths = [
            path.join(os.homedir(), 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default', 'Extensions'),
            path.join(os.homedir(), 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Profile *', 'Extensions')
          ];
          break;
      }
      break;
      
    case 'darwin': // macOS
      switch (browser) {
        case 'chrome':
          basePaths = [
            path.join(os.homedir(), 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Extensions'),
            path.join(os.homedir(), 'Library', 'Application Support', 'Google', 'Chrome', 'Profile *', 'Extensions')
          ];
          break;
        case 'firefox':
          basePaths = [
            path.join(os.homedir(), 'Library', 'Application Support', 'Firefox', 'Profiles', '*', 'extensions')
          ];
          break;
        case 'edge':
          basePaths = [
            path.join(os.homedir(), 'Library', 'Application Support', 'Microsoft Edge', 'Default', 'Extensions'),
            path.join(os.homedir(), 'Library', 'Application Support', 'Microsoft Edge', 'Profile *', 'Extensions')
          ];
          break;
        case 'safari':
          basePaths = [
            path.join(os.homedir(), 'Library', 'Safari', 'Extensions'),
            path.join(os.homedir(), 'Library', 'Containers', 'com.apple.Safari', 'Data', 'Library', 'Safari', 'Extensions')
          ];
          break;
      }
      break;
      
    case 'linux': // Linux
      switch (browser) {
        case 'chrome':
          basePaths = [
            path.join(os.homedir(), '.config', 'google-chrome', 'Default', 'Extensions'),
            path.join(os.homedir(), '.config', 'google-chrome', 'Profile *', 'Extensions')
          ];
          break;
        case 'firefox':
          basePaths = [
            path.join(os.homedir(), '.mozilla', 'firefox', '*', 'extensions')
          ];
          break;
        case 'edge':
          basePaths = [
            path.join(os.homedir(), '.config', 'microsoft-edge', 'Default', 'Extensions'),
            path.join(os.homedir(), '.config', 'microsoft-edge', 'Profile *', 'Extensions')
          ];
          break;
      }
      break;
  }
  
  // Expand all base paths using glob to handle wildcards
  const expansionPromises = basePaths.map(basePath => {
    return glob(basePath).catch(() => []);
  });
  
  const expandedBasePaths = (await Promise.all(expansionPromises)).flat();
  
  // Find all extension directories
  const extensionPathPromises = expandedBasePaths.map(async basePath => {
    try {
      if (fs.existsSync(basePath)) {
        if (browser === 'firefox' || browser === 'safari') {
          // Firefox and Safari have a different structure
          return glob(path.join(basePath, '*')).catch(() => []);
        } else {
          // Chrome and Edge structure: Extension ID -> Version -> extension files
          const extensionIds = await fs.promises.readdir(basePath);
          const versionDirPromises = extensionIds.map(async id => {
            const extensionIdPath = path.join(basePath, id);
            try {
              const versions = await fs.promises.readdir(extensionIdPath);
              // Return the path to the latest version
              if (versions.length > 0) {
                const latest = versions.sort((a, b) => compareVersions(b, a))[0];
                return path.join(extensionIdPath, latest);
              }
            } catch (error) {
              // Skip if we can't read the directory
            }
            return null;
          });
          
          const results = await Promise.all(versionDirPromises);
          return results.filter(Boolean) as string[];
        }
      }
    } catch (error) {
      log.warn(`Error reading extension directory: ${basePath}`, { error });
    }
    return [];
  });
  
  const results = (await Promise.all(extensionPathPromises)).flat();
  return results.filter(Boolean);
}

/**
 * Parse extension data from its directory
 */
async function parseExtensionData(
  extensionPath: string,
  browser: string
): Promise<DetectedExtension | null> {
  try {
    // Different browsers have different manifest file structures
    let manifestPath: string;
    if (browser === 'safari') {
      // Safari extensions use Info.plist
      manifestPath = path.join(extensionPath, 'Info.plist');
      // TODO: Implement plist parsing for Safari extensions
      // For now, we'll skip Safari extensions since they require specialized parsing
      return null;
    } else {
      // Chrome, Firefox, and Edge use manifest.json
      manifestPath = path.join(extensionPath, 'manifest.json');
    }
    
    if (!fs.existsSync(manifestPath)) {
      return null;
    }
    
    const manifestContent = await readFileAsync(manifestPath, 'utf8');
    const manifest = JSON.parse(manifestContent);
    
    // Extract extension ID
    let id: string;
    let name: string;
    let version: string;
    let enabled = true; // Default to enabled
    
    if (browser === 'firefox') {
      // Firefox extension ID is the directory name
      id = path.basename(extensionPath);
      name = manifest.name || path.basename(extensionPath);
      version = manifest.version || '0.0.0';
      
      // Check if disabled
      const isXPI = extensionPath.endsWith('.xpi');
      enabled = !isXPI || !path.basename(extensionPath).includes('disabled');
    } else {
      // Chrome/Edge extension ID is the directory name two levels up
      id = path.basename(path.dirname(path.dirname(extensionPath)));
      name = manifest.name || id;
      version = manifest.version || '0.0.0';
      
      // Check if disabled via Chrome's preferences
      // This is a simplification, in reality we would check the browser's preferences
      enabled = true;
    }
    
    return {
      id,
      name,
      browser,
      version,
      path: extensionPath,
      enabled
    };
  } catch (error) {
    log.warn(`Error parsing extension manifest at ${extensionPath}`, { error });
    return null;
  }
}

/**
 * Get information about an extension from store or cache
 */
async function getExtensionInfo(
  id: string,
  name: string,
  browser: string,
  version: string,
  offlineMode: boolean,
  checkVulnerabilities: boolean,
  cacheDir?: string
): Promise<ExtensionInfo> {
  // Check cache first
  if (cacheDir) {
    const cacheFile = path.join(cacheDir, `ext-${browser}-${id.toLowerCase()}.json`);
    
    if (fs.existsSync(cacheFile)) {
      try {
        const cacheContent = await readFileAsync(cacheFile, 'utf8');
        const cachedInfo = JSON.parse(cacheContent) as ExtensionInfo;
        log.info(`Loaded ${name} info from cache`);
        return cachedInfo;
      } catch (cacheError) {
        log.warn(`Error reading extension cache for ${name}`, { error: cacheError });
      }
    }
  }
  
  // If in offline mode and no cache, return placeholder data
  if (offlineMode) {
    log.info(`Offline mode enabled for ${name}, using placeholder data`);
    return {
      latestVersion: version, // Assume current version is latest
      isOutdated: false,
      isDeprecated: false,
      isRemoved: false,
      vulnerabilities: []
    };
  }
  
  // In a real implementation, we would query extension stores
  // For this example, we'll use mock data
  try {
    log.info(`Querying ${browser} store for extension: ${name} (${id})`);
    
    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 50 + Math.random() * 200));
    
    // Generate mock data
    const info: ExtensionInfo = {
      latestVersion: incrementVersion(version),
      isOutdated: Math.random() < 0.4, // 40% chance of being outdated
      isDeprecated: Math.random() < 0.1, // 10% chance of being deprecated
      isRemoved: Math.random() < 0.05, // 5% chance of being removed
      userCount: Math.floor(Math.random() * 1000000) + 100,
      rating: Math.random() * 5,
      lastUpdated: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000),
      storeUrl: getStoreUrl(id, browser),
      vulnerabilities: []
    };
    
    // Make sure versions match our other properties
    if (info.isOutdated) {
      info.latestVersion = incrementVersion(version);
    } else {
      info.latestVersion = version;
    }
    
    if (info.isDeprecated || info.isRemoved) {
      info.isOutdated = true;
    }
    
    // Add vulnerabilities based on configuration
    if (checkVulnerabilities && (info.isDeprecated || info.isRemoved || Math.random() < 0.2)) {
      info.vulnerabilities = [
        {
          id: `EXT-${Math.floor(Math.random() * 10000)}`,
          severity: getRandomSeverity(),
          description: `Security vulnerability in ${name} that could lead to ${getRandomVulnerabilityType()}`,
          fixedInVersion: info.latestVersion
        }
      ];
    }
    
    // Save to cache if cacheDir is provided
    if (cacheDir) {
      try {
        if (!fs.existsSync(cacheDir)) {
          fs.mkdirSync(cacheDir, { recursive: true });
        }
        
        const cacheFile = path.join(cacheDir, `ext-${browser}-${id.toLowerCase()}.json`);
        await fs.promises.writeFile(cacheFile, JSON.stringify(info, null, 2), 'utf8');
        log.info(`Cached ${name} info`);
      } catch (cacheError) {
        log.warn(`Error writing extension cache for ${name}`, { error: cacheError });
      }
    }
    
    return info;
  } catch (error) {
    log.error(`Error querying store for ${name}`, { error });
    
    // Return basic info if store query fails
    return {
      latestVersion: version,
      isOutdated: false,
      isDeprecated: false,
      isRemoved: false,
      vulnerabilities: []
    };
  }
}

/**
 * Calculate business impact score for an extension issue
 */
function calculateBusinessImpact(
  extension: DetectedExtension,
  info: ExtensionInfo
): number {
  let score = 1; // Start with minimal impact
  
  // Adjust score based on issues
  if (info.isOutdated) score += 1;
  if (info.isDeprecated) score += 1;
  if (info.isRemoved) score += 2;
  
  // Adjust based on vulnerabilities
  if (info.vulnerabilities && info.vulnerabilities.length > 0) {
    const hasHighSeverity = info.vulnerabilities.some(v => 
      v.severity === 'high' || v.severity === 'critical'
    );
    
    score += hasHighSeverity ? 2 : 1;
  }
  
  // Extensions with many users have higher impact
  const userCount = extension.userCount || info.userCount || 0;
  if (userCount > 100000) score += 1;
  
  // Cap at maximum of 5
  return Math.min(score, 5);
}

/**
 * Generate a recommendation for an extension issue
 */
function generateRecommendation(
  extension: DetectedExtension,
  info: ExtensionInfo
): string {
  const recommendations: string[] = [];
  
  if (info.isRemoved) {
    recommendations.push(
      `Remove ${extension.name} as it has been removed from the ${extension.browser} store`
    );
  } else if (info.vulnerabilities && info.vulnerabilities.length > 0) {
    if (info.isDeprecated) {
      recommendations.push(
        `Replace ${extension.name} with a secure alternative due to vulnerabilities and deprecation`
      );
    } else {
      recommendations.push(
        `Update ${extension.name} from ${extension.version} to ${info.latestVersion} to address security vulnerabilities`
      );
    }
  } else if (info.isDeprecated) {
    recommendations.push(
      `Find a replacement for deprecated extension ${extension.name}`
    );
  } else if (info.isOutdated) {
    recommendations.push(
      `Update ${extension.name} from ${extension.version} to ${info.latestVersion}`
    );
  }
  
  if (info.lastUpdated) {
    const monthsAgo = Math.floor((Date.now() - info.lastUpdated.getTime()) / (30 * 24 * 60 * 60 * 1000));
    if (monthsAgo > 12) {
      recommendations.push(
        `Consider replacing ${extension.name} as it hasn't been updated in ${monthsAgo} months`
      );
    }
  }
  
  if (recommendations.length === 0) {
    recommendations.push(`No immediate action required for ${extension.name} ${extension.version}`);
  }
  
  return recommendations.join('. ');
}

/**
 * Generate tags for categorizing extension issues
 */
function generateTags(
  extension: DetectedExtension,
  info: ExtensionInfo
): string[] {
  const tags: string[] = [extension.browser, 'extension'];
  
  if (info.isOutdated) tags.push('outdated');
  if (info.isDeprecated) tags.push('deprecated');
  if (info.isRemoved) tags.push('removed');
  
  if (info.vulnerabilities && info.vulnerabilities.length > 0) {
    tags.push('security');
    
    // Add tag for highest severity
    const severities = info.vulnerabilities.map(v => v.severity);
    if (severities.includes('critical')) tags.push('critical-severity');
    else if (severities.includes('high')) tags.push('high-severity');
    else if (severities.includes('medium')) tags.push('medium-severity');
    else if (severities.includes('low')) tags.push('low-severity');
  }
  
  if (info.lastUpdated) {
    const monthsAgo = Math.floor((Date.now() - info.lastUpdated.getTime()) / (30 * 24 * 60 * 60 * 1000));
    if (monthsAgo > 12) tags.push('unmaintained');
  }
  
  return tags;
}

/* ---- Helper Functions for Mock Data ---- */

/**
 * Helper function to increment a version for demo purposes
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
    
    // Increment a random part
    const partToIncrement = Math.floor(Math.random() * parts.length);
    const partValue = parseInt(parts[partToIncrement], 10) || 0;
    parts[partToIncrement] = String(partValue + 1);
    
    return parts.join('.');
  } catch (error) {
    return `${version}.1`; // Fallback
  }
}

/**
 * Helper function for getting a store URL
 */
function getStoreUrl(id: string, browser: string): string {
  switch (browser) {
    case 'chrome':
      return `https://chrome.google.com/webstore/detail/${id}`;
    case 'firefox':
      return `https://addons.mozilla.org/en-US/firefox/addon/${id}`;
    case 'edge':
      return `https://microsoftedge.microsoft.com/addons/detail/${id}`;
    case 'safari':
      return `https://apps.apple.com/us/app/${id}`;
    default:
      return '';
  }
}

/**
 * Helper function for getting a random severity
 */
function getRandomSeverity(): 'low' | 'medium' | 'high' | 'critical' {
  const severities: Array<'low' | 'medium' | 'high' | 'critical'> = ['low', 'medium', 'high', 'critical'];
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
 * Helper function for getting a random vulnerability type
 */
function getRandomVulnerabilityType(): string {
  const types = [
    'data leakage',
    'excessive permissions',
    'code injection',
    'cross-site scripting',
    'private browsing bypass',
    'cookie theft',
    'browser history access',
    'cryptomining',
    'malicious redirect',
    'data exfiltration',
    'adware behavior'
  ];
  return types[Math.floor(Math.random() * types.length)];
}
