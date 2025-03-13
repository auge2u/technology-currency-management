import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { promisify } from 'util';
import { glob } from 'glob';
import { log } from '../utils/logging';
import { ExtensionIssue } from '../types/scanning';
import { compareVersions, daysBetween } from '../utils/scanner-utils';

const readFileAsync = promisify(fs.readFile);
const readdirAsync = promisify(fs.readdir);
const statAsync = promisify(fs.stat);

/**
 * Configuration for extension scanning
 */
export interface ExtensionScannerConfig {
  // Which browsers to scan
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
  
  // Maximum age in days before considering an extension outdated
  maxExtensionAgeDays: number;
}

/**
 * Detected browser extension
 */
interface DetectedExtension {
  id: string;
  name: string;
  version: string;
  browser: 'chrome' | 'firefox' | 'edge' | 'safari';
  location: string;
  manifestPath: string;
  updateUrl?: string;
  installDate?: Date;
  lastUpdateDate?: Date;
}

/**
 * Extension version info from store
 */
interface ExtensionVersionInfo {
  latestVersion: string;
  latestUpdateDate?: Date;
  isDeprecated: boolean;
  isRemoved: boolean;
  userCount?: number;
  rating?: number;
  storeUrl?: string;
  knownVulnerabilities: Array<{
    id: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    fixedInVersion?: string;
  }>;
  alternatives?: Array<{
    id: string;
    name: string;
    url: string;
  }>;
}

/**
 * Scanner for detecting outdated browser extensions
 */
export async function scanExtensions(
  config: ExtensionScannerConfig
): Promise<ExtensionIssue[]> {
  try {
    log.info('Starting browser extension scanner');
    const issues: ExtensionIssue[] = [];
    
    // Detect extensions for each browser
    for (const browser of config.browsers) {
      try {
        log.info(`Scanning ${browser} extensions`);
        const extensions = await detectExtensions(browser);
        log.info(`Found ${extensions.length} ${browser} extensions`);
        
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
              extension.version,
              extension.browser,
              config.offlineMode,
              config.checkVulnerabilities,
              config.cacheDir
            );
            
            // Check if outdated
            const isOutdated = compareVersions(extension.version, extensionInfo.latestVersion) < 0;
            
            // Check if very old (not updated in a long time)
            const isVeryOld = extension.lastUpdateDate && extensionInfo.latestUpdateDate && 
              daysBetween(extension.lastUpdateDate, extensionInfo.latestUpdateDate) > config.maxExtensionAgeDays;
            
            // Only create an issue if there's at least one problem
            if (isOutdated || isVeryOld || extensionInfo.isDeprecated || extensionInfo.isRemoved || 
                extensionInfo.knownVulnerabilities.length > 0) {
              
              // Create the issue
              const issue: ExtensionIssue = {
                id: extension.id,
                name: extension.name,
                browser: extension.browser,
                currentVersion: extension.version,
                latestVersion: extensionInfo.latestVersion,
                location: extension.location,
                isOutdated,
                isDeprecated: extensionInfo.isDeprecated,
                isRemoved: extensionInfo.isRemoved,
                userCount: extensionInfo.userCount,
                rating: extensionInfo.rating,
                storeUrl: extensionInfo.storeUrl,
                lastUpdated: extension.lastUpdateDate,
                latestUpdateDate: extensionInfo.latestUpdateDate,
                detectedAt: new Date()
              };
              
              // Add vulnerability info if any exist
              if (extensionInfo.knownVulnerabilities.length > 0) {
                issue.vulnerabilities = extensionInfo.knownVulnerabilities.map(v => ({
                  id: v.id,
                  severity: v.severity,
                  description: v.description,
                  fixedInVersion: v.fixedInVersion
                }));
              }
              
              // Calculate business impact
              issue.businessImpact = calculateBusinessImpact(
                extension.name,
                isOutdated,
                extensionInfo.isDeprecated,
                extensionInfo.knownVulnerabilities.length > 0,
                extensionInfo.userCount || 0
              );
              
              // Generate recommendation
              issue.recommendation = generateRecommendation(
                extension,
                extensionInfo,
                isOutdated,
                isVeryOld
              );
              
              // Add appropriate tags
              issue.tags = generateTags(
                extension.browser,
                isOutdated,
                isVeryOld,
                extensionInfo.isDeprecated,
                extensionInfo.isRemoved,
                extensionInfo.knownVulnerabilities.length > 0
              );
              
              // Add to issues list
              issues.push(issue);
              log.info(`Added issue for extension ${extension.name} (${extension.id})`);
            }
          } catch (extError) {
            log.warn(`Error processing extension: ${extension.name} (${extension.id})`, { error: extError });
          }
        }
      } catch (browserError) {
        log.error(`Error scanning ${browser} extensions`, { error: browserError });
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
 * Detect installed extensions for a specific browser
 */
async function detectExtensions(
  browser: 'chrome' | 'firefox' | 'edge' | 'safari'
): Promise<DetectedExtension[]> {
  try {
    const extensions: DetectedExtension[] = [];
    const homedir = os.homedir();
    let extensionDirs: string[] = [];
    
    // Determine extension directory based on browser and OS
    switch (browser) {
      case 'chrome':
        if (os.platform() === 'win32') {
          extensionDirs = [
            path.join(process.env.LOCALAPPDATA || '', 'Google', 'Chrome', 'User Data', 'Default', 'Extensions')
          ];
        } else if (os.platform() === 'darwin') {
          extensionDirs = [
            path.join(homedir, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Extensions')
          ];
        } else if (os.platform() === 'linux') {
          extensionDirs = [
            path.join(homedir, '.config', 'google-chrome', 'Default', 'Extensions')
          ];
        }
        break;
        
      case 'firefox':
        if (os.platform() === 'win32') {
          extensionDirs = [
            path.join(process.env.APPDATA || '', 'Mozilla', 'Firefox', 'Profiles')
          ];
        } else if (os.platform() === 'darwin') {
          extensionDirs = [
            path.join(homedir, 'Library', 'Application Support', 'Firefox', 'Profiles')
          ];
        } else if (os.platform() === 'linux') {
          extensionDirs = [
            path.join(homedir, '.mozilla', 'firefox')
          ];
        }
        break;
        
      case 'edge':
        if (os.platform() === 'win32') {
          extensionDirs = [
            path.join(process.env.LOCALAPPDATA || '', 'Microsoft', 'Edge', 'User Data', 'Default', 'Extensions')
          ];
        } else if (os.platform() === 'darwin') {
          extensionDirs = [
            path.join(homedir, 'Library', 'Application Support', 'Microsoft Edge', 'Default', 'Extensions')
          ];
        } else if (os.platform() === 'linux') {
          extensionDirs = [
            path.join(homedir, '.config', 'microsoft-edge', 'Default', 'Extensions')
          ];
        }
        break;
        
      case 'safari':
        if (os.platform() === 'darwin') {
          extensionDirs = [
            path.join(homedir, 'Library', 'Safari', 'Extensions'),
            path.join(homedir, 'Library', 'Containers')
          ];
        }
        break;
    }
    
    // Process each extension directory
    for (const extensionDir of extensionDirs) {
      // Check if directory exists
      if (!fs.existsSync(extensionDir)) {
        log.info(`Extension directory not found: ${extensionDir}`);
        continue;
      }
      
      switch (browser) {
        case 'chrome':
        case 'edge':
          // Chrome/Edge: Each extension is in a subdirectory with its ID
          const extensionIds = await readdirAsync(extensionDir);
          
          for (const extensionId of extensionIds) {
            const extPath = path.join(extensionDir, extensionId);
            const extStat = await statAsync(extPath);
            
            if (extStat.isDirectory()) {
              // Each version is in a subdirectory
              const versionDirs = await readdirAsync(extPath);
              
              if (versionDirs.length > 0) {
                // Use the highest version directory
                const latestVersion = versionDirs.sort(compareVersions).pop()!;
                const versionPath = path.join(extPath, latestVersion);
                const manifestPath = path.join(versionPath, 'manifest.json');
                
                if (fs.existsSync(manifestPath)) {
                  try {
                    const manifestContent = await readFileAsync(manifestPath, 'utf8');
                    const manifest = JSON.parse(manifestContent);
                    
                    extensions.push({
                      id: extensionId,
                      name: manifest.name || `Unknown Extension (${extensionId})`,
                      version: manifest.version || latestVersion,
                      browser,
                      location: versionPath,
                      manifestPath,
                      updateUrl: manifest.update_url,
                      installDate: extStat.birthtime,
                      lastUpdateDate: extStat.mtime
                    });
                  } catch (manifestError) {
                    log.warn(`Error parsing manifest for ${extensionId}`, { error: manifestError });
                  }
                }
              }
            }
          }
          break;
          
        case 'firefox':
          // Firefox: Need to find profile directories first
          const profileDirs = await readdirAsync(extensionDir);
          
          for (const profileDir of profileDirs) {
            const profilePath = path.join(extensionDir, profileDir);
            const profileStat = await statAsync(profilePath);
            
            if (profileStat.isDirectory()) {
              const extensionsPath = path.join(profilePath, 'extensions');
              
              if (fs.existsSync(extensionsPath)) {
                const extFiles = await readdirAsync(extensionsPath);
                
                for (const extFile of extFiles) {
                  const extPath = path.join(extensionsPath, extFile);
                  const extStat = await statAsync(extPath);
                  
                  if (extStat.isDirectory() || extFile.endsWith('.xpi')) {
                    let manifestPath = path.join(extPath, 'manifest.json');
                    
                    if (fs.existsSync(manifestPath)) {
                      try {
                        const manifestContent = await readFileAsync(manifestPath, 'utf8');
                        const manifest = JSON.parse(manifestContent);
                        
                        extensions.push({
                          id: manifest.applications?.gecko?.id || extFile,
                          name: manifest.name || `Unknown Extension (${extFile})`,
                          version: manifest.version || '0.0.0',
                          browser,
                          location: extPath,
                          manifestPath,
                          installDate: extStat.birthtime,
                          lastUpdateDate: extStat.mtime
                        });
                      } catch (manifestError) {
                        log.warn(`Error parsing manifest for ${extFile}`, { error: manifestError });
                      }
                    }
                  }
                }
              }
            }
          }
          break;
          
        case 'safari':
          // Safari: Extensions are in .safariextz files or app bundles
          const extFiles = await readdirAsync(extensionDir);
          
          for (const extFile of extFiles) {
            if (extFile.endsWith('.safariextz') || extFile.endsWith('.appex')) {
              const extPath = path.join(extensionDir, extFile);
              const extStat = await statAsync(extPath);
              
              // For Safari, we might need to parse the Info.plist file
              // This is simplified for the example
              const id = extFile.replace(/\.(safariextz|appex)$/, '');
              const name = id;
              
              extensions.push({
                id,
                name,
                version: '1.0.0', // Placeholder, would need to extract from Info.plist
                browser,
                location: extPath,
                manifestPath: extPath,
                installDate: extStat.birthtime,
                lastUpdateDate: extStat.mtime
              });
            }
          }
          break;
      }
    }
    
    return extensions;
  } catch (error) {
    log.error(`Error detecting ${browser} extensions`, { error });
    return [];
  }
}

/**
 * Get extension information from store or cache
 */
async function getExtensionInfo(
  id: string,
  name: string,
  version: string,
  browser: 'chrome' | 'firefox' | 'edge' | 'safari',
  offlineMode: boolean,
  checkVulnerabilities: boolean,
  cacheDir?: string
): Promise<ExtensionVersionInfo> {
  // Check cache first
  if (cacheDir) {
    const cacheFile = path.join(cacheDir, `${browser}-${id}.json`);
    
    if (fs.existsSync(cacheFile)) {
      try {
        const cacheContent = await readFileAsync(cacheFile, 'utf8');
        const cachedInfo = JSON.parse(cacheContent) as ExtensionVersionInfo;
        log.info(`Loaded ${name} (${id}) info from cache`);
        return cachedInfo;
      } catch (cacheError) {
        log.warn(`Error reading extension cache for ${name} (${id})`, { error: cacheError });
      }
    }
  }
  
  // If in offline mode and no cache, return placeholder data
  if (offlineMode) {
    log.info(`Offline mode enabled for ${name} (${id}), using placeholder data`);
    return {
      latestVersion: version, // Assume current version is latest
      isDeprecated: false,
      isRemoved: false,
      knownVulnerabilities: []
    };
  }
  
  // In a real implementation, we would query the extension store API
  // For this example, we'll return mock data
  try {
    // Mock store query
    log.info(`Querying store for ${browser} extension: ${name} (${id})`);
    
    // Generate mock data based on the extension
    const info: ExtensionVersionInfo = {
      latestVersion: incrementVersion(version),
      latestUpdateDate: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000), // Random date in last year
      isDeprecated: id.includes('deprecated') || name.toLowerCase().includes('deprecated'),
      isRemoved: id.includes('removed') || name.toLowerCase().includes('discontinued'),
      userCount: Math.floor(Math.random() * 1000000),
      rating: Math.random() * 5,
      storeUrl: getStoreUrl(id, browser),
      knownVulnerabilities: []
    };
    
    // Add vulnerabilities for some extensions (for demo purposes)
    if (checkVulnerabilities && (name.toLowerCase().includes('vulnerable') || Math.random() < 0.1)) {
      info.knownVulnerabilities = [
        {
          id: `VULN-${Math.floor(Math.random() * 10000)}`,
          severity: getRandomSeverity(),
          description: `Security vulnerability in ${name} that could allow ${getRandomVulnerabilityType()}`,
          fixedInVersion: info.latestVersion
        }
      ];
    }
    
    // If deprecated or removed, suggest alternatives
    if (info.isDeprecated || info.isRemoved) {
      info.alternatives = [
        {
          id: `alt-${id}`,
          name: `${name.replace('Deprecated', 'Modern').replace('Legacy', 'New')} Alternative`,
          url: getStoreUrl(`alt-${id}`, browser)
        }
      ];
    }
    
    // Save to cache if cacheDir is provided
    if (cacheDir) {
      try {
        if (!fs.existsSync(cacheDir)) {
          fs.mkdirSync(cacheDir, { recursive: true });
        }
        
        const cacheFile = path.join(cacheDir, `${browser}-${id}.json`);
        await fs.promises.writeFile(cacheFile, JSON.stringify(info, null, 2), 'utf8');
        log.info(`Cached ${name} (${id}) info`);
      } catch (cacheError) {
        log.warn(`Error writing extension cache for ${name} (${id})`, { error: cacheError });
      }
    }
    
    return info;
  } catch (error) {
    log.error(`Error querying store for ${name} (${id})`, { error });
    
    // Return basic info if store query fails
    return {
      latestVersion: version,
      isDeprecated: false,
      isRemoved: false,
      knownVulnerabilities: []
    };
  }
}

/**
 * Calculate business impact score
 */
function calculateBusinessImpact(
  name: string,
  isOutdated: boolean,
  isDeprecated: boolean,
  hasVulnerabilities: boolean,
  userCount: number
): number {
  let score = 1; // Start with minimal impact
  
  if (isOutdated) score += 1;
  if (isDeprecated) score += 2;
  if (hasVulnerabilities) score += 2;
  
  // If the extension has many users, it's likely important
  if (userCount > 500000) score += 1;
  
  // Some extensions are likely to be critical based on their names
  const criticalKeywords = ['security', 'password', 'vpn', 'authentication', 'wallet', 'crypto'];
  if (criticalKeywords.some(keyword => name.toLowerCase().includes(keyword))) {
    score += 1;
  }
  
  // Cap at maximum of 5
  return Math.min(score, 5);
}

/**
 * Generate a recommendation
 */
function generateRecommendation(
  extension: DetectedExtension,
  extensionInfo: ExtensionVersionInfo,
  isOutdated: boolean,
  isVeryOld: boolean
): string {
  const recommendations: string[] = [];
  
  if (extensionInfo.isRemoved) {
    if (extensionInfo.alternatives && extensionInfo.alternatives.length > 0) {
      const alternative = extensionInfo.alternatives[0];
      recommendations.push(`Replace removed extension ${extension.name} with ${alternative.name} (${alternative.url})`);
    } else {
      recommendations.push(`Remove the discontinued extension ${extension.name}`);
    }
  } else if (extensionInfo.isDeprecated) {
    if (extensionInfo.alternatives && extensionInfo.alternatives.length > 0) {
      const alternative = extensionInfo.alternatives[0];
      recommendations.push(`Replace deprecated extension ${extension.name} with ${alternative.name} (${alternative.url})`);
    } else {
      recommendations.push(`Consider replacing deprecated extension ${extension.name}`);
    }
  } else if (extensionInfo.knownVulnerabilities.length > 0) {
    recommendations.push(`Update ${extension.name} immediately to address security vulnerabilities`);
  } else if (isOutdated) {
    recommendations.push(`Update ${extension.name} from ${extension.version} to ${extensionInfo.latestVersion}`);
  } else if (isVeryOld) {
    recommendations.push(`Verify that ${extension.name} is still maintained and consider finding alternatives`);
  }
  
  if (recommendations.length === 0) {
    recommendations.push(`No immediate action required for ${extension.name}`);
  }
  
  return recommendations.join('. ');
}

/**
 * Generate tags for categorizing issues
 */
function generateTags(
  browser: string,
  isOutdated: boolean,
  isVeryOld: boolean,
  isDeprecated: boolean,
  isRemoved: boolean,
  hasVulnerabilities: boolean
): string[] {
  const tags: string[] = [browser];
  
  if (isOutdated) tags.push('outdated');
  if (isVeryOld) tags.push('unmaintained');
  if (isDeprecated) tags.push('deprecated');
  if (isRemoved) tags.push('removed');
  if (hasVulnerabilities) tags.push('security');
  
  return tags;
}

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
    
    // Increment the last part
    const lastPart = parseInt(parts[parts.length - 1], 10) || 0;
    parts[parts.length - 1] = String(lastPart + 1);
    
    return parts.join('.');
  } catch (error) {
    return `${version}.1`; // Fallback
  }
}

/**
 * Get a store URL for an extension
 */
function getStoreUrl(id: string, browser: 'chrome' | 'firefox' | 'edge' | 'safari'): string {
  switch (browser) {
    case 'chrome':
      return `https://chrome.google.com/webstore/detail/${id}`;
    case 'firefox':
      return `https://addons.mozilla.org/en-US/firefox/addon/${id.replace('@', '')}`;
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
  return severities[Math.floor(Math.random() * severities.length)];
}

/**
 * Helper function for getting a random vulnerability type
 */
function getRandomVulnerabilityType(): string {
  const types = [
    'unauthorized data access',
    'cross-site scripting (XSS)',
    'privilege escalation',
    'data leakage',
    'malicious code execution',
    'browser fingerprinting',
    'API key exposure',
    'DOM-based vulnerabilities'
  ];
  return types[Math.floor(Math.random() * types.length)];
}
