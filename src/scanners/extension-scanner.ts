import * as fs from 'fs';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import axios from 'axios';
import { log } from '../utils/logging';
import { OutdatedExtension } from '../types/scanning';
import { determineSeverity } from '../utils/severity-calculator';

const execAsync = promisify(exec);

/**
 * Scans for outdated browser extensions in the codebase
 */
export async function scanBrowserExtensions(rootDir: string): Promise<OutdatedExtension[]> {
  try {
    log.info('Starting browser extension scanning');
    
    const results: OutdatedExtension[] = [];
    
    // Find all manifest.json files (potentially browser extensions)
    const manifestFiles = await findExtensionManifests(rootDir);
    log.debug(`Found ${manifestFiles.length} potential extension manifest files`);
    
    // Process each manifest
    for (const manifestFile of manifestFiles) {
      try {
        // Skip node_modules directories
        if (manifestFile.includes('node_modules')) {
          continue;
        }
        
        const manifestContent = fs.readFileSync(manifestFile, 'utf8');
        const manifest = JSON.parse(manifestContent);
        
        // Determine if this is actually a browser extension manifest
        if (isExtensionManifest(manifest)) {
          const extensionInfo = await processExtensionManifest(manifest, manifestFile);
          if (extensionInfo) {
            results.push(extensionInfo);
          }
        }
      } catch (error) {
        log.warn(`Error processing manifest file: ${manifestFile}`, { error });
      }
    }
    
    log.info(`Extension scanning completed. Found ${results.length} outdated browser extensions`);
    
    return results;
  } catch (error) {
    log.error('Error during browser extension scanning', { error });
    return [];
  }
}

/**
 * Finds all potential extension manifest files in the codebase
 */
async function findExtensionManifests(rootDir: string): Promise<string[]> {
  try {
    // Find manifest.json files
    const chromeManifests = await findFiles(rootDir, 'manifest.json');
    
    // Find package.json files that might be Firefox add-on manifests
    const packageJsons = await findFiles(rootDir, 'package.json');
    const firefoxManifests = await filterFirefoxManifests(packageJsons);
    
    // Find Info.plist files that might be Safari extension manifests
    const safariManifests = await findFiles(rootDir, 'Info.plist');
    
    return [...chromeManifests, ...firefoxManifests, ...safariManifests];
  } catch (error) {
    log.error('Error finding extension manifests', { error });
    return [];
  }
}

/**
 * Filters package.json files that are actually Firefox add-on manifests
 */
async function filterFirefoxManifests(packageJsons: string[]): Promise<string[]> {
  const firefoxManifests: string[] = [];
  
  for (const packageFile of packageJsons) {
    try {
      const content = fs.readFileSync(packageFile, 'utf8');
      const packageJson = JSON.parse(content);
      
      // Check if this is a Firefox add-on
      if (
        packageJson.engines && 
        (packageJson.engines.firefox || packageJson.engines['gecko']) ||
        packageJson.applications && packageJson.applications.gecko
      ) {
        firefoxManifests.push(packageFile);
      }
    } catch (error) {
      // Silently ignore errors
    }
  }
  
  return firefoxManifests;
}

/**
 * Determines if a given manifest JSON is actually a browser extension manifest
 */
function isExtensionManifest(manifest: any): boolean {
  // Check for Chrome/Edge extension manifest
  if (
    manifest.manifest_version && 
    (manifest.browser_action || manifest.page_action || manifest.background || manifest.content_scripts)
  ) {
    return true;
  }
  
  // Check for Firefox add-on manifest
  if (
    manifest.engines && 
    (manifest.engines.firefox || manifest.engines['gecko']) ||
    manifest.applications && manifest.applications.gecko
  ) {
    return true;
  }
  
  // Check for Safari extension hints
  if (
    manifest.CFBundleIdentifier && 
    manifest.CFBundlePackageType && 
    manifest.NSExtension
  ) {
    return true;
  }
  
  return false;
}

/**
 * Processes an extension manifest and returns information if it's outdated
 */
async function processExtensionManifest(
  manifest: any, 
  manifestPath: string
): Promise<OutdatedExtension | null> {
  try {
    // Determine extension type/browser
    const browser = determineBrowser(manifest, manifestPath);
    if (!browser) {
      return null;
    }
    
    // Get extension details
    const name = getExtensionName(manifest, browser);
    const currentVersion = getExtensionVersion(manifest, browser);
    
    if (!name || !currentVersion) {
      log.debug(`Could not determine name or version for extension at ${manifestPath}`);
      return null;
    }
    
    // Get extension ID
    const id = getExtensionId(manifest, browser) || name.toLowerCase().replace(/\s+/g, '-');
    
    // Check for latest version and issues
    const {
      latestVersion,
      hasSecurityIssues,
      hasCompatibilityIssues,
      isDeprecated,
      updateUrl
    } = await checkExtensionStore(id, name, currentVersion, browser);
    
    // If we couldn't determine the latest version, or it's the same as current, 
    // the extension is not outdated
    if (!latestVersion || latestVersion === currentVersion) {
      return null;
    }
    
    // Determine severity based on various factors
    const severity = determineSeverity({
      versionDifference: { current: currentVersion, latest: latestVersion },
      isDeprecated,
      hasSecurityIssues,
      hasCompatibilityIssues
    });
    
    return {
      id,
      name,
      browser,
      currentVersion,
      latestVersion,
      manifestPath,
      severity,
      hasSecurityIssues: !!hasSecurityIssues,
      hasCompatibilityIssues: !!hasCompatibilityIssues,
      isDeprecated: !!isDeprecated,
      updateUrl,
      detectedAt: new Date()
    };
  } catch (error) {
    log.warn(`Error processing extension manifest at ${manifestPath}`, { error });
    return null;
  }
}

/**
 * Determines which browser the extension is for
 */
function determineBrowser(manifest: any, manifestPath: string): 'chrome' | 'firefox' | 'safari' | 'edge' | null {
  if (manifestPath.includes('Info.plist')) {
    return 'safari';
  }
  
  if (manifestPath.includes('package.json')) {
    if (
      manifest.engines && 
      (manifest.engines.firefox || manifest.engines['gecko']) ||
      manifest.applications && manifest.applications.gecko
    ) {
      return 'firefox';
    }
  }
  
  if (manifestPath.includes('manifest.json')) {
    // Check for Edge specific fields
    if (
      manifest.browser_specific_settings && 
      manifest.browser_specific_settings.edge
    ) {
      return 'edge';
    }
    
    // Default to Chrome for standard WebExtension manifests
    if (manifest.manifest_version) {
      return 'chrome';
    }
  }
  
  return null;
}

/**
 * Gets the extension name from the manifest based on browser type
 */
function getExtensionName(manifest: any, browser: string): string | null {
  switch (browser) {
    case 'chrome':
    case 'edge':
      return manifest.name || null;
      
    case 'firefox':
      return manifest.name || null;
      
    case 'safari':
      return manifest.CFBundleDisplayName || manifest.CFBundleName || null;
      
    default:
      return null;
  }
}

/**
 * Gets the extension version from the manifest based on browser type
 */
function getExtensionVersion(manifest: any, browser: string): string | null {
  switch (browser) {
    case 'chrome':
    case 'edge':
      return manifest.version || null;
      
    case 'firefox':
      return manifest.version || null;
      
    case 'safari':
      return manifest.CFBundleShortVersionString || manifest.CFBundleVersion || null;
      
    default:
      return null;
  }
}

/**
 * Gets the extension ID from the manifest based on browser type
 */
function getExtensionId(manifest: any, browser: string): string | null {
  switch (browser) {
    case 'chrome':
      return manifest.key ? manifest.key : null;
      
    case 'edge':
      return manifest.browser_specific_settings?.edge?.extension_id || null;
      
    case 'firefox':
      return manifest.applications?.gecko?.id || manifest.browser_specific_settings?.gecko?.id || null;
      
    case 'safari':
      return manifest.CFBundleIdentifier || null;
      
    default:
      return null;
  }
}

/**
 * Checks extension store for latest version and potential issues
 */
async function checkExtensionStore(
  id: string,
  name: string,
  currentVersion: string,
  browser: string
): Promise<{
  latestVersion?: string;
  hasSecurityIssues?: boolean;
  hasCompatibilityIssues?: boolean;
  isDeprecated?: boolean;
  updateUrl?: string;
}> {
  try {
    switch (browser) {
      case 'chrome':
        return await checkChromeWebStore(id, name, currentVersion);
        
      case 'firefox':
        return await checkFirefoxAddons(id, name, currentVersion);
        
      case 'safari':
        return await checkSafariExtensions(id, name, currentVersion);
        
      case 'edge':
        return await checkEdgeAddons(id, name, currentVersion);
        
      default:
        return {};
    }
  } catch (error) {
    log.warn(`Error checking extension store for ${name} (${browser})`, { error });
    return {};
  }
}

/**
 * Checks Chrome Web Store for extension information
 */
async function checkChromeWebStore(
  id: string, 
  name: string, 
  currentVersion: string
): Promise<{
  latestVersion?: string;
  hasSecurityIssues?: boolean;
  hasCompatibilityIssues?: boolean;
  isDeprecated?: boolean;
  updateUrl?: string;
}> {
  try {
    // Try to get info by ID if available
    if (id && id.length > 20) {
      try {
        const response = await axios.get(`https://chrome.google.com/webstore/detail/${id}`);
        
        // Extract version from response using regex
        const versionMatch = response.data.match(/"version"\s*:\s*"([\d\.]+)"/i);
        if (versionMatch && versionMatch[1]) {
          const latestVersion = versionMatch[1];
          
          // Check for deprecation hints
          const isDeprecated = response.data.includes('no longer available') || 
                              response.data.includes('has been deprecated') ||
                              response.data.includes('This item has been disabled');
                              
          return {
            latestVersion,
            isDeprecated,
            updateUrl: `https://chrome.google.com/webstore/detail/${id}`
          };
        }
      } catch (error) {
        // If 404, the extension might be deprecated or removed
        if (axios.isAxiosError(error) && error.response?.status === 404) {
          return {
            isDeprecated: true
          };
        }
      }
    }
    
    // Fallback: Check Web Store using the extension name
    try {
      // This is a simplified approach - in a real implementation, you might need to 
      // use a Chrome Web Store API if available, or more sophisticated scraping
      const searchName = encodeURIComponent(name);
      const response = await axios.get(`https://chrome.google.com/webstore/search/${searchName}`);
      
      // Simple check if the extension might exist in store
      if (response.data.includes(name)) {
        return {
          hasCompatibilityIssues: false
        };
      } else {
        return {
          hasCompatibilityIssues: true,
          isDeprecated: true
        };
      }
    } catch (error) {
      log.warn(`Error searching Chrome Web Store for ${name}`, { error });
    }
    
    return {};
  } catch (error) {
    log.warn(`Error checking Chrome Web Store for ${name}`, { error });
    return {};
  }
}

/**
 * Checks Firefox Add-ons for extension information
 */
async function checkFirefoxAddons(
  id: string, 
  name: string, 
  currentVersion: string
): Promise<{
  latestVersion?: string;
  hasSecurityIssues?: boolean;
  hasCompatibilityIssues?: boolean;
  isDeprecated?: boolean;
  updateUrl?: string;
}> {
  try {
    // Try to get by ID first
    if (id) {
      try {
        const response = await axios.get(`https://addons.mozilla.org/api/v5/addons/addon/${id}/`);
        const data = response.data;
        
        return {
          latestVersion: data.current_version?.version,
          isDeprecated: !data.is_listed || data.status === 'deleted',
          hasSecurityIssues: data.current_version?.compatibility_count?.['firefox'] === 0,
          updateUrl: `https://addons.mozilla.org/en-US/firefox/addon/${data.slug}/`
        };
      } catch (error) {
        if (axios.isAxiosError(error) && error.response?.status === 404) {
          // Add-on not found - might be deprecated
          return { isDeprecated: true };
        }
      }
    }
    
    // Fallback: Try to search by name
    try {
      const searchName = encodeURIComponent(name);
      const response = await axios.get(`https://addons.mozilla.org/api/v5/addons/search/?q=${searchName}&sort=relevance&type=extension`);
      
      // Try to find a matching add-on
      const matchingAddons = response.data.results.filter((addon: any) => 
        addon.name.toLowerCase().includes(name.toLowerCase())
      );
      
      if (matchingAddons.length > 0) {
        const addon = matchingAddons[0];
        return {
          latestVersion: addon.current_version?.version,
          isDeprecated: !addon.is_listed,
          updateUrl: `https://addons.mozilla.org/en-US/firefox/addon/${addon.slug}/`
        };
      }
    } catch (error) {
      log.warn(`Error searching Firefox Add-ons for ${name}`, { error });
    }
    
    return {};
  } catch (error) {
    log.warn(`Error checking Firefox Add-ons for ${name}`, { error });
    return {};
  }
}

/**
 * Checks Safari Extensions for extension information
 */
async function checkSafariExtensions(
  id: string, 
  name: string, 
  currentVersion: string
): Promise<{
  latestVersion?: string;
  hasSecurityIssues?: boolean;
  hasCompatibilityIssues?: boolean;
  isDeprecated?: boolean;
  updateUrl?: string;
}> {
  try {
    // Safari doesn't have a public API for extensions, so we'll use App Store search
    const searchName = encodeURIComponent(name);
    const response = await axios.get(`https://itunes.apple.com/search?term=${searchName}&entity=macSoftware&limit=10`);
    
    if (response.data.resultCount > 0) {
      // Try to find a matching app
      const matchingApps = response.data.results.filter((app: any) => 
        app.trackName.toLowerCase().includes(name.toLowerCase())
      );
      
      if (matchingApps.length > 0) {
        const app = matchingApps[0];
        return {
          latestVersion: app.version,
          isDeprecated: false,
          updateUrl: app.trackViewUrl
        };
      }
    }
    
    // For Safari, it's harder to determine if an extension is deprecated
    // We'll conservatively mark anything we can't find as potentially having compatibility issues
    return {
      hasCompatibilityIssues: true
    };
  } catch (error) {
    log.warn(`Error checking Safari Extensions for ${name}`, { error });
    return {};
  }
}

/**
 * Checks Edge Add-ons for extension information
 */
async function checkEdgeAddons(
  id: string, 
  name: string, 
  currentVersion: string
): Promise<{
  latestVersion?: string;
  hasSecurityIssues?: boolean;
  hasCompatibilityIssues?: boolean;
  isDeprecated?: boolean;
  updateUrl?: string;
}> {
  try {
    // Edge Add-ons doesn't have a public API
    // First, we'll try to search for the extension
    const searchName = encodeURIComponent(name);
    const response = await axios.get(`https://microsoftedge.microsoft.com/addons/search?query=${searchName}`);
    
    // Check if we can find the extension mentioned
    if (response.data.includes(name)) {
      // This is a simplified approach - in a real implementation, you'd need more sophisticated scraping
      // to get the actual latest version
      return {
        hasCompatibilityIssues: false,
        updateUrl: `https://microsoftedge.microsoft.com/addons/search?query=${searchName}`
      };
    }
    
    // For Edge, we'll conservatively mark anything we can't confirm as potentially having compatibility issues
    return {
      hasCompatibilityIssues: true
    };
  } catch (error) {
    log.warn(`Error checking Edge Add-ons for ${name}`, { error });
    return {};
  }
}

/**
 * Find files with a specific name recursively
 */
async function findFiles(rootDir: string, fileName: string): Promise<string[]> {
  try {
    const { stdout } = await execAsync(`find ${rootDir} -name "${fileName}" -type f`);
    return stdout.trim().split('\n').filter(Boolean);
  } catch (error) {
    log.error(`Error finding ${fileName} files`, { error });
    return [];
  }
}
