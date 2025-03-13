import * as fs from 'fs';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import { DependencyIssue, VulnerabilityInfo } from '../types/scanning';
import { compareVersions } from '../utils/scanner-utils';
import { log } from '../utils/logging';

const execAsync = promisify(exec);

/**
 * Configuration for dependency scanning
 */
export interface DependencyScannerConfig {
  // Root directory to scan
  rootDirectory: string;
  
  // Ecosystems to check
  ecosystems: Array<'npm' | 'pip' | 'maven' | 'gradle' | 'nuget' | 'composer' | 'cargo' | 'go'>;
  
  // Whether to scan for transitive dependencies
  checkTransitiveDependencies: boolean;
  
  // Whether to check for vulnerabilities
  checkVulnerabilities: boolean;
  
  // Whether to scan dev dependencies
  includeDevDependencies: boolean;
  
  // Security advisory sources to use
  securityAdvisorySources: Array<'npm' | 'github' | 'snyk' | 'osv' | 'nvd'>;
  
  // Severity threshold (only report issues at or above this severity)
  severityThreshold: 'low' | 'medium' | 'high' | 'critical';
  
  // Skip dependencies with specific names
  ignoreDependencies?: string[];
  
  // Skip dependencies matching specific patterns
  ignorePatterns?: string[];
  
  // Retry limit for external API calls
  apiRetryLimit: number;
  
  // API timeout in milliseconds
  apiTimeoutMs: number;
}

/**
 * Scan project dependencies for outdated packages and vulnerabilities
 */
export async function scanDependencies(
  config: DependencyScannerConfig
): Promise<DependencyIssue[]> {
  try {
    log.info('Starting dependency scanner');
    
    const issues: DependencyIssue[] = [];
    
    // Find all package manifests based on enabled ecosystems
    const manifests = await findPackageManifests(config);
    log.info(`Found ${manifests.length} dependency manifests to scan`);
    
    // Process each manifest file
    for (const manifest of manifests) {
      try {
        const dependencyIssues = await scanManifest(manifest, config);
        issues.push(...dependencyIssues);
      } catch (manifestError) {
        log.warn(`Error scanning manifest ${manifest.path}`, { error: manifestError });
      }
    }
    
    log.info(`Completed dependency scanning. Found ${issues.length} issues`);
    return issues;
  } catch (error) {
    log.error('Error during dependency scanning', { error });
    return [];
  }
}

/**
 * Map of file patterns for each supported ecosystem
 */
const ECOSYSTEM_FILE_PATTERNS: Record<string, string[]> = {
  npm: ['package.json'],
  pip: ['requirements.txt', 'setup.py', 'Pipfile', 'pyproject.toml'],
  maven: ['pom.xml'],
  gradle: ['build.gradle', 'build.gradle.kts'],
  nuget: ['*.csproj', '*.fsproj', 'packages.config'],
  composer: ['composer.json'],
  cargo: ['Cargo.toml'],
  go: ['go.mod']
};

/**
 * Information about a package manifest file
 */
interface ManifestInfo {
  path: string;
  ecosystem: 'npm' | 'pip' | 'maven' | 'gradle' | 'nuget' | 'composer' | 'cargo' | 'go';
  dependencies: Map<string, string>;
}

/**
 * Find all package manifest files in the project
 */
async function findPackageManifests(config: DependencyScannerConfig): Promise<ManifestInfo[]> {
  const manifests: ManifestInfo[] = [];
  
  for (const ecosystem of config.ecosystems) {
    const filePatterns = ECOSYSTEM_FILE_PATTERNS[ecosystem];
    
    if (!filePatterns) {
      log.warn(`Unknown ecosystem: ${ecosystem}`);
      continue;
    }
    
    for (const pattern of filePatterns) {
      const foundFiles = await globFiles(path.join(config.rootDirectory, '**', pattern));
      
      for (const filePath of foundFiles) {
        try {
          const dependencies = await parseDependencies(filePath, ecosystem, config.includeDevDependencies);
          
          if (dependencies.size > 0) {
            manifests.push({
              path: filePath,
              ecosystem,
              dependencies
            });
          }
        } catch (parseError) {
          log.warn(`Error parsing dependencies in ${filePath}`, { error: parseError });
        }
      }
    }
  }
  
  return manifests;
}

/**
 * Find files matching a glob pattern
 */
async function globFiles(pattern: string): Promise<string[]> {
  // Using a dynamic import for glob as it's an ESM module in newer versions
  const { glob } = await import('glob');
  return glob(pattern);
}

/**
 * Parse dependencies from a manifest file
 */
async function parseDependencies(
  filePath: string,
  ecosystem: 'npm' | 'pip' | 'maven' | 'gradle' | 'nuget' | 'composer' | 'cargo' | 'go',
  includeDevDependencies: boolean
): Promise<Map<string, string>> {
  const dependencies = new Map<string, string>();
  
  try {
    const fileContent = fs.readFileSync(filePath, 'utf8');
    
    switch (ecosystem) {
      case 'npm':
        return parseNpmDependencies(fileContent, includeDevDependencies);
      case 'pip':
        return parsePipDependencies(fileContent, filePath);
      case 'maven':
        return parseMavenDependencies(fileContent);
      case 'cargo':
        return parseCargoDependencies(fileContent);
      case 'composer':
        return parseComposerDependencies(fileContent, includeDevDependencies);
      case 'go':
        return parseGoDependencies(fileContent);
      // Add more parsers as needed
      default:
        log.warn(`No parser implemented for ecosystem: ${ecosystem}`);
        return new Map();
    }
  } catch (error) {
    log.warn(`Error reading or parsing ${filePath}`, { error });
    return new Map();
  }
}

/**
 * Parse dependencies from package.json (npm/Node.js)
 */
function parseNpmDependencies(fileContent: string, includeDevDependencies: boolean): Map<string, string> {
  const dependencies = new Map<string, string>();
  
  try {
    const packageJson = JSON.parse(fileContent);
    
    // Regular dependencies
    if (packageJson.dependencies) {
      for (const [name, version] of Object.entries(packageJson.dependencies)) {
        dependencies.set(name, version as string);
      }
    }
    
    // Dev dependencies if enabled
    if (includeDevDependencies && packageJson.devDependencies) {
      for (const [name, version] of Object.entries(packageJson.devDependencies)) {
        dependencies.set(name, version as string);
      }
    }
  } catch (error) {
    log.warn('Error parsing package.json', { error });
  }
  
  return dependencies;
}

/**
 * Parse dependencies from Python requirements files
 */
function parsePipDependencies(fileContent: string, filePath: string): Map<string, string> {
  const dependencies = new Map<string, string>();
  const fileName = path.basename(filePath);
  
  if (fileName === 'requirements.txt') {
    // Parse requirements.txt format
    const lines = fileContent.split('\n');
    
    for (const line of lines) {
      // Skip comments and empty lines
      const trimmedLine = line.trim();
      if (trimmedLine === '' || trimmedLine.startsWith('#')) {
        continue;
      }
      
      // Handle different requirement formats
      // e.g., package==1.0.0, package>=1.0.0, package~=1.0.0
      const requirementMatch = trimmedLine.match(/^([a-zA-Z0-9\-_.]+)(\[.*\])?(\s*[=<>~!]=\s*|\s+)([a-zA-Z0-9\-_.]+)/);
      
      if (requirementMatch) {
        const name = requirementMatch[1];
        const version = requirementMatch[4];
        dependencies.set(name, version);
      }
    }
  } else if (fileName === 'Pipfile') {
    // Simple parsing for Pipfile (would need a TOML parser for proper handling)
    const lines = fileContent.split('\n');
    let inPackagesSection = false;
    
    for (const line of lines) {
      const trimmedLine = line.trim();
      
      if (trimmedLine === '[packages]') {
        inPackagesSection = true;
        continue;
      } else if (trimmedLine.startsWith('[') && trimmedLine.endsWith(']')) {
        inPackagesSection = false;
        continue;
      }
      
      if (inPackagesSection) {
        const packageMatch = trimmedLine.match(/^([a-zA-Z0-9\-_.]+)\s*=\s*"([^"]+)"/);
        if (packageMatch) {
          const name = packageMatch[1];
          const version = packageMatch[2].replace(/^\^|~|==|>=|<=/, '');
          dependencies.set(name, version);
        }
      }
    }
  }
  // Add support for setup.py and pyproject.toml as needed
  
  return dependencies;
}

/**
 * Parse dependencies from Maven pom.xml
 */
function parseMavenDependencies(fileContent: string): Map<string, string> {
  const dependencies = new Map<string, string>();
  
  // Simple regex-based parsing - for production use, a proper XML parser would be better
  const dependencyRegex = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*<version>([^<]+)<\/version>/g;
  
  let match;
  while ((match = dependencyRegex.exec(fileContent)) !== null) {
    const groupId = match[1].trim();
    const artifactId = match[2].trim();
    const version = match[3].trim();
    
    // Use a composite key for Maven dependencies
    const dependencyKey = `${groupId}:${artifactId}`;
    dependencies.set(dependencyKey, version);
  }
  
  return dependencies;
}

/**
 * Parse dependencies from Cargo.toml (Rust)
 */
function parseCargoDependencies(fileContent: string): Map<string, string> {
  const dependencies = new Map<string, string>();
  
  // Simple parsing for TOML - for production use, a proper TOML parser would be better
  const lines = fileContent.split('\n');
  let inDependenciesSection = false;
  
  for (const line of lines) {
    const trimmedLine = line.trim();
    
    if (trimmedLine === '[dependencies]') {
      inDependenciesSection = true;
      continue;
    } else if (trimmedLine.startsWith('[') && trimmedLine.endsWith(']')) {
      inDependenciesSection = false;
      continue;
    }
    
    if (inDependenciesSection && trimmedLine !== '') {
      // Simple key = "value" format
      const simpleMatch = trimmedLine.match(/^([a-zA-Z0-9\-_]+)\s*=\s*"([^"]+)"/);
      if (simpleMatch) {
        const name = simpleMatch[1];
        const version = simpleMatch[2];
        dependencies.set(name, version);
        continue;
      }
      
      // Table format (dependency = { version = "1.0" })
      const tableStartMatch = trimmedLine.match(/^([a-zA-Z0-9\-_]+)\s*=\s*\{/);
      if (tableStartMatch) {
        const name = tableStartMatch[1];
        // Look for version in the next few lines
        const versionMatch = line.match(/version\s*=\s*"([^"]+)"/);
        if (versionMatch) {
          dependencies.set(name, versionMatch[1]);
        }
      }
    }
  }
  
  return dependencies;
}

/**
 * Parse dependencies from composer.json (PHP)
 */
function parseComposerDependencies(fileContent: string, includeDevDependencies: boolean): Map<string, string> {
  const dependencies = new Map<string, string>();
  
  try {
    const composerJson = JSON.parse(fileContent);
    
    // Regular dependencies
    if (composerJson.require) {
      for (const [name, version] of Object.entries(composerJson.require)) {
        // Skip php requirement itself
        if (name !== 'php') {
          dependencies.set(name, version as string);
        }
      }
    }
    
    // Dev dependencies if enabled
    if (includeDevDependencies && composerJson['require-dev']) {
      for (const [name, version] of Object.entries(composerJson['require-dev'])) {
        dependencies.set(name, version as string);
      }
    }
  } catch (error) {
    log.warn('Error parsing composer.json', { error });
  }
  
  return dependencies;
}

/**
 * Parse dependencies from go.mod (Go)
 */
function parseGoDependencies(fileContent: string): Map<string, string> {
  const dependencies = new Map<string, string>();
  const lines = fileContent.split('\n');
  let inRequireBlock = false;
  
  for (const line of lines) {
    const trimmedLine = line.trim();
    
    if (trimmedLine === 'require (') {
      inRequireBlock = true;
      continue;
    } else if (trimmedLine === ')') {
      inRequireBlock = false;
      continue;
    } else if (trimmedLine.startsWith('require ')) {
      // Single-line require
      const match = trimmedLine.match(/require\s+([^\s]+)\s+([^\s]+)/);
      if (match) {
        dependencies.set(match[1], match[2]);
      }
      continue;
    }
    
    if (inRequireBlock && trimmedLine !== '') {
      const match = trimmedLine.match(/([^\s]+)\s+([^\s]+)/);
      if (match) {
        dependencies.set(match[1], match[2]);
      }
    }
  }
  
  return dependencies;
}

/**
 * Scan a specific manifest file for dependency issues
 */
async function scanManifest(
  manifest: ManifestInfo,
  config: DependencyScannerConfig
): Promise<DependencyIssue[]> {
  const issues: DependencyIssue[] = [];
  const { path: manifestPath, ecosystem, dependencies } = manifest;
  
  log.info(`Scanning ${ecosystem} dependencies in ${manifestPath}`);
  
  // Skip ignored dependencies
  let filteredDependencies = dependencies;
  if (config.ignoreDependencies && config.ignoreDependencies.length > 0) {
    filteredDependencies = new Map(
      [...dependencies].filter(([name]) => !config.ignoreDependencies!.includes(name))
    );
  }
  
  // Check for latest versions and vulnerabilities
  for (const [name, currentVersion] of filteredDependencies.entries()) {
    try {
      // Skip dependencies matching ignore patterns
      if (config.ignorePatterns && config.ignorePatterns.some(pattern => 
        new RegExp(pattern).test(name)
      )) {
        continue;
      }
      
      const latestVersion = await getLatestVersion(name, ecosystem, config);
      
      if (!latestVersion) {
        continue; // Skip if we couldn't determine latest version
      }
      
      const isOutdated = compareVersions(currentVersion, latestVersion) < 0;
      
      if (isOutdated) {
        // Fetch vulnerability information if enabled
        let vulnerabilities: VulnerabilityInfo[] = [];
        
        if (config.checkVulnerabilities) {
          vulnerabilities = await getVulnerabilities(
            name, 
            currentVersion, 
            ecosystem, 
            config
          );
        }
        
        // Filter vulnerabilities by severity if needed
        if (config.severityThreshold !== 'low') {
          const severityLevels = { 'low': 0, 'medium': 1, 'high': 2, 'critical': 3 };
          const threshold = severityLevels[config.severityThreshold];
          
          vulnerabilities = vulnerabilities.filter(vuln => {
            return severityLevels[vuln.severity] >= threshold;
          });
        }
        
        // Create dependency issue
        const issue: DependencyIssue = {
          name,
          currentVersion,
          latestVersion,
          isOutdated,
          isDirect: true, // We're only scanning direct dependencies for now
          ecosystem,
          definitionFile: manifestPath,
          vulnerabilities,
          isDeprecated: await isDeprecated(name, ecosystem),
          detectedAt: new Date(),
          suggestedFix: generateUpgradeCommand(name, latestVersion, ecosystem, manifestPath)
        };
        
        // Add deprecation message if applicable
        if (issue.isDeprecated) {
          issue.deprecationMessage = await getDeprecationMessage(name, ecosystem);
        }
        
        issues.push(issue);
      }
    } catch (depError) {
      log.warn(`Error checking dependency ${name}@${currentVersion}`, { error: depError });
    }
  }
  
  return issues;
}

/**
 * Get latest version for a package
 */
async function getLatestVersion(
  packageName: string,
  ecosystem: string,
  config: DependencyScannerConfig
): Promise<string | null> {
  try {
    switch (ecosystem) {
      case 'npm':
        return getLatestNpmVersion(packageName, config);
      case 'pip':
        return getLatestPipVersion(packageName, config);
      case 'maven':
        return getLatestMavenVersion(packageName, config);
      // Add other ecosystems as needed
      default:
        log.warn(`No version checker implemented for ecosystem: ${ecosystem}`);
        return null;
    }
  } catch (error) {
    log.warn(`Error getting latest version for ${packageName}`, { error });
    return null;
  }
}

/**
 * Get latest npm package version
 */
async function getLatestNpmVersion(
  packageName: string,
  config: DependencyScannerConfig
): Promise<string | null> {
  try {
    const { stdout } = await execAsync(`npm view ${packageName} version`, {
      timeout: config.apiTimeoutMs
    });
    return stdout.trim();
  } catch (error) {
    log.warn(`Error getting latest npm version for ${packageName}`, { error });
    return null;
  }
}

/**
 * Get latest Python package version
 */
async function getLatestPipVersion(
  packageName: string,
  config: DependencyScannerConfig
): Promise<string | null> {
  try {
    const { stdout } = await execAsync(`pip index versions ${packageName} --pre=false`, {
      timeout: config.apiTimeoutMs
    });
    
    // Parse the output to get the latest version
    const versionMatch = stdout.match(/Available versions: ([^\s,]+)/);
    if (versionMatch && versionMatch[1]) {
      return versionMatch[1];
    }
    return null;
  } catch (error) {
    log.warn(`Error getting latest pip version for ${packageName}`, { error });
    return null;
  }
}

/**
 * Get latest Maven package version
 */
async function getLatestMavenVersion(
  packageName: string,
  config: DependencyScannerConfig
): Promise<string | null> {
  // Maven packages use groupId:artifactId format
  const [groupId, artifactId] = packageName.split(':');
  
  if (!groupId || !artifactId) {
    log.warn(`Invalid Maven package name: ${packageName}`);
    return null;
  }
  
  try {
    // Use Maven's metadata to get the latest version
    // In a real implementation, this would parse the Maven Central XML response
    // For simplicity, we're returning null here
    return null;
  } catch (error) {
    log.warn(`Error getting latest Maven version for ${packageName}`, { error });
    return null;
  }
}

/**
 * Check if a package is deprecated
 */
async function isDeprecated(
  packageName: string,
  ecosystem: string
): Promise<boolean> {
  try {
    switch (ecosystem) {
      case 'npm':
        return isNpmDeprecated(packageName);
      // Add other ecosystems as needed
      default:
        return false;
    }
  } catch (error) {
    log.warn(`Error checking deprecation status for ${packageName}`, { error });
    return false;
  }
}

/**
 * Check if an npm package is deprecated
 */
async function isNpmDeprecated(packageName: string): Promise<boolean> {
  try {
    const { stdout } = await execAsync(`npm view ${packageName} deprecated`);
    return stdout.trim() !== 'undefined';
  } catch (error) {
    return false;
  }
}

/**
 * Get deprecation message for a package
 */
async function getDeprecationMessage(
  packageName: string,
  ecosystem: string
): Promise<string | undefined> {
  try {
    switch (ecosystem) {
      case 'npm':
        return getNpmDeprecationMessage(packageName);
      // Add other ecosystems as needed
      default:
        return undefined;
    }
  } catch (error) {
    log.warn(`Error getting deprecation message for ${packageName}`, { error });
    return undefined;
  }
}

/**
 * Get deprecation message for an npm package
 */
async function getNpmDeprecationMessage(packageName: string): Promise<string | undefined> {
  try {
    const { stdout } = await execAsync(`npm view ${packageName} deprecated`);
    const message = stdout.trim();
    return message !== 'undefined' ? message : undefined;
  } catch (error) {
    return undefined;
  }
}

/**
 * Get vulnerabilities for a package
 */
async function getVulnerabilities(
  packageName: string,
  version: string,
  ecosystem: string,
  config: DependencyScannerConfig
): Promise<VulnerabilityInfo[]> {
  try {
    // In a real implementation, this would query security advisories
    // from multiple sources based on config.securityAdvisorySources
    
    // For simplicity, we'll return an empty array
    return [];
  } catch (error) {
    log.warn(`Error getting vulnerabilities for ${packageName}@${version}`, { error });
    return [];
  }
}

/**
 * Generate upgrade command for a dependency
 */
function generateUpgradeCommand(
  packageName: string,
  targetVersion: string,
  ecosystem: string,
  manifestPath: string
): string | undefined {
  switch (ecosystem) {
    case 'npm':
      return `npm install ${packageName}@${targetVersion}`;
    case 'pip':
      return `pip install ${packageName}==${targetVersion}`;
    case 'composer':
      return `composer require ${packageName}:${targetVersion}`;
    // Add other ecosystems as needed
    default:
      return undefined;
  }
}
