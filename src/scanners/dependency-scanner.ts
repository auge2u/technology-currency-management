import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { glob } from 'glob';
import * as semver from 'semver';
import * as child_process from 'child_process';
import { log } from '../utils/logging';
import { DependencyIssue } from '../types/scanning';

const readFileAsync = promisify(fs.readFile);
const execAsync = promisify(child_process.exec);

/**
 * Configuration for dependency scanning
 */
export interface DependencyScannerConfig {
  // Root directory to scan
  rootDir: string;
  
  // Package manager specific configs
  npm?: {
    // Whether to scan npm dependencies
    enabled: boolean;
    // Whether to include dev dependencies
    includeDevDependencies: boolean;
    // Registry URL (defaults to npm registry)
    registryUrl?: string;
    // Auth token for private registries
    authToken?: string;
    // Custom npm vulnerabilities database path
    customVulnDbPath?: string;
  };
  
  python?: {
    // Whether to scan Python dependencies
    enabled: boolean;
    // Custom vulnerability database for Python packages
    customVulnDbPath?: string;
  };
  
  java?: {
    // Whether to scan Maven/Gradle dependencies
    enabled: boolean;
    // Custom vulnerability database for Java packages
    customVulnDbPath?: string;
  };
  
  nuget?: {
    // Whether to scan .NET dependencies
    enabled: boolean;
    // Custom vulnerability database for .NET packages
    customVulnDbPath?: string;
  };
  
  // Optional specific packages to focus on or ignore
  includePackages?: string[];
  excludePackages?: string[];
  
  // Maximum depth for transitive dependency scanning
  maxTransitiveDepth?: number;
  
  // Maximum file size to scan
  maxFileSizeBytes?: number;
  
  // Cache settings
  cacheResults?: boolean;
  cacheTtlMinutes?: number;
  cacheDir?: string;
  
  // Offline mode (won't fetch latest versions from registries)
  offlineMode?: boolean;
  
  // Whether to use local security advisories only
  localSecurityCheckOnly?: boolean;
  
  // Custom severity overrides for specific packages or versions
  severityOverrides?: Array<{
    packageName: string;
    versionRange?: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
  }>;
}

/**
 * Dependency package with vulnerability information
 */
interface DependencyPackage {
  name: string;
  version: string;
  isDev: boolean;
  source: 'npm' | 'pip' | 'maven' | 'gradle' | 'nuget';
  filePath: string;
  latestVersion?: string;
  vulnerabilities: Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    cveIds?: string[];
    fixedInVersion?: string;
    url?: string;
  }>;
  isDirect: boolean;
  dependencies?: DependencyPackage[];
  dependencyDepth: number;
}

/**
 * Utility functions for semver operations with safety fallbacks
 */
const versionUtils = {
  isGreaterThan: (v1: string, v2: string): boolean => {
    try {
      const sv1 = semver.coerce(v1);
      const sv2 = semver.coerce(v2);
      
      if (sv1 && sv2) {
        return semver.gt(sv1, sv2);
      }
      
      // Simple fallback for non-semver strings
      const parts1 = v1.split('.').map(p => parseInt(p, 10) || 0);
      const parts2 = v2.split('.').map(p => parseInt(p, 10) || 0);
      
      for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
        const p1 = i < parts1.length ? parts1[i] : 0;
        const p2 = i < parts2.length ? parts2[i] : 0;
        
        if (p1 > p2) return true;
        if (p1 < p2) return false;
      }
      
      return false;
    } catch {
      // If all else fails, string comparison
      return v1 > v2;
    }
  },
  
  satisfies: (version: string, range: string): boolean => {
    try {
      const sv = semver.coerce(version);
      return sv ? semver.satisfies(sv, range) : false;
    } catch {
      // If semver fails, try simple string matching
      if (range.startsWith('<')) {
        const targetVersion = range.substring(1);
        return !versionUtils.isGreaterThan(version, targetVersion) && version !== targetVersion;
      }
      if (range.startsWith('<=')) {
        const targetVersion = range.substring(2);
        return !versionUtils.isGreaterThan(version, targetVersion);
      }
      if (range.startsWith('>')) {
        const targetVersion = range.substring(1);
        return versionUtils.isGreaterThan(version, targetVersion);
      }
      if (range.startsWith('>=')) {
        const targetVersion = range.substring(2);
        return versionUtils.isGreaterThan(version, targetVersion) || version === targetVersion;
      }
      if (range.includes(' - ')) {
        const [min, max] = range.split(' - ');
        const gtMin = versionUtils.isGreaterThan(version, min) || version === min;
        const ltMax = !versionUtils.isGreaterThan(version, max);
        return gtMin && ltMax;
      }
      
      // Exact match
      return version === range;
    }
  }
};

/**
 * Scanner for detecting outdated and vulnerable dependencies
 */
export async function scanDependencies(
  config: DependencyScannerConfig
): Promise<DependencyIssue[]> {
  try {
    log.info('Starting dependency scanner');
    const issues: DependencyIssue[] = [];
    
    // Detect package manifests
    const packageManifests = await detectPackageManifests(config);
    log.info(`Found ${packageManifests.length} package manifests`);
    
    // Parse all dependencies
    const allDependencies: DependencyPackage[] = [];
    
    for (const manifest of packageManifests) {
      try {
        const deps = await parseDependencies(manifest, config);
        allDependencies.push(...deps);
        log.info(`Parsed ${deps.length} dependencies from ${manifest.filePath}`);
      } catch (manifestError) {
        log.error(`Error parsing manifest ${manifest.filePath}`, { error: manifestError });
      }
    }
    
    log.info(`Found a total of ${allDependencies.length} dependencies`);
    
    // Check for latest versions and vulnerabilities
    const enrichedDependencies = await enrichDependencyInfo(allDependencies, config);
    
    // Convert to issues
    for (const dep of enrichedDependencies) {
      const isOutdated = dep.latestVersion && 
                          versionUtils.isGreaterThan(dep.latestVersion, dep.version);
      
      if (isOutdated || dep.vulnerabilities.length > 0) {
        // Calculate risk level
        const riskLevel = calculateRiskLevel(dep);
        
        // Create issue
        const issue: DependencyIssue = {
          detectedAt: new Date(),
          packageName: dep.name,
          currentVersion: dep.version,
          latestVersion: dep.latestVersion,
          packageManager: dep.source,
          isDirect: dep.isDirect,
          isOutdated: !!isOutdated,
          isVulnerable: dep.vulnerabilities.length > 0,
          vulnerabilities: dep.vulnerabilities,
          riskLevel,
          tags: generateTags(dep),
          recommendation: generateRecommendation(dep),
          dependentFiles: [dep.filePath],
          updateImpact: assessUpdateImpact(dep, isOutdated)
        };
        
        issues.push(issue);
        log.info(`Added issue for dependency ${dep.name}@${dep.version}`);
      }
    }
    
    log.info(`Completed dependency scanning. Found ${issues.length} total issues`);
    return issues;
  } catch (error) {
    log.error('Error during dependency scanning', { error });
    return [];
  }
}

/**
 * Interface representing a detected package manifest
 */
interface PackageManifest {
  type: 'npm' | 'pip' | 'maven' | 'gradle' | 'nuget';
  filePath: string;
}

/**
 * Detect package manifests in the specified directory
 */
async function detectPackageManifests(
  config: DependencyScannerConfig
): Promise<PackageManifest[]> {
  const manifests: PackageManifest[] = [];
  const patterns = [];
  
  // Configure patterns based on enabled package managers
  if (config.npm?.enabled !== false) {
    patterns.push('**/package.json');
  }
  
  if (config.python?.enabled) {
    patterns.push('**/requirements.txt', '**/pyproject.toml', '**/setup.py', '**/Pipfile');
  }
  
  if (config.java?.enabled) {
    patterns.push('**/pom.xml', '**/build.gradle', '**/build.gradle.kts');
  }
  
  if (config.nuget?.enabled) {
    patterns.push('**/*.csproj', '**/packages.config');
  }
  
  // Find all matching files
  for (const pattern of patterns) {
    try {
      const files = await glob(pattern, {
        cwd: config.rootDir,
        absolute: true,
        ignore: ['**/node_modules/**', '**/.git/**', '**/venv/**']
      });
      
      for (const file of files) {
        try {
          // Check file size if max size is specified
          if (config.maxFileSizeBytes) {
            const stats = await fs.promises.stat(file);
            if (stats.size > config.maxFileSizeBytes) {
              log.info(`Skipping file exceeding size limit: ${file} (${stats.size} bytes)`);
              continue;
            }
          }
          
          // Determine manifest type
          let type: 'npm' | 'pip' | 'maven' | 'gradle' | 'nuget';
          
          if (file.endsWith('package.json')) {
            type = 'npm';
          } else if (file.endsWith('requirements.txt') || file.endsWith('setup.py') ||
                     file.endsWith('pyproject.toml') || file.endsWith('Pipfile')) {
            type = 'pip';
          } else if (file.endsWith('pom.xml')) {
            type = 'maven';
          } else if (file.endsWith('build.gradle') || file.endsWith('build.gradle.kts')) {
            type = 'gradle';
          } else if (file.endsWith('.csproj') || file.endsWith('packages.config')) {
            type = 'nuget';
          } else {
            continue; // Unrecognized file type
          }
          
          manifests.push({
            type,
            filePath: file
          });
          
          log.info(`Found ${type} manifest at ${file}`);
        } catch (fileError) {
          log.warn(`Error processing file ${file}`, { error: fileError });
        }
      }
    } catch (globError) {
      log.warn(`Error searching for pattern ${pattern}`, { error: globError });
    }
  }
  
  return manifests;
}

/**
 * Parse dependencies from a package manifest
 */
async function parseDependencies(
  manifest: PackageManifest,
  config: DependencyScannerConfig
): Promise<DependencyPackage[]> {
  const dependencies: DependencyPackage[] = [];
  
  try {
    const content = await readFileAsync(manifest.filePath, 'utf8');
    
    switch (manifest.type) {
      case 'npm':
        return parseNpmDependencies(content, manifest.filePath, config);
      case 'pip':
        return parsePipDependencies(content, manifest.filePath, config);
      case 'maven':
        return parseMavenDependencies(content, manifest.filePath, config);
      case 'gradle':
        return parseGradleDependencies(content, manifest.filePath, config);
      case 'nuget':
        return parseNugetDependencies(content, manifest.filePath, config);
      default:
        return [];
    }
  } catch (error) {
    log.error(`Error parsing dependencies from ${manifest.filePath}`, { error });
    return [];
  }
}

/**
 * Parse NPM dependencies from package.json
 */
async function parseNpmDependencies(
  content: string,
  filePath: string,
  config: DependencyScannerConfig
): Promise<DependencyPackage[]> {
  const dependencies: DependencyPackage[] = [];
  
  try {
    const packageJson = JSON.parse(content);
    
    // Parse regular dependencies
    if (packageJson.dependencies) {
      for (const [name, versionRange] of Object.entries(packageJson.dependencies)) {
        // Skip if package should be excluded
        if (config.excludePackages?.includes(name)) {
          continue;
        }
        
        // Include only specific packages if configured
        if (config.includePackages && !config.includePackages.includes(name)) {
          continue;
        }
        
        // Extract version from semver range
        const version = extractVersionFromRange(versionRange as string);
        
        dependencies.push({
          name,
          version,
          isDev: false,
          source: 'npm',
          filePath,
          vulnerabilities: [],
          isDirect: true,
          dependencyDepth: 0
        });
      }
    }
    
    // Parse dev dependencies if configured
    if (config.npm?.includeDevDependencies && packageJson.devDependencies) {
      for (const [name, versionRange] of Object.entries(packageJson.devDependencies)) {
        // Skip if package should be excluded
        if (config.excludePackages?.includes(name)) {
          continue;
        }
        
        // Include only specific packages if configured
        if (config.includePackages && !config.includePackages.includes(name)) {
          continue;
        }
        
        // Extract version from semver range
        const version = extractVersionFromRange(versionRange as string);
        
        dependencies.push({
          name,
          version,
          isDev: true,
          source: 'npm',
          filePath,
          vulnerabilities: [],
          isDirect: true,
          dependencyDepth: 0
        });
      }
    }
    
    return dependencies;
  } catch (error) {
    log.error(`Error parsing NPM dependencies from ${filePath}`, { error });
    return [];
  }
}

/**
 * Extract a specific version from a semver range
 */
function extractVersionFromRange(range: string): string {
  // Handle npm version ranges like ^1.2.3, ~1.2.3, etc.
  if (typeof range !== 'string') {
    return 'unknown';
  }
  
  // Remove any leading comparison operators
  const cleanRange = range.replace(/^[\^~>=<]+/, '');
  
  // Handle version ranges like 1.2.3 - 2.3.4
  if (cleanRange.includes(' - ')) {
    return cleanRange.split(' - ')[0].trim();
  }
  
  // Handle || expressions by taking the first part
  if (cleanRange.includes('||')) {
    return cleanRange.split('||')[0].trim();
  }
  
  // Handle git URLs, etc.
  if (cleanRange.includes('#')) {
    const parts = cleanRange.split('#');
    return parts[parts.length - 1];
  }
  
  // If we get this far, assume this is a simple version
  return cleanRange;
}

/**
 * Parse Python dependencies from various files
 */
async function parsePipDependencies(
  content: string,
  filePath: string,
  config: DependencyScannerConfig
): Promise<DependencyPackage[]> {
  const dependencies: DependencyPackage[] = [];
  
  try {
    // Simple parsing for requirements.txt
    if (filePath.endsWith('requirements.txt')) {
      const lines = content.split('\n');
      
      for (const line of lines) {
        // Skip comments and empty lines
        if (line.trim().startsWith('#') || !line.trim()) {
          continue;
        }
        
        // Handle common formats: package==1.2.3, package>=1.2.3, etc.
        const matches = line.match(/^([a-zA-Z0-9_\-\.]+)(?:[=<>~!]{1,2})([\d\.]+)/);
        if (matches && matches.length >= 3) {
          const name = matches[1];
          const version = matches[2];
          
          // Skip if package should be excluded
          if (config.excludePackages?.includes(name)) {
            continue;
          }
          
          // Include only specific packages if configured
          if (config.includePackages && !config.includePackages.includes(name)) {
            continue;
          }
          
          dependencies.push({
            name,
            version,
            isDev: false, // Assuming all requirements.txt dependencies are prod
            source: 'pip',
            filePath,
            vulnerabilities: [],
            isDirect: true,
            dependencyDepth: 0
          });
        }
      }
    }
    
    // For other Python files (setup.py, etc.), we'd need more complex parsing...
    // This is a simplified implementation
    
    return dependencies;
  } catch (error) {
    log.error(`Error parsing Python dependencies from ${filePath}`, { error });
    return [];
  }
}

/**
 * Parse Maven dependencies from pom.xml
 */
async function parseMavenDependencies(
  content: string,
  filePath: string,
  config: DependencyScannerConfig
): Promise<DependencyPackage[]> {
  const dependencies: DependencyPackage[] = [];
  
  try {
    // Basic regex-based parsing for Maven dependencies
    // In a real implementation, use a proper XML parser
    const dependencyRegex = /<dependency>[\s\S]*?<groupId>([^<]+)<\/groupId>[\s\S]*?<artifactId>([^<]+)<\/artifactId>[\s\S]*?<version>([^<]+)<\/version>[\s\S]*?<\/dependency>/g;
    let match;
    
    while ((match = dependencyRegex.exec(content)) !== null) {
      const groupId = match[1].trim();
      const artifactId = match[2].trim();
      const version = match[3].trim();
      const name = `${groupId}:${artifactId}`;
      
      // Skip if package should be excluded
      if (config.excludePackages?.includes(name)) {
        continue;
      }
      
      // Include only specific packages if configured
      if (config.includePackages && !config.includePackages.includes(name)) {
        continue;
      }
      
      // Check for scope to determine if it's a dev dependency
      const scopeMatch = /<scope>([^<]+)<\/scope>/g.exec(match[0]);
      const scope = scopeMatch ? scopeMatch[1].trim() : 'compile';
      const isDev = scope === 'test' || scope === 'provided';
      
      dependencies.push({
        name,
        version,
        isDev,
        source: 'maven',
        filePath,
        vulnerabilities: [],
        isDirect: true,
        dependencyDepth: 0
      });
    }
    
    return dependencies;
  } catch (error) {
    log.error(`Error parsing Maven dependencies from ${filePath}`, { error });
    return [];
  }
}

/**
 * Parse Gradle dependencies from build.gradle
 */
async function parseGradleDependencies(
  content: string,
  filePath: string,
  config: DependencyScannerConfig
): Promise<DependencyPackage[]> {
  const dependencies: DependencyPackage[] = [];
  
  try {
    // Basic regex-based parsing for Gradle dependencies
    // This is simplified and won't handle all Gradle build files correctly
    const dependencyRegex = /(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testCompileOnly)\s*['"]([^:]+):([^:]+):([^'"]+)['"]|(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testCompileOnly)\s*group:\s*['"]([^'"]+)['"],\s*name:\s*['"]([^'"]+)['"],\s*version:\s*['"]([^'"]+)['"]|(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testCompileOnly)\s*\(['"]([^:]+):([^:]+):([^'"]+)['"]\)/g;
    let match;
    
    while ((match = dependencyRegex.exec(content)) !== null) {
      let groupId, artifactId, version;
      
      if (match[1] && match[2] && match[3]) {
        groupId = match[1];
        artifactId = match[2];
        version = match[3];
      } else if (match[4] && match[5] && match[6]) {
        groupId = match[4];
        artifactId = match[5];
        version = match[6];
      } else if (match[7] && match[8] && match[9]) {
        groupId = match[7];
        artifactId = match[8];
        version = match[9];
      } else {
        continue;
      }
      
      const name = `${groupId}:${artifactId}`;
      
      // Skip if package should be excluded
      if (config.excludePackages?.includes(name)) {
        continue;
      }
      
      // Include only specific packages if configured
      if (config.includePackages && !config.includePackages.includes(name)) {
        continue;
      }
      
      // Check configuration to determine if it's a dev dependency
      const isDev = match[0].includes('test') || match[0].includes('compileOnly');
      
      dependencies.push({
        name,
        version,
        isDev,
        source: 'gradle',
        filePath,
        vulnerabilities: [],
        isDirect: true,
        dependencyDepth: 0
      });
    }
    
    return dependencies;
  } catch (error) {
    log.error(`Error parsing Gradle dependencies from ${filePath}`, { error });
    return [];
  }
}

/**
 * Parse .NET dependencies from project files
 */
async function parseNugetDependencies(
  content: string,
  filePath: string,
  config: DependencyScannerConfig
): Promise<DependencyPackage[]> {
  const dependencies: DependencyPackage[] = [];
  
  try {
    if (filePath.endsWith('.csproj')) {
      // Parse modern .NET project format
      const packageRefRegex = /<PackageReference\s+Include=['"]([^'"]+)['"]\s+Version=['"]([^'"]+)['"]|<PackageReference\s+Include=['"]([^'"]+)['"]>[\s\S]*?<Version>([^<]+)<\/Version>/g;
      let match;
      
      while ((match = packageRefRegex.exec(content)) !== null) {
        const name = match[1] || match[3];
        const version = match[2] || match[4];
        
        // Skip if package should be excluded
        if (config.excludePackages?.includes(name)) {
          continue;
        }
        
        // Include only specific packages if configured
        if (config.includePackages && !config.includePackages.includes(name)) {
          continue;
        }
        
        dependencies.push({
          name,
          version,
          isDev: false, // Can't easily determine this from .csproj files
          source: 'nuget',
          filePath,
          vulnerabilities: [],
          isDirect: true,
          dependencyDepth: 0
        });
      }
    } else if (filePath.endsWith('packages.config')) {
      // Parse legacy packages.config format
      const packageRegex = /<package\s+id=['"]([^'"]+)['"]\s+version=['"]([^'"]+)['"]|<package\s+version=['"]([^'"]+)['"]\s+id=['"]([^'"]+)['"][^>]*>/g;
      let match;
      
      while ((match = packageRegex.exec(content)) !== null) {
        const name = match[1] || match[4];
        const version = match[2] || match[3];
        
        // Skip if package should be excluded
        if (config.excludePackages?.includes(name)) {
          continue;
        }
        
        // Include only specific packages if configured
        if (config.includePackages && !config.includePackages.includes(name)) {
          continue;
        }
        
        dependencies.push({
          name,
          version,
          isDev: false, // Can't determine this from packages.config
          source: 'nuget',
          filePath,
          vulnerabilities: [],
          isDirect: true,
          dependencyDepth: 0
        });
      }
    }
    
    return dependencies;
  } catch (error) {
    log.error(`Error parsing NuGet dependencies from ${filePath}`, { error });
    return [];
  }
}

/**
 * Enrich dependency information with latest versions and vulnerabilities
 */
async function enrichDependencyInfo(
  dependencies: DependencyPackage[],
  config: DependencyScannerConfig
): Promise<DependencyPackage[]> {
  const enrichedDeps = [...dependencies];
  
  // Process each dependency
  for (const dep of enrichedDeps) {
    try {
      // Skip offline mode checks for latest versions
      if (!config.offlineMode) {
        await fetchLatestVersion(dep, config);
      }
      
      // Check for vulnerabilities
      await checkVulnerabilities(dep, config);
      
      log.info(`Enriched dependency info for ${dep.name}@${dep.version}`);
    } catch (error) {
      log.warn(`Error enriching dependency info for ${dep.name}@${dep.version}`, { error });
    }
  }
  
  return enrichedDeps;
}

/**
 * Fetch the latest version for a dependency
 */
async function fetchLatestVersion(
  dependency: DependencyPackage,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    switch (dependency.source) {
      case 'npm':
        await fetchNpmLatestVersion(dependency, config);
        break;
      case 'pip':
        await fetchPipLatestVersion(dependency, config);
        break;
      case 'maven':
      case 'gradle':
        await fetchMavenLatestVersion(dependency, config);
        break;
      case 'nuget':
        await fetchNugetLatestVersion(dependency, config);
        break;
    }
  } catch (error) {
    log.warn(`Error fetching latest version for ${dependency.name}`, { error });
  }
}

/**
 * Fetch the latest version for an NPM package
 */
async function fetchNpmLatestVersion(
  dependency: DependencyPackage,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // For a real implementation, use npm registry API
    // This is a simplified example using npm view command
    const registryUrl = config.npm?.registryUrl || 'https://registry.npmjs.org';
    const npmCommand = `npm view ${dependency.name} version --registry=${registryUrl} --json`;
    
    const { stdout } = await execAsync(npmCommand);
    const latestVersion = JSON.parse(stdout.trim());
    
    dependency.latestVersion = latestVersion;
    log.info(`Fetched latest version for ${dependency.name}: ${latestVersion}`);
  } catch (error) {
    log.warn(`Error fetching latest NPM version for ${dependency.name}`, { error });
  }
}

/**
 * Fetch the latest version for a Python package
 */
async function fetchPipLatestVersion(
  dependency: DependencyPackage,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // For a real implementation, use PyPI API
    // This is a simplified example using pip index command
    const pipCommand = `pip index versions ${dependency.name} --no-python-version-warning`;
    
    const { stdout } = await execAsync(pipCommand);
    const versionMatch = stdout.match(/Available versions:\s+([\d\.]+)/);
    
    if (versionMatch && versionMatch[1]) {
      dependency.latestVersion = versionMatch[1];
      log.info(`Fetched latest version for ${dependency.name}: ${dependency.latestVersion}`);
    }
  } catch (error) {
    log.warn(`Error fetching latest Python version for ${dependency.name}`, { error });
  }
}

/**
 * Fetch the latest version for a Maven/Gradle package
 */
async function fetchMavenLatestVersion(
  dependency: DependencyPackage,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // In a real implementation, use Maven Central API
    // For now, we'll set a mock version
    const [groupId, artifactId] = dependency.name.split(':');
    
    if (!groupId || !artifactId) {
      log.warn(`Invalid Maven dependency format: ${dependency.name}`);
      return;
    }
    
    // Mock implementation - would query Maven Central in a real implementation
    const version = dependency.version;
    const parts = version.split('.');
    if (parts.length >= 3) {
      const major = parseInt(parts[0], 10);
      const minor = parseInt(parts[1], 10);
      const patch = parseInt(parts[2], 10);
      
      // Simulate latest version by incrementing patch
      dependency.latestVersion = `${major}.${minor}.${patch + 1}`;
      log.info(`Mock latest version for ${dependency.name}: ${dependency.latestVersion}`);
    }
  } catch (error) {
    log.warn(`Error fetching latest Maven version for ${dependency.name}`, { error });
  }
}

/**
 * Fetch the latest version for a NuGet package
 */
async function fetchNugetLatestVersion(
  dependency: DependencyPackage,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // In a real implementation, use NuGet API
    // For now, we'll set a mock version
    
    // Mock implementation - would query NuGet API in a real implementation
    const version = dependency.version;
    const parts = version.split('.');
    if (parts.length >= 3) {
      const major = parseInt(parts[0], 10);
      const minor = parseInt(parts[1], 10);
      const patch = parseInt(parts[2], 10);
      
      // Simulate latest version by incrementing patch
      dependency.latestVersion = `${major}.${minor}.${patch + 1}`;
      log.info(`Mock latest version for ${dependency.name}: ${dependency.latestVersion}`);
    }
  } catch (error) {
    log.warn(`Error fetching latest NuGet version for ${dependency.name}`, { error });
  }
}

/**
 * Check for vulnerabilities in a dependency
 */
async function checkVulnerabilities(
  dependency: DependencyPackage,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    switch (dependency.source) {
      case 'npm':
        await checkNpmVulnerabilities(dependency, config);
        break;
      case 'pip':
        await checkPipVulnerabilities(dependency, config);
        break;
      case 'maven':
      case 'gradle':
        await checkMavenVulnerabilities(dependency, config);
        break;
      case 'nuget':
        await checkNugetVulnerabilities(dependency, config);
        break;
    }
    
    // Apply custom severity overrides if configured
    applyCustomSeverityOverrides(dependency, config);
  } catch (error) {
    log.warn(`Error checking vulnerabilities for ${dependency.name}`, { error });
  }
}

/**
 * Check for vulnerabilities in an NPM package
 */
async function checkNpmVulnerabilities(
  dependency: DependencyPackage,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // For a real implementation, use npm audit or an advisory database API
    // Here we're using a simplified approach with mock data
    if (config.npm?.customVulnDbPath && fs.existsSync(config.npm.customVulnDbPath)) {
      // Read from custom database
      const customDb = JSON.parse(await readFileAsync(config.npm.customVulnDbPath, 'utf8'));
      const vulns = customDb[dependency.name] || [];
      
      for (const vuln of vulns) {
        if (versionUtils.satisfies(dependency.version, vuln.versionRange)) {
          dependency.vulnerabilities.push({
            severity: vuln.severity,
            description: vuln.description,
            cveIds: vuln.cveIds,
            fixedInVersion: vuln.fixedInVersion,
            url: vuln.url
          });
        }
      }
    } else if (!config.localSecurityCheckOnly) {
      // In a real implementation, use npm audit
      // For example:
      // const { stdout } = await execAsync(`npm audit --json ${dependency.name}@${dependency.version}`);
      // const auditResults = JSON.parse(stdout);
      // ... process audit results ...
      
      // Using mock data for this example
      if (dependency.name === 'lodash' && dependency.version.startsWith('4.17.') && parseInt(dependency.version.split('.')[2], 10) < 21) {
        dependency.vulnerabilities.push({
          severity: 'high',
          description: 'Prototype pollution vulnerability in lodash before 4.17.21',
          cveIds: ['CVE-2021-23337'],
          fixedInVersion: '4.17.21',
          url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337'
        });
      }
    }
    
    log.info(`Checked vulnerabilities for ${dependency.name}@${dependency.version}, found ${dependency.vulnerabilities.length}`);
  } catch (error) {
    log.warn(`Error checking NPM vulnerabilities for ${dependency.name}`, { error });
  }
}

/**
 * Check for vulnerabilities in a Python package
 */
async function checkPipVulnerabilities(
  dependency: DependencyPackage,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // For a real implementation, use safety or PyUp database
    // Here we're using a simplified approach with mock data
    
    // Using mock data for this example
    if (dependency.name === 'django' && dependency.version.startsWith('2.2.') && parseInt(dependency.version.split('.')[2], 10) < 20) {
      dependency.vulnerabilities.push({
        severity: 'high',
        description: 'Potential SQL injection via QuerySet.order_by() in Django before 2.2.20',
        cveIds: ['CVE-2021-28658'],
        fixedInVersion: '2.2.20',
        url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-28658'
      });
    }
    
    log.info(`Checked vulnerabilities for ${dependency.name}@${dependency.version}, found ${dependency.vulnerabilities.length}`);
  } catch (error) {
    log.warn(`Error checking Python vulnerabilities for ${dependency.name}`, { error });
  }
}

/**
 * Check for vulnerabilities in a Maven/Gradle package
 */
async function checkMavenVulnerabilities(
  dependency: DependencyPackage,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // For a real implementation, use OWASP dependency check or a vulnerability database
    // Here we're using a simplified approach with mock data
    
    // Using mock data for this example
    if (dependency.name.includes('spring-core') && dependency.version.startsWith('5.3.') && parseInt(dependency.version.split('.')[2], 10) < 18) {
      dependency.vulnerabilities.push({
        severity: 'high',
        description: 'RCE in Spring Framework',
        cveIds: ['CVE-2022-22965'],
        fixedInVersion: '5.3.18',
        url: 'https://nvd.nist.gov/vuln/detail/CVE-2022-22965'
      });
    }
    
    log.info(`Checked vulnerabilities for ${dependency.name}@${dependency.version}, found ${dependency.vulnerabilities.length}`);
  } catch (error) {
    log.warn(`Error checking Maven vulnerabilities for ${dependency.name}`, { error });
  }
}

/**
 * Check for vulnerabilities in a NuGet package
 */
async function checkNugetVulnerabilities(
  dependency: DependencyPackage,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // For a real implementation, use NuGet security advisories
    // Here we're using a simplified approach with mock data
    
    // Using mock data for this example
    if (dependency.name === 'Newtonsoft.Json' && dependency.version.startsWith('12.0.') && parseInt(dependency.version.split('.')[2], 10) < 3) {
      dependency.vulnerabilities.push({
        severity: 'medium',
        description: 'Denial of Service in Newtonsoft.Json before 12.0.3',
        cveIds: ['CVE-2020-10204'],
        fixedInVersion: '12.0.3',
        url: 'https://nvd.nist.gov/vuln/detail/CVE-2020-10204'
      });
    }
    
    log.info(`Checked vulnerabilities for ${dependency.name}@${dependency.version}, found ${dependency.vulnerabilities.length}`);
  } catch (error) {
    log.warn(`Error checking NuGet vulnerabilities for ${dependency.name}`, { error });
  }
}

/**
 * Apply custom severity overrides from configuration
 */
function applyCustomSeverityOverrides(
  dependency: DependencyPackage,
  config: DependencyScannerConfig
): void {
  // Skip if no overrides configured
  if (!config.severityOverrides || config.severityOverrides.length === 0) {
    return;
  }
  
  // Find matching override for this package
  const matchingOverrides = config.severityOverrides.filter(override => {
    if (override.packageName !== dependency.name) {
      return false;
    }
    
    if (!override.versionRange) {
      return true; // Applies to all versions
    }
    
    return versionUtils.satisfies(dependency.version, override.versionRange);
  });
  
  if (matchingOverrides.length > 0) {
    // Apply the first matching override to all vulnerabilities
    const override = matchingOverrides[0];
    
    for (const vuln of dependency.vulnerabilities) {
      vuln.severity = override.severity;
      log.info(`Applied custom severity override for ${dependency.name}@${dependency.version}: ${override.severity}`);
    }
  }
}

/**
 * Calculate risk level for a dependency issue
 */
function calculateRiskLevel(
  dependency: DependencyPackage
): 'low' | 'medium' | 'high' | 'critical' {
  // Start with a base risk level
  let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
  
  // Check for vulnerabilities first
  if (dependency.vulnerabilities.length > 0) {
    // Find the highest severity vulnerability
    for (const vuln of dependency.vulnerabilities) {
      switch (vuln.severity) {
        case 'critical':
          return 'critical'; // Immediately return critical for any critical vulnerability
        case 'high':
          riskLevel = 'high';
          break;
        case 'medium':
          if (riskLevel !== 'high') riskLevel = 'medium';
          break;
        case 'low':
          if (riskLevel === 'low') riskLevel = 'low';
          break;
      }
    }
  } else if (dependency.latestVersion && 
             versionUtils.isGreaterThan(dependency.latestVersion, dependency.version)) {
    // For outdated dependencies without vulnerabilities, check how outdated they are
    // This is a simple heuristic and would be more nuanced in a real implementation
    const versionParts = dependency.version.split('.');
    const latestParts = dependency.latestVersion.split('.');
    
    if (versionParts[0] !== latestParts[0]) {
      // Major version difference
      riskLevel = 'medium';
    } else if (versionParts[1] !== latestParts[1]) {
      // Minor version difference
      riskLevel = 'low';
    }
  }
  
  // Adjust risk for direct vs transitive dependencies
  if (riskLevel !== 'critical' && !dependency.isDirect) {
    // Slightly downgrade risk for transitive dependencies
    if (riskLevel === 'high') riskLevel = 'medium';
    else if (riskLevel === 'medium') riskLevel = 'low';
  }
  
  // Adjust risk based on dependency type (dev vs prod)
  if (riskLevel !== 'critical' && dependency.isDev) {
    // Slightly downgrade risk for dev dependencies
    if (riskLevel === 'high') riskLevel = 'medium';
    else if (riskLevel === 'medium') riskLevel = 'low';
  }
  
  return riskLevel;
}

/**
 * Generate tags for a dependency issue
 */
function generateTags(dependency: DependencyPackage): string[] {
  const tags = [dependency.source];
  
  if (dependency.isDev) {
    tags.push('dev-dependency');
  } else {
    tags.push('prod-dependency');
  }
  
  if (dependency.isDirect) {
    tags.push('direct');
  } else {
    tags.push('transitive');
  }
  
  if (dependency.latestVersion && 
      versionUtils.isGreaterThan(dependency.latestVersion, dependency.version)) {
    tags.push('outdated');
    
    // Check if it's a major, minor, or patch version difference
    const versionParts = dependency.version.split('.');
    const latestParts = dependency.latestVersion.split('.');
    
    if (versionParts[0] !== latestParts[0]) {
      tags.push('major-update');
    } else if (versionParts[1] !== latestParts[1]) {
      tags.push('minor-update');
    } else {
      tags.push('patch-update');
    }
  }
  
  if (dependency.vulnerabilities.length > 0) {
    tags.push('vulnerable');
    
    // Add tags for vulnerability severity
    const severities = new Set(dependency.vulnerabilities.map(v => v.severity));
    severities.forEach(severity => tags.push(`${severity}-severity`));
    
    // Add CVE tags
    const cveIds = dependency.vulnerabilities
      .filter(v => v.cveIds && v.cveIds.length > 0)
      .flatMap(v => v.cveIds);
    
    if (cveIds.length > 0) {
      // Add up to 3 CVE tags to avoid tag explosion
      const uniqueCves = [...new Set(cveIds)].slice(0, 3);
      tags.push(...uniqueCves.map(cve => cve.toLowerCase().replace(/-/g, '')));
    }
  }
  
  return tags;
}

/**
 * Generate recommendation for a dependency issue
 */
function generateRecommendation(dependency: DependencyPackage): string {
  const recommendations: string[] = [];
  
  // Handle vulnerabilities first
  if (dependency.vulnerabilities.length > 0) {
    // Find the version that fixes all vulnerabilities
    const fixVersions = dependency.vulnerabilities
      .filter(v => v.fixedInVersion)
      .map(v => v.fixedInVersion);
    
    const latestFixVersion = fixVersions.length > 0 ?
      fixVersions.reduce((latest, current) => {
        return versionUtils.isGreaterThan(current, latest) ? current : latest;
      }, fixVersions[0]) :
      dependency.latestVersion;
    
    if (latestFixVersion) {
      recommendations.push(
        `Update ${dependency.name} from ${dependency.version} to ${latestFixVersion} to address ${dependency.vulnerabilities.length} security ${dependency.vulnerabilities.length === 1 ? 'vulnerability' : 'vulnerabilities'}`
      );
    } else {
      recommendations.push(
        `Urgent: Review security vulnerabilities in ${dependency.name} ${dependency.version}`
      );
    }
    
    // List the vulnerabilities
    dependency.vulnerabilities.forEach(vuln => {
      let desc = `- ${vuln.severity.toUpperCase()}: ${vuln.description}`;
      if (vuln.cveIds && vuln.cveIds.length > 0) {
        desc += ` (${vuln.cveIds.join(', ')})`;
      }
      if (vuln.fixedInVersion) {
        desc += ` - Fixed in version ${vuln.fixedInVersion}`;
      }
      recommendations.push(desc);
    });
  }
  // Handle outdated dependencies
  else if (dependency.latestVersion && 
           versionUtils.isGreaterThan(dependency.latestVersion, dependency.version)) {
    // Determine if it's a major, minor, or patch version update
    const versionParts = dependency.version.split('.');
    const latestParts = dependency.latestVersion.split('.');
    
    if (versionParts[0] !== latestParts[0]) {
      recommendations.push(
        `Consider updating ${dependency.name} from ${dependency.version} to ${dependency.latestVersion}. This is a major version upgrade and may include breaking changes.`
      );
    } else if (versionParts[1] !== latestParts[1]) {
      recommendations.push(
        `Update ${dependency.name} from ${dependency.version} to ${dependency.latestVersion} to get new features and improvements.`
      );
    } else {
      recommendations.push(
        `Update ${dependency.name} from ${dependency.version} to ${dependency.latestVersion} for bug fixes and patches.`
      );
    }
  }
  
  // Suggest package manager specific commands
  if (recommendations.length > 0) {
    switch (dependency.source) {
      case 'npm':
        recommendations.push(
          `Use 'npm install ${dependency.name}${dependency.isDev ? ' --save-dev' : ''}' to update this package.`
        );
        break;
      case 'pip':
        recommendations.push(
          `Use 'pip install --upgrade ${dependency.name}' to update this package.`
        );
        break;
      case 'maven':
        recommendations.push(
          `Update the version in your pom.xml file.`
        );
        break;
      case 'gradle':
        recommendations.push(
          `Update the version in your build.gradle file.`
        );
        break;
      case 'nuget':
        recommendations.push(
          `Use 'dotnet add package ${dependency.name}' to update this package.`
        );
        break;
    }
  }
  
  // If no recommendations were generated, provide a default
  if (recommendations.length === 0) {
    recommendations.push(
      `No immediate actions required for ${dependency.name} ${dependency.version}.`
    );
  }
  
  return recommendations.join('\n');
}

/**
 * Assess impact of updating a dependency
 */
function assessUpdateImpact(
  dependency: DependencyPackage,
  isOutdated: boolean
): {
  breakingChanges: boolean;
  affectedComponents?: string[];
  estimatedEffort: 'low' | 'medium' | 'high';
} {
  // Default impact assessment
  const impact = {
    breakingChanges: false,
    estimatedEffort: 'low' as 'low' | 'medium' | 'high'
  };
  
  if (!isOutdated || !dependency.latestVersion) {
    return impact;
  }
  
  // Determine if breaking changes are likely
  const versionParts = dependency.version.split('.');
  const latestParts = dependency.latestVersion.split('.');
  
  // Major version bump typically means breaking changes
  if (versionParts[0] !== latestParts[0]) {
    impact.breakingChanges = true;
    impact.estimatedEffort = 'high';
  } 
  // Multiple minor version jumps may require moderate effort
  else if (versionParts[1] !== latestParts[1]) {
    const minorVersionDiff = parseInt(latestParts[1], 10) - parseInt(versionParts[1], 10);
    
    if (minorVersionDiff > 2) {
      impact.estimatedEffort = 'medium';
    }
  }
  
  // If dependency has vulnerabilities, increase estimated effort
  if (dependency.vulnerabilities.length > 0) {
    // Severity-based effort estimation
    const hasCritical = dependency.vulnerabilities.some(v => v.severity === 'critical');
    const hasHigh = dependency.vulnerabilities.some(v => v.severity === 'high');
    
    if (hasCritical) {
      impact.estimatedEffort = 'high';
    } else if (hasHigh && impact.estimatedEffort !== 'high') {
      impact.estimatedEffort = 'medium';
    }
  }
  
  return impact;
}