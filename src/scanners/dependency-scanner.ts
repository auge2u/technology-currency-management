import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { glob } from 'glob';
import { log } from '../utils/logging';
import { DependencyIssue } from '../types/scanning';
import { compareVersions, formatDate } from '../utils/scanner-utils';

const readFileAsync = promisify(fs.readFile);

/**
 * Configuration for dependency scanning
 */
export interface DependencyScannerConfig {
  // Root directory to scan
  rootDirectory: string;
  
  // Whether to use offline mode (don't make API calls)
  offlineMode: boolean;
  
  // Skip specific dependencies
  ignoreDependencies?: string[];
  
  // API timeout in milliseconds
  apiTimeoutMs: number;
  
  // Directory to store cached data
  cacheDir?: string;
  
  // Only flag major version differences
  majorVersionsOnly?: boolean;
  
  // Custom package manifests to scan
  customManifests?: string[];
  
  // Scan development dependencies
  includeDevDependencies?: boolean;
  
  // Scan peer dependencies
  includePeerDependencies?: boolean;
  
  // Scan optional dependencies
  includeOptionalDependencies?: boolean;
}

/**
 * Package managers supported by the scanner
 */
enum PackageManager {
  NPM = 'npm',
  YARN = 'yarn',
  PNPM = 'pnpm',
  PIP = 'pip',
  PIPENV = 'pipenv',
  POETRY = 'poetry',
  MAVEN = 'maven',
  GRADLE = 'gradle',
  NUGET = 'nuget',
  CARGO = 'cargo',
  COMPOSER = 'composer',
  GO = 'go',
  GEM = 'gem',
  SWIFT = 'swift',
  CUSTOM = 'custom'
}

/**
 * Dependency manifest file with version patterns
 */
interface DependencyManifest {
  packageManager: PackageManager;
  filePattern: string;
  parser: (content: string) => Record<string, string> | null;
  devDependenciesParser?: (content: string) => Record<string, string> | null;
  peerDependenciesParser?: (content: string) => Record<string, string> | null;
  optionalDependenciesParser?: (content: string) => Record<string, string> | null;
}

/**
 * Detected dependency
 */
interface DetectedDependency {
  name: string;
  currentVersion: string;
  packageManager: string;
  type: 'production' | 'development' | 'peer' | 'optional';
  manifest: string;
  detectedAt: Date;
}

/**
 * Dependency information from repository or cache
 */
interface DependencyInfo {
  latestVersion: string;
  latestStableVersion: string;
  isOutdated: boolean;
  isDeprecated: boolean;
  hasSecurityIssues: boolean;
  securityIssues?: Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    fixedInVersion?: string;
    cve?: string;
  }>;
  releaseDate?: Date;
  latestReleaseDate?: Date;
  downloadCount?: number;
  repo?: string;
  license?: string;
  isMaintained?: boolean;
  recommendedVersion?: string;
  alternatives?: string[];
}

/**
 * Scanner for detecting dependencies across package managers
 */
export async function scanDependencies(
  config: DependencyScannerConfig
): Promise<DependencyIssue[]> {
  try {
    log.info('Starting dependency scanner');
    const issues: DependencyIssue[] = [];
    
    // Detect dependencies
    const dependencies = await detectDependencies(config);
    log.info(`Found ${dependencies.length} dependencies`);
    
    // Check each dependency
    for (const dependency of dependencies) {
      try {
        // Skip ignored dependencies
        if (config.ignoreDependencies && config.ignoreDependencies.includes(dependency.name)) {
          log.info(`Skipping ignored dependency: ${dependency.name}`);
          continue;
        }
        
        // Get dependency information
        const dependencyInfo = await getDependencyInfo(
          dependency.name,
          dependency.currentVersion,
          dependency.packageManager,
          config.offlineMode,
          config.apiTimeoutMs,
          config.cacheDir,
          config.majorVersionsOnly || false
        );
        
        // Only create an issue if there's at least one problem
        if (dependencyInfo.isOutdated || dependencyInfo.isDeprecated || dependencyInfo.hasSecurityIssues) {
          
          // Create the issue
          const issue: DependencyIssue = {
            name: dependency.name,
            packageManager: dependency.packageManager,
            currentVersion: dependency.currentVersion,
            latestVersion: dependencyInfo.latestVersion,
            type: dependency.type,
            manifestFile: dependency.manifest,
            detectedAt: dependency.detectedAt,
            isOutdated: dependencyInfo.isOutdated,
            isDeprecated: dependencyInfo.isDeprecated,
            hasSecurityIssues: dependencyInfo.hasSecurityIssues,
            license: dependencyInfo.license,
            repo: dependencyInfo.repo
          };
          
          // Add security issues if any
          if (dependencyInfo.securityIssues?.length) {
            issue.securityIssues = dependencyInfo.securityIssues;
          }
          
          // Calculate business impact
          issue.businessImpact = calculateBusinessImpact(
            dependency,
            dependencyInfo
          );
          
          // Calculate update effort
          issue.updateEffort = calculateUpdateEffort(
            dependency,
            dependencyInfo
          );
          
          // Generate recommendation
          issue.recommendation = generateRecommendation(
            dependency,
            dependencyInfo
          );
          
          // Generate tags
          issue.tags = generateTags(
            dependency,
            dependencyInfo
          );
          
          // Add to issues list
          issues.push(issue);
          log.info(`Added issue for dependency ${dependency.name} ${dependency.currentVersion}`);
        }
      } catch (depError) {
        log.warn(`Error processing dependency: ${dependency.name}`, { error: depError });
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
 * Detect dependencies across various package managers
 */
async function detectDependencies(
  config: DependencyScannerConfig
): Promise<DetectedDependency[]> {
  try {
    const dependencies: DetectedDependency[] = [];
    const rootDir = config.rootDirectory;
    
    // Define dependency manifests to scan
    const manifests = getManifestDefinitions();
    
    // Add custom manifests if provided
    if (config.customManifests) {
      for (const customPattern of config.customManifests) {
        manifests.push({
          packageManager: PackageManager.CUSTOM,
          filePattern: customPattern,
          parser: parseCustomManifest
        });
      }
    }
    
    // Scan each manifest type
    for (const manifest of manifests) {
      try {
        const matches = await glob(path.join(rootDir, manifest.filePattern), {
          ignore: ['**/node_modules/**', '**/.git/**', '**/dist/**', '**/build/**']
        });
        
        for (const match of matches) {
          try {
            const content = await readFileAsync(match, 'utf8');
            
            // Parse production dependencies
            const dependencies = manifest.parser(content);
            if (dependencies) {
              for (const [name, version] of Object.entries(dependencies)) {
                addDependency(
                  name,
                  version,
                  manifest.packageManager.toString(),
                  'production',
                  match,
                  dependencies
                );
              }
            }
            
            // Parse development dependencies if enabled
            if (config.includeDevDependencies && manifest.devDependenciesParser) {
              const devDependencies = manifest.devDependenciesParser(content);
              if (devDependencies) {
                for (const [name, version] of Object.entries(devDependencies)) {
                  addDependency(
                    name,
                    version,
                    manifest.packageManager.toString(),
                    'development',
                    match,
                    devDependencies
                  );
                }
              }
            }
            
            // Parse peer dependencies if enabled
            if (config.includePeerDependencies && manifest.peerDependenciesParser) {
              const peerDependencies = manifest.peerDependenciesParser(content);
              if (peerDependencies) {
                for (const [name, version] of Object.entries(peerDependencies)) {
                  addDependency(
                    name,
                    version,
                    manifest.packageManager.toString(),
                    'peer',
                    match,
                    peerDependencies
                  );
                }
              }
            }
            
            // Parse optional dependencies if enabled
            if (config.includeOptionalDependencies && manifest.optionalDependenciesParser) {
              const optionalDependencies = manifest.optionalDependenciesParser(content);
              if (optionalDependencies) {
                for (const [name, version] of Object.entries(optionalDependencies)) {
                  addDependency(
                    name,
                    version,
                    manifest.packageManager.toString(),
                    'optional',
                    match,
                    optionalDependencies
                  );
                }
              }
            }
            
            log.info(`Parsed dependencies from ${match}`);
          } catch (matchError) {
            log.warn(`Error processing manifest: ${match}`, { error: matchError });
          }
        }
      } catch (manifestError) {
        log.warn(`Error processing manifest type: ${manifest.packageManager}`, { error: manifestError });
      }
    }
    
    return dependencies;
    
    // Helper to add dependency to the list
    function addDependency(
      name: string,
      version: string,
      packageManager: string,
      type: 'production' | 'development' | 'peer' | 'optional',
      manifest: string,
      allDeps: Record<string, string>
    ) {
      // Clean up version string
      const cleanVersion = cleanVersionString(version);
      
      // Only add if it's a valid version
      if (cleanVersion) {
        dependencies.push({
          name,
          currentVersion: cleanVersion,
          packageManager,
          type,
          manifest,
          detectedAt: new Date()
        });
      }
    }
  } catch (error) {
    log.error('Error detecting dependencies', { error });
    return [];
  }
}

/**
 * Get dependency information from repository or cache
 */
async function getDependencyInfo(
  name: string,
  version: string,
  packageManager: string,
  offlineMode: boolean,
  timeoutMs: number,
  cacheDir?: string,
  majorVersionsOnly = false
): Promise<DependencyInfo> {
  // Check cache first
  if (cacheDir) {
    const cacheFile = path.join(cacheDir, `dep-${packageManager}-${name.replace(/[^a-z0-9]/gi, '-').toLowerCase()}.json`);
    
    if (fs.existsSync(cacheFile)) {
      try {
        const cacheContent = await readFileAsync(cacheFile, 'utf8');
        const cachedInfo = JSON.parse(cacheContent) as DependencyInfo;
        log.info(`Loaded ${name} dependency info from cache`);
        return cachedInfo;
      } catch (cacheError) {
        log.warn(`Error reading dependency cache for ${name}`, { error: cacheError });
      }
    }
  }
  
  // If in offline mode and no cache, return placeholder data
  if (offlineMode) {
    log.info(`Offline mode enabled for ${name}, using placeholder data`);
    return {
      latestVersion: version,
      latestStableVersion: version,
      isOutdated: false,
      isDeprecated: false,
      hasSecurityIssues: false
    };
  }
  
  // In a real implementation, we would query package repositories
  // For this example, we'll use mock data
  try {
    log.info(`Querying ${packageManager} repository for dependency: ${name} ${version}`);
    
    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 50 + Math.random() * 200));
    
    // Generate latest version based on current version
    const latestVersion = incrementVersion(version);
    const isOutdated = compareVersions(latestVersion, version) > 0;
    
    // Check if we should only flag major version differences
    let actuallyOutdated = isOutdated;
    if (majorVersionsOnly && isOutdated) {
      const currentMajor = parseInt(version.split('.')[0], 10);
      const latestMajor = parseInt(latestVersion.split('.')[0], 10);
      actuallyOutdated = latestMajor > currentMajor;
    }
    
    // Generate mock data
    const info: DependencyInfo = {
      latestVersion,
      latestStableVersion: latestVersion,
      isOutdated: actuallyOutdated,
      isDeprecated: Math.random() < 0.1, // 10% chance of being deprecated
      hasSecurityIssues: Math.random() < 0.2, // 20% chance of having security issues
      releaseDate: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000),
      latestReleaseDate: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000),
      downloadCount: Math.floor(Math.random() * 1000000),
      license: getRandomLicense(),
      isMaintained: Math.random() > 0.1, // 90% chance of being maintained
      recommendedVersion: latestVersion
    };
    
    // Add security issues if flagged
    if (info.hasSecurityIssues) {
      info.securityIssues = [
        {
          severity: getRandomSeverity(),
          description: `${getRandomVulnerabilityType()} vulnerability in ${name}`,
          fixedInVersion: info.latestVersion,
          cve: `CVE-${new Date().getFullYear()}-${Math.floor(Math.random() * 10000)}`
        }
      ];
    }
    
    // Suggest alternatives if deprecated
    if (info.isDeprecated) {
      info.alternatives = getRandomAlternatives(name, packageManager);
    }
    
    // Save to cache if cacheDir is provided
    if (cacheDir) {
      try {
        if (!fs.existsSync(cacheDir)) {
          fs.mkdirSync(cacheDir, { recursive: true });
        }
        
        const cacheFile = path.join(cacheDir, `dep-${packageManager}-${name.replace(/[^a-z0-9]/gi, '-').toLowerCase()}.json`);
        await fs.promises.writeFile(cacheFile, JSON.stringify(info, null, 2), 'utf8');
        log.info(`Cached ${name} dependency info`);
      } catch (cacheError) {
        log.warn(`Error writing dependency cache for ${name}`, { error: cacheError });
      }
    }
    
    return info;
  } catch (error) {
    log.error(`Error querying repository for ${name}`, { error });
    
    // Return basic info if repository query fails
    return {
      latestVersion: version,
      latestStableVersion: version,
      isOutdated: false,
      isDeprecated: false,
      hasSecurityIssues: false
    };
  }
}

/**
 * Calculate business impact score for a dependency issue
 */
function calculateBusinessImpact(
  dependency: DetectedDependency,
  info: DependencyInfo
): number {
  let score = 1; // Start with minimal impact
  
  // Security issues have high impact
  if (info.hasSecurityIssues) {
    const hasCritical = info.securityIssues?.some(issue => issue.severity === 'critical');
    const hasHigh = info.securityIssues?.some(issue => issue.severity === 'high');
    
    if (hasCritical) score += 3;
    else if (hasHigh) score += 2;
    else score += 1;
  }
  
  // Deprecation has medium impact
  if (info.isDeprecated) score += 1;
  
  // Being outdated has lower impact
  if (info.isOutdated) score += 1;
  
  // Production dependencies have higher impact than dev dependencies
  if (dependency.type === 'production') score += 1;
  
  // Unmaintained packages have higher impact
  if (info.isMaintained === false) score += 1;
  
  // Cap at maximum of 5
  return Math.min(score, 5);
}

/**
 * Calculate update effort for a dependency
 */
function calculateUpdateEffort(
  dependency: DetectedDependency,
  info: DependencyInfo
): number {
  // Start with moderate effort
  let effort = 2;
  
  // Calculate version difference
  if (info.latestVersion) {
    const currentMajor = parseInt(dependency.currentVersion.split('.')[0], 10) || 0;
    const latestMajor = parseInt(info.latestVersion.split('.')[0], 10) || 0;
    
    const majorDiff = latestMajor - currentMajor;
    
    // Major version upgrades are more difficult
    if (majorDiff > 1) effort += 2;
    else if (majorDiff === 1) effort += 1;
  }
  
  // Deprecated packages are harder to update (requires replacement)
  if (info.isDeprecated) effort += 1;
  
  // Popular packages are usually easier to update (better docs, examples)
  if (info.downloadCount && info.downloadCount > 1000000) effort -= 1;
  
  // Different dependency types have different update complexities
  switch (dependency.type) {
    case 'peer':
      // Peer dependencies are tricky to update
      effort += 1;
      break;
    case 'development':
      // Dev dependencies are usually easier
      effort -= 1;
      break;
  }
  
  // Cap at 1-5 range
  return Math.max(1, Math.min(5, effort));
}

/**
 * Generate a recommendation for a dependency issue
 */
function generateRecommendation(
  dependency: DetectedDependency,
  info: DependencyInfo
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
      `Update ${dependency.name} immediately to fix ${highestSeverity} severity security ${info.securityIssues?.length === 1 ? 'issue' : 'issues'}`
    );
  } else if (info.isDeprecated) {
    if (info.alternatives?.length) {
      recommendations.push(
        `Replace deprecated package ${dependency.name} with one of the recommended alternatives: ${info.alternatives.join(', ')}`
      );
    } else {
      recommendations.push(
        `Replace deprecated package ${dependency.name} with a maintained alternative`
      );
    }
  } else if (info.isOutdated) {
    recommendations.push(
      `Update ${dependency.name} from ${dependency.currentVersion} to ${info.latestVersion}`
    );
  }
  
  // Add testing recommendation for major updates
  if (info.latestVersion) {
    const currentMajor = parseInt(dependency.currentVersion.split('.')[0], 10) || 0;
    const latestMajor = parseInt(info.latestVersion.split('.')[0], 10) || 0;
    
    if (latestMajor > currentMajor) {
      recommendations.push(
        `Test thoroughly after updating as this is a major version change (${currentMajor} → ${latestMajor})`
      );
    }
  }
  
  if (recommendations.length === 0) {
    recommendations.push(`No immediate action required for ${dependency.name} ${dependency.currentVersion}`);
  }
  
  return recommendations.join('. ');
}

/**
 * Generate tags for categorizing dependency issues
 */
function generateTags(
  dependency: DetectedDependency,
  info: DependencyInfo
): string[] {
  const tags: string[] = [dependency.packageManager, dependency.type];
  
  if (info.isOutdated) tags.push('outdated');
  if (info.isDeprecated) tags.push('deprecated');
  
  // Add security tags
  if (info.hasSecurityIssues) {
    tags.push('security');
    
    // Add tag for highest severity
    const severities = info.securityIssues?.map(v => v.severity) || [];
    if (severities.includes('critical')) tags.push('critical-severity');
    else if (severities.includes('high')) tags.push('high-severity');
    else if (severities.includes('medium')) tags.push('medium-severity');
    else if (severities.includes('low')) tags.push('low-severity');
  }
  
  // Add license tags
  if (info.license) {
    if (isPermissiveLicense(info.license)) {
      tags.push('permissive-license');
    } else if (isCopyleftLicense(info.license)) {
      tags.push('copyleft-license');
    }
  }
  
  // Maintenance status
  if (info.isMaintained === false) {
    tags.push('unmaintained');
  }
  
  return tags;
}

/* ---- Helper Functions and Definitions ---- */

/**
 * Get manifest definitions for various package managers
 */
function getManifestDefinitions(): DependencyManifest[] {
  return [
    // NPM / Yarn / PNPM
    {
      packageManager: PackageManager.NPM,
      filePattern: '**/package.json',
      parser: (content) => {
        try {
          const pkg = JSON.parse(content);
          return pkg.dependencies || {};
        } catch (error) {
          return null;
        }
      },
      devDependenciesParser: (content) => {
        try {
          const pkg = JSON.parse(content);
          return pkg.devDependencies || {};
        } catch (error) {
          return null;
        }
      },
      peerDependenciesParser: (content) => {
        try {
          const pkg = JSON.parse(content);
          return pkg.peerDependencies || {};
        } catch (error) {
          return null;
        }
      },
      optionalDependenciesParser: (content) => {
        try {
          const pkg = JSON.parse(content);
          return pkg.optionalDependencies || {};
        } catch (error) {
          return null;
        }
      }
    },
    // Python pip
    {
      packageManager: PackageManager.PIP,
      filePattern: '**/requirements.txt',
      parser: (content) => {
        const result: Record<string, string> = {};
        const lines = content.split('\n');
        
        for (const line of lines) {
          // Skip comments and empty lines
          if (line.trim().startsWith('#') || !line.trim()) continue;
          
          // Parse requirement line
          const match = line.match(/^([a-zA-Z0-9_.-]+)([<>=~!]+)([a-zA-Z0-9_.-]+)/);
          if (match) {
            const [, name, , version] = match;
            result[name.trim()] = version.trim();
          } else {
            // Handle case where no version is specified
            const simpleName = line.trim().split(/\s+/)[0];
            if (simpleName) {
              result[simpleName] = '*';
            }
          }
        }
        
        return result;
      }
    },
    // Python Poetry
    {
      packageManager: PackageManager.POETRY,
      filePattern: '**/pyproject.toml',
      parser: (content) => {
        const result: Record<string, string> = {};
        const lines = content.split('\n');
        let inDependencies = false;
        
        for (const line of lines) {
          if (line.trim() === '[tool.poetry.dependencies]') {
            inDependencies = true;
            continue;
          } else if (line.trim().startsWith('[') && inDependencies) {
            inDependencies = false;
          }
          
          if (inDependencies) {
            const match = line.match(/([a-zA-Z0-9_.-]+)\s*=\s*"([^"]+)"|([a-zA-Z0-9_.-]+)\s*=\s*'([^']+)'/);
            if (match) {
              const name = match[1] || match[3];
              const version = match[2] || match[4] || '*';
              
              if (name && name !== 'python') {
                result[name.trim()] = version.replace(/\^|~|=|>|<|\*|\|/g, '');
              }
            }
          }
        }
        
        return Object.keys(result).length > 0 ? result : null;
      },
      devDependenciesParser: (content) => {
        const result: Record<string, string> = {};
        const lines = content.split('\n');
        let inDevDependencies = false;
        
        for (const line of lines) {
          if (line.trim() === '[tool.poetry.dev-dependencies]') {
            inDevDependencies = true;
            continue;
          } else if (line.trim().startsWith('[') && inDevDependencies) {
            inDevDependencies = false;
          }
          
          if (inDevDependencies) {
            const match = line.match(/([a-zA-Z0-9_.-]+)\s*=\s*"([^"]+)"|([a-zA-Z0-9_.-]+)\s*=\s*'([^']+)'/);
            if (match) {
              const name = match[1] || match[3];
              const version = match[2] || match[4] || '*';
              
              if (name && name !== 'python') {
                result[name.trim()] = version.replace(/\^|~|=|>|<|\*|\|/g, '');
              }
            }
          }
        }
        
        return Object.keys(result).length > 0 ? result : null;
      }
    },
    // Maven
    {
      packageManager: PackageManager.MAVEN,
      filePattern: '**/pom.xml',
      parser: (content) => {
        const result: Record<string, string> = {};
        
        // Extract dependencies
        const dependencyMatches = content.matchAll(/<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*<version>([^<]+)<\/version>/g);
        
        for (const match of dependencyMatches) {
          const groupId = match[1].trim();
          const artifactId = match[2].trim();
          const version = match[3].trim();
          
          result[`${groupId}:${artifactId}`] = version;
        }
        
        return Object.keys(result).length > 0 ? result : null;
      }
    },
    // Gradle
    {
      packageManager: PackageManager.GRADLE,
      filePattern: '**/*.gradle',
      parser: (content) => {
        const result: Record<string, string> = {};
        
        // Match different dependency formats
        const depMatches = [
          ...content.matchAll(/implementation\s+['"]([-\w.]+):([-\w.]+):([-\w.]+)['"]\s*/g),
          ...content.matchAll(/api\s+['"]([-\w.]+):([-\w.]+):([-\w.]+)['"]\s*/g),
          ...content.matchAll(/compile\s+['"]([-\w.]+):([-\w.]+):([-\w.]+)['"]\s*/g),
          ...content.matchAll(/runtime\s+['"]([-\w.]+):([-\w.]+):([-\w.]+)['"]\s*/g)
        ];
        
        for (const match of depMatches) {
          const groupId = match[1].trim();
          const artifactId = match[2].trim();
          const version = match[3].trim();
          
          result[`${groupId}:${artifactId}`] = version;
        }
        
        return Object.keys(result).length > 0 ? result : null;
      },
      devDependenciesParser: (content) => {
        const result: Record<string, string> = {};
        
        // Match test dependencies
        const depMatches = [
          ...content.matchAll(/testImplementation\s+['"]([-\w.]+):([-\w.]+):([-\w.]+)['"]\s*/g),
          ...content.matchAll(/testCompile\s+['"]([-\w.]+):([-\w.]+):([-\w.]+)['"]\s*/g)
        ];
        
        for (const match of depMatches) {
          const groupId = match[1].trim();
          const artifactId = match[2].trim();
          const version = match[3].trim();
          
          result[`${groupId}:${artifactId}`] = version;
        }
        
        return Object.keys(result).length > 0 ? result : null;
      }
    },
    // Composer (PHP)
    {
      packageManager: PackageManager.COMPOSER,
      filePattern: '**/composer.json',
      parser: (content) => {
        try {
          const pkg = JSON.parse(content);
          return pkg.require || {};
        } catch (error) {
          return null;
        }
      },
      devDependenciesParser: (content) => {
        try {
          const pkg = JSON.parse(content);
          return pkg['require-dev'] || {};
        } catch (error) {
          return null;
        }
      }
    },
    // Cargo (Rust)
    {
      packageManager: PackageManager.CARGO,
      filePattern: '**/Cargo.toml',
      parser: (content) => {
        const result: Record<string, string> = {};
        const lines = content.split('\n');
        let inDependencies = false;
        
        for (const line of lines) {
          if (line.trim() === '[dependencies]') {
            inDependencies = true;
            continue;
          } else if (line.trim().startsWith('[') && inDependencies) {
            inDependencies = false;
          }
          
          if (inDependencies) {
            // Match lines like package = "version" or package = { version = "version" }
            const simpleMatch = line.match(/([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"|([a-zA-Z0-9_-]+)\s*=\s*'([^']+)'/);
            const complexMatch = line.match(/([a-zA-Z0-9_-]+)\s*=\s*\{[^\}]*version\s*=\s*"([^"]+)"[^\}]*\}/);
            
            if (simpleMatch) {
              const name = simpleMatch[1] || simpleMatch[3];
              const version = simpleMatch[2] || simpleMatch[4] || '*';
              result[name.trim()] = version.replace(/\^|~|=|>|<|\*|\|/g, '');
            } else if (complexMatch) {
              result[complexMatch[1].trim()] = complexMatch[2];
            }
          }
        }
        
        return Object.keys(result).length > 0 ? result : null;
      },
      devDependenciesParser: (content) => {
        const result: Record<string, string> = {};
        const lines = content.split('\n');
        let inDevDependencies = false;
        
        for (const line of lines) {
          if (line.trim() === '[dev-dependencies]') {
            inDevDependencies = true;
            continue;
          } else if (line.trim().startsWith('[') && inDevDependencies) {
            inDevDependencies = false;
          }
          
          if (inDevDependencies) {
            // Match lines like package = "version" or package = { version = "version" }
            const simpleMatch = line.match(/([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"|([a-zA-Z0-9_-]+)\s*=\s*'([^']+)'/);
            const complexMatch = line.match(/([a-zA-Z0-9_-]+)\s*=\s*\{[^\}]*version\s*=\s*"([^"]+)"[^\}]*\}/);
            
            if (simpleMatch) {
              const name = simpleMatch[1] || simpleMatch[3];
              const version = simpleMatch[2] || simpleMatch[4] || '*';
              result[name.trim()] = version.replace(/\^|~|=|>|<|\*|\|/g, '');
            } else if (complexMatch) {
              result[complexMatch[1].trim()] = complexMatch[2];
            }
          }
        }
        
        return Object.keys(result).length > 0 ? result : null;
      }
    },
    // Go modules
    {
      packageManager: PackageManager.GO,
      filePattern: '**/go.mod',
      parser: (content) => {
        const result: Record<string, string> = {};
        const lines = content.split('\n');
        
        for (const line of lines) {
          // Match lines like: require github.com/pkg/errors v0.9.1
          const directMatch = line.match(/^require\s+([^\s]+)\s+([^\s]+)/);
          
          // Match lines in a require block: github.com/pkg/errors v0.9.1
          const blockMatch = line.match(/^\s+([^\s]+)\s+([^\s]+)/);
          
          if (directMatch || blockMatch) {
            const match = directMatch || blockMatch;
            const name = match[1].trim();
            let version = match[2].trim();
            
            // Remove 'v' prefix if present
            if (version.startsWith('v')) {
              version = version.substring(1);
            }
            
            result[name] = version;
          }
        }
        
        return Object.keys(result).length > 0 ? result : null;
      }
    },
    // Ruby Gemfile
    {
      packageManager: PackageManager.GEM,
      filePattern: '**/Gemfile',
      parser: (content) => {
        const result: Record<string, string> = {};
        const lines = content.split('\n');
        
        for (const line of lines) {
          // Skip comments and empty lines
          if (line.trim().startsWith('#') || !line.trim()) continue;
          
          // Match gem specifications: gem 'name', '~> 1.2.3'
          const match = line.match(/gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?/);
          if (match) {
            const name = match[1].trim();
            let version = match[2] ? match[2].trim() : '*';
            
            // Clean up version string
            version = version.replace(/^[~><]=?\s*/, '');
            
            result[name] = version;
          }
        }
        
        return Object.keys(result).length > 0 ? result : null;
      },
      devDependenciesParser: (content) => {
        const result: Record<string, string> = {};
        const lines = content.split('\n');
        let inDevelopmentGroup = false;
        let inTestGroup = false;
        
        for (const line of lines) {
          // Skip comments and empty lines
          if (line.trim().startsWith('#') || !line.trim()) continue;
          
          // Check if we're entering/exiting a development or test group
          if (line.match(/^group\s+:(?:development|dev)(?:,|\s|$)/)) {
            inDevelopmentGroup = true;
          } else if (line.match(/^group\s+:test(?:,|\s|$)/)) {
            inTestGroup = true;
          } else if (line.trim() === 'end' && (inDevelopmentGroup || inTestGroup)) {
            inDevelopmentGroup = false;
            inTestGroup = false;
          }
          
          // Only process gems in development or test groups
          if (inDevelopmentGroup || inTestGroup) {
            const match = line.match(/gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?/);
            if (match) {
              const name = match[1].trim();
              let version = match[2] ? match[2].trim() : '*';
              
              // Clean up version string
              version = version.replace(/^[~><]=?\s*/, '');
              
              result[name] = version;
            }
          }
        }
        
        return Object.keys(result).length > 0 ? result : null;
      }
    },
    // Swift Package Manager
    {
      packageManager: PackageManager.SWIFT,
      filePattern: '**/Package.swift',
      parser: (content) => {
        const result: Record<string, string> = {};
        
        // Match package dependencies: .package(url: "https://github.com/user/package.git", from: "1.0.0")
        const matches = content.matchAll(/\.package\((?:url|name):\s*"([^"]+)",\s*(?:from|exact|branch|revision|version|range):\s*"([^"]+)"\)/g);
        
        for (const match of matches) {
          // Extract the package name from the URL
          const url = match[1].trim();
          const version = match[2].trim();
          
          // Get the package name from the URL
          const urlParts = url.split('/');
          const packageName = urlParts[urlParts.length - 1].replace('.git', '');
          
          result[packageName] = version;
        }
        
        return Object.keys(result).length > 0 ? result : null;
      }
    },
    // NuGet packages (C#)
    {
      packageManager: PackageManager.NUGET,
      filePattern: '**/*.csproj',
      parser: (content) => {
        const result: Record<string, string> = {};
        
        // Match package references: <PackageReference Include="Package.Name" Version="1.2.3" />
        const matches = content.matchAll(/<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"\s*\/?>/g);
        
        for (const match of matches) {
          const name = match[1].trim();
          const version = match[2].trim();
          
          result[name] = version;
        }
        
        return Object.keys(result).length > 0 ? result : null;
      }
    }
  ];
}

/**
 * Parse a custom manifest file
 */
function parseCustomManifest(content: string): Record<string, string> | null {
  try {
    // Try parsing as JSON first
    const json = JSON.parse(content);
    
    // Check common locations for dependencies
    if (json.dependencies) {
      return json.dependencies;
    } else if (json.require) {
      return json.require;
    }
  } catch (e) {
    // Not JSON, try line-by-line parsing for simple key-value formats
    const result: Record<string, string> = {};
    const lines = content.split('\n');
    
    for (const line of lines) {
      // Skip comments and empty lines
      if (line.trim().startsWith('#') || line.trim().startsWith('//') || !line.trim()) continue;
      
      // Try matching key-value pairs in various formats
      const match = line.match(/([\w.-]+)[=:]\s*['"]?([\w.-]+)['"]?/) ||
                   line.match(/([\w.-]+)\s+([\w.-]+)/);
      
      if (match) {
        result[match[1].trim()] = match[2].trim();
      }
    }
    
    if (Object.keys(result).length > 0) {
      return result;
    }
  }
  
  return null;
}

/**
 * Clean up version string by removing version range operators
 */
function cleanVersionString(version: string): string {
  if (!version) return '';
  
  // Remove common version range operators
  return version
    .replace(/^[\^~>=<]+\s*/, '') // Remove operators at the start
    .replace(/[*xX]/, '0')        // Replace wildcards with 0
    .split(/\s+/)[0]               // Take only the first part if there are multiple
    .split(/[|,]/)[0];             // Take only the first part if there are OR conditions
}

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
 * Get a random license for mock data
 */
function getRandomLicense(): string {
  const licenses = [
    'MIT', 'Apache-2.0', 'BSD-3-Clause', 'GPL-3.0', 'LGPL-2.1',
    'ISC', 'MPL-2.0', 'AGPL-3.0', 'Unlicense', 'proprietary'
  ];
  return licenses[Math.floor(Math.random() * licenses.length)];
}

/**
 * Check if a license is permissive
 */
function isPermissiveLicense(license: string): boolean {
  const permissiveLicenses = ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'ISC', 'Unlicense'];
  return permissiveLicenses.some(l => license.includes(l));
}

/**
 * Check if a license is copyleft
 */
function isCopyleftLicense(license: string): boolean {
  const copyleftLicenses = ['GPL', 'LGPL', 'AGPL', 'MPL'];
  return copyleftLicenses.some(l => license.includes(l));
}

/**
 * Get a random security vulnerability severity
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
 * Get a random vulnerability type for mock data
 */
function getRandomVulnerabilityType(): string {
  const types = [
    'prototype pollution',
    'cross-site scripting',
    'path traversal',
    'command injection',
    'insecure deserialization',
    'buffer overflow',
    'SQL injection',
    'regular expression denial of service',
    'arbitrary code execution',
    'memory leak',
    'information disclosure'
  ];
  return types[Math.floor(Math.random() * types.length)];
}

/**
 * Get random alternatives for deprecated packages
 */
function getRandomAlternatives(name: string, packageManager: string): string[] {
  // This would be powered by a real database in a production system
  // Here we just generate some mock alternatives
  const count = 1 + Math.floor(Math.random() * 3);
  const result: string[] = [];
  
  for (let i = 0; i < count; i++) {
    // Generate alternatives by adding prefixes/suffixes
    const prefixes = ['modern-', 'better-', 'secure-', 'new-'];
    const suffixes = ['-next', '-improved', '-2', '.js'];
    
    const usePrefix = Math.random() > 0.5;
    
    if (usePrefix) {
      const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
      result.push(prefix + name);
    } else {
      const nameParts = name.split('/');
      const baseName = nameParts[nameParts.length - 1];
      const suffix = suffixes[Math.floor(Math.random() * suffixes.length)];
      
      if (nameParts.length > 1) {
        const scope = nameParts.slice(0, -1).join('/');
        result.push(`${scope}/${baseName}${suffix}`);
      } else {
        result.push(baseName + suffix);
      }
    }
  }
  
  return result;
}
