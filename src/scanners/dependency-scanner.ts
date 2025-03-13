import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { glob } from 'glob';
import * as child_process from 'child_process';
import { DependencyIssue, VulnerabilityInfo } from '../types/scanning';
import { log } from '../utils/logging';
import { compareVersions, isDependencyCritical, isReallyOutdated } from '../utils/scanner-utils';

const readFileAsync = promisify(fs.readFile);
const execAsync = promisify(child_process.exec);

/**
 * Configuration for dependency scanning
 */
export interface DependencyScannerConfig {
  // Root directory to scan
  rootDirectory: string;
  
  // Which dependency types to check
  dependencyTypes: Array<'npm' | 'pip' | 'gem' | 'composer' | 'maven' | 'gradle' | 'nuget' | 'cargo' | 'go'>;
  
  // Whether to use offline mode (don't make API calls)
  offlineMode: boolean;
  
  // Whether to check for security vulnerabilities
  checkVulnerabilities: boolean;
  
  // Whether to check for unused dependencies
  checkUnused: boolean;
  
  // Whether to check for license issues
  checkLicenses: boolean;
  
  // Skip dependencies with specific names
  ignoreDependencies?: string[];
  
  // Skip dependencies matching specific patterns
  ignorePatterns?: string[];
  
  // API timeout in milliseconds
  apiTimeoutMs: number;
  
  // Directory to store cached data
  cacheDir?: string;
  
  // Whether this is a production system
  isProduction?: boolean;
}

/**
 * Detected dependency
 */
interface DetectedDependency {
  name: string;
  version: string;
  type: 'npm' | 'pip' | 'gem' | 'composer' | 'maven' | 'gradle' | 'nuget' | 'cargo' | 'go';
  location: string;
  isDevDependency: boolean;
}

/**
 * Dependency version info from registry
 */
interface DependencyVersionInfo {
  latestVersion: string;
  latestReleaseDate?: Date;
  isDeprecated: boolean;
  vulnerabilities: VulnerabilityInfo[];
  licenses: string[];
  alternativeDependencies?: {
    name: string;
    url: string;
  }[];
}

/**
 * Scanner for detecting outdated dependencies
 */
export async function scanDependencies(
  config: DependencyScannerConfig
): Promise<DependencyIssue[]> {
  try {
    log.info('Starting dependency scanner');
    const issues: DependencyIssue[] = [];
    
    // Detect dependencies for each type
    for (const dependencyType of config.dependencyTypes) {
      try {
        log.info(`Scanning for ${dependencyType} dependencies`);
        
        // Detect dependencies
        const dependencies = await detectDependencies(config.rootDirectory, dependencyType);
        log.info(`Found ${dependencies.length} ${dependencyType} dependencies`);
        
        // Check each dependency
        for (const dependency of dependencies) {
          try {
            // Skip ignored dependencies
            if (config.ignoreDependencies && config.ignoreDependencies.includes(dependency.name)) {
              log.info(`Skipping ignored dependency: ${dependency.name}`);
              continue;
            }
            
            // Skip dependencies matching ignore patterns
            if (config.ignorePatterns && 
                config.ignorePatterns.some(pattern => new RegExp(pattern).test(dependency.name))) {
              log.info(`Skipping dependency matching ignore pattern: ${dependency.name}`);
              continue;
            }
            
            // Get dependency information
            const dependencyInfo = await getDependencyInfo(
              dependency.name,
              dependency.version,
              dependency.type,
              config.offlineMode,
              config.checkVulnerabilities,
              config.checkLicenses,
              config.cacheDir
            );
            
            // Check if outdated
            const isOutdated = isReallyOutdated(
              dependency.name,
              dependency.version,
              dependencyInfo.latestVersion
            );
            
            // Check if unused (in a real implementation, this would use static analysis)
            const isUnused = config.checkUnused ? await checkIfUnused(dependency, config.rootDirectory) : false;
            
            // Check for license issues
            const licenseIssue = config.checkLicenses ? 
              checkLicenseIssues(dependencyInfo.licenses, config.isProduction || false) : undefined;
            
            // Only create an issue if there's at least one problem
            if (isOutdated || isUnused || licenseIssue || dependencyInfo.isDeprecated || 
                (config.checkVulnerabilities && dependencyInfo.vulnerabilities.length > 0)) {
              
              // Create the issue
              const issue: DependencyIssue = {
                name: dependency.name,
                type: dependency.type,
                currentVersion: dependency.version,
                latestVersion: dependencyInfo.latestVersion,
                isOutdated,
                isDeprecated: dependencyInfo.isDeprecated,
                isUnused,
                licenseIssue,
                location: dependency.location,
                detectedAt: new Date()
              };
              
              // Add vulnerability info if any exist
              if (dependencyInfo.vulnerabilities.length > 0) {
                issue.vulnerabilities = dependencyInfo.vulnerabilities;
                issue.securityImpact = Math.max(...dependencyInfo.vulnerabilities.map(v => 
                  securityImpactFromSeverity(v.severity)));
              }
              
              // Calculate business impact
              const isCritical = isDependencyCritical(dependency.name);
              issue.businessImpact = calculateBusinessImpact(
                isOutdated,
                dependencyInfo.isDeprecated,
                dependencyInfo.vulnerabilities.length > 0,
                isCritical,
                !dependency.isDevDependency
              );
              
              // Calculate migration effort
              issue.migrationEffort = calculateMigrationEffort(
                dependency.name,
                dependency.version,
                dependencyInfo.latestVersion,
                dependencyInfo.vulnerabilities.length > 0,
                dependency.type
              );
              
              // Generate recommendation
              issue.recommendation = generateRecommendation(
                dependency.name,
                dependency.version,
                dependencyInfo.latestVersion,
                isOutdated,
                dependencyInfo.isDeprecated,
                isUnused,
                licenseIssue,
                dependencyInfo.vulnerabilities.length > 0,
                dependencyInfo.alternativeDependencies
              );
              
              // Add appropriate tags
              issue.tags = generateTags(
                dependency.type,
                isOutdated,
                dependencyInfo.isDeprecated,
                isUnused,
                licenseIssue,
                dependencyInfo.vulnerabilities.length > 0,
                dependency.isDevDependency
              );
              
              // Add to issues list
              issues.push(issue);
              log.info(`Added issue for dependency ${dependency.name} ${dependency.version}`);
            }
          } catch (depError) {
            log.warn(`Error processing dependency: ${dependency.name}`, { error: depError });
          }
        }
      } catch (typeError) {
        log.error(`Error scanning ${dependencyType} dependencies`, { error: typeError });
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
 * Detect dependencies in a project
 */
async function detectDependencies(
  rootDirectory: string,
  dependencyType: 'npm' | 'pip' | 'gem' | 'composer' | 'maven' | 'gradle' | 'nuget' | 'cargo' | 'go'
): Promise<DetectedDependency[]> {
  try {
    const dependencies: DetectedDependency[] = [];
    
    switch (dependencyType) {
      case 'npm':
        // Find package.json files
        const packageJsonFiles = await glob(path.join(rootDirectory, '**', 'package.json'), {
          ignore: ['**/node_modules/**', '**/.git/**']
        });
        
        for (const packageJsonFile of packageJsonFiles) {
          try {
            const content = await readFileAsync(packageJsonFile, 'utf8');
            const packageJson = JSON.parse(content);
            
            // Process dependencies
            if (packageJson.dependencies) {
              for (const [name, version] of Object.entries(packageJson.dependencies)) {
                dependencies.push({
                  name,
                  version: String(version).replace(/[^0-9.]/g, ''),
                  type: 'npm',
                  location: packageJsonFile,
                  isDevDependency: false
                });
              }
            }
            
            // Process devDependencies
            if (packageJson.devDependencies) {
              for (const [name, version] of Object.entries(packageJson.devDependencies)) {
                dependencies.push({
                  name,
                  version: String(version).replace(/[^0-9.]/g, ''),
                  type: 'npm',
                  location: packageJsonFile,
                  isDevDependency: true
                });
              }
            }
          } catch (fileError) {
            log.warn(`Error processing package.json: ${packageJsonFile}`, { error: fileError });
          }
        }
        break;
        
      case 'pip':
        // Find requirements.txt files
        const requirementsFiles = await glob(path.join(rootDirectory, '**', 'requirements*.txt'), {
          ignore: ['**/venv/**', '**/.git/**', '**/.env/**']
        });
        
        for (const requirementsFile of requirementsFiles) {
          try {
            const content = await readFileAsync(requirementsFile, 'utf8');
            const lines = content.split('\n');
            
            for (const line of lines) {
              // Skip comments and empty lines
              if (line.trim().startsWith('#') || !line.trim()) {
                continue;
              }
              
              // Parse dependency line
              const match = line.match(/^([\w-_.]+)(?:[<>=!~]+([\d.]+))?/);
              if (match) {
                const name = match[1];
                const version = match[2] || '0.0.0'; // Default if not specified
                
                dependencies.push({
                  name,
                  version,
                  type: 'pip',
                  location: requirementsFile,
                  // Assume dev dependencies have "dev" in the filename
                  isDevDependency: requirementsFile.includes('dev')
                });
              }
            }
          } catch (fileError) {
            log.warn(`Error processing requirements file: ${requirementsFile}`, { error: fileError });
          }
        }
        break;
        
      // Add more dependency types here in a real implementation
      // For this example, we'll just implement npm and pip
      
      default:
        log.info(`Dependency type not fully implemented: ${dependencyType}`);
    }
    
    return dependencies;
  } catch (error) {
    log.error(`Error detecting ${dependencyType} dependencies`, { error });
    return [];
  }
}

/**
 * Get dependency information from registry or cache
 */
async function getDependencyInfo(
  name: string,
  version: string,
  type: 'npm' | 'pip' | 'gem' | 'composer' | 'maven' | 'gradle' | 'nuget' | 'cargo' | 'go',
  offlineMode: boolean,
  checkVulnerabilities: boolean,
  checkLicenses: boolean,
  cacheDir?: string
): Promise<DependencyVersionInfo> {
  // Check cache first
  if (cacheDir) {
    const cacheFile = path.join(cacheDir, `${type}-${name}.json`);
    
    if (fs.existsSync(cacheFile)) {
      try {
        const cacheContent = await readFileAsync(cacheFile, 'utf8');
        const cachedInfo = JSON.parse(cacheContent) as DependencyVersionInfo;
        log.info(`Loaded ${name} info from cache`);
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
      latestVersion: version, // Assume current version is latest
      isDeprecated: false,
      vulnerabilities: [],
      licenses: []
    };
  }
  
  // In a real implementation, we would query the registry API
  // For this example, we'll return mock data
  try {
    // Mock registry query
    log.info(`Querying registry for ${type} dependency: ${name}@${version}`);
    
    // Generate mock data based on the dependency name and version
    const info: DependencyVersionInfo = {
      latestVersion: incrementVersion(version),
      latestReleaseDate: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000), // Random date in last 30 days
      isDeprecated: name.includes('deprecated') || name.includes('legacy'),
      vulnerabilities: [],
      licenses: [getRandomLicense()]
    };
    
    // Add vulnerabilities for some dependencies (for demo purposes)
    if (checkVulnerabilities && (name.includes('vulnerable') || Math.random() < 0.1)) {
      info.vulnerabilities = [
        {
          id: `CVE-2023-${Math.floor(Math.random() * 10000)}`,
          severity: getRandomSeverity(),
          title: `Security vulnerability in ${name}`,
          description: `${name} version ${version} has a security vulnerability`,
          publishedDate: new Date(Date.now() - Math.random() * 90 * 24 * 60 * 60 * 1000), // Random date in last 90 days
          affectedVersions: `<=${version}`,
          patchedVersions: `>${version}`,
          recommendation: `Update to ${info.latestVersion} or newer`
        }
      ];
    }
    
    // If deprecated, suggest alternatives
    if (info.isDeprecated) {
      info.alternativeDependencies = [
        {
          name: `${name.replace('deprecated', 'modern').replace('legacy', 'next')}`,
          url: `https://www.npmjs.com/package/${name.replace('deprecated', 'modern')}`
        }
      ];
    }
    
    // Save to cache if cacheDir is provided
    if (cacheDir) {
      try {
        if (!fs.existsSync(cacheDir)) {
          fs.mkdirSync(cacheDir, { recursive: true });
        }
        
        const cacheFile = path.join(cacheDir, `${type}-${name}.json`);
        await fs.promises.writeFile(cacheFile, JSON.stringify(info, null, 2), 'utf8');
        log.info(`Cached ${name} info`);
      } catch (cacheError) {
        log.warn(`Error writing dependency cache for ${name}`, { error: cacheError });
      }
    }
    
    return info;
  } catch (error) {
    log.error(`Error querying registry for ${name}`, { error });
    
    // Return basic info if registry query fails
    return {
      latestVersion: version,
      isDeprecated: false,
      vulnerabilities: [],
      licenses: []
    };
  }
}

/**
 * Check if a dependency is unused
 * In a real implementation, this would use static analysis
 */
async function checkIfUnused(
  dependency: DetectedDependency,
  rootDirectory: string
): Promise<boolean> {
  // For this example, we'll just return false (not unused)
  // In a real implementation, this would use static analysis tools
  return false;
}

/**
 * Check for license issues
 */
function checkLicenseIssues(
  licenses: string[],
  isProduction: boolean
): { issue: string; severity: 'low' | 'medium' | 'high' } | undefined {
  if (!licenses || licenses.length === 0) {
    return {
      issue: 'Unknown license',
      severity: isProduction ? 'high' : 'medium'
    };
  }
  
  // List of potentially problematic licenses for commercial use
  const restrictiveLicenses = ['GPL', 'AGPL', 'LGPL', 'SSPL'];
  
  for (const license of licenses) {
    if (restrictiveLicenses.some(l => license.includes(l))) {
      return {
        issue: `Restrictive license: ${license}`,
        severity: isProduction ? 'high' : 'medium'
      };
    }
  }
  
  return undefined;
}

/**
 * Calculate business impact score
 */
function calculateBusinessImpact(
  isOutdated: boolean,
  isDeprecated: boolean,
  hasVulnerabilities: boolean,
  isCriticalDependency: boolean,
  isProductionDependency: boolean
): number {
  let score = 1; // Start with minimal impact
  
  if (isOutdated) score += 1;
  if (isDeprecated) score += 2;
  if (hasVulnerabilities) score += 2;
  if (isCriticalDependency) score += 1;
  if (isProductionDependency) score += 1;
  
  // Cap at maximum of 5
  return Math.min(score, 5);
}

/**
 * Calculate migration effort
 */
function calculateMigrationEffort(
  name: string,
  currentVersion: string,
  latestVersion: string,
  hasVulnerabilities: boolean,
  type: string
): number {
  // Start with base effort
  let effort = 1;
  
  // Major version change is more effort
  if (getMajorVersion(currentVersion) < getMajorVersion(latestVersion)) {
    effort += 2;
  } else if (getMinorVersion(currentVersion) < getMinorVersion(latestVersion)) {
    effort += 1;
  }
  
  // Critical dependencies are usually harder to migrate
  if (isDependencyCritical(name)) {
    effort += 1;
  }
  
  // Cap at maximum of 5
  return Math.min(effort, 5);
}

/**
 * Generate tags for categorizing issues
 */
function generateTags(
  type: string,
  isOutdated: boolean,
  isDeprecated: boolean,
  isUnused: boolean,
  licenseIssue: { issue: string; severity: 'low' | 'medium' | 'high' } | undefined,
  hasVulnerabilities: boolean,
  isDevDependency: boolean
): string[] {
  const tags: string[] = [type];
  
  if (isOutdated) tags.push('outdated');
  if (isDeprecated) tags.push('deprecated');
  if (isUnused) tags.push('unused');
  if (licenseIssue) tags.push('license-issue');
  if (hasVulnerabilities) tags.push('security');
  if (isDevDependency) tags.push('dev-dependency');
  else tags.push('production-dependency');
  
  return tags;
}

/**
 * Generate a recommendation
 */
function generateRecommendation(
  name: string,
  currentVersion: string,
  latestVersion: string,
  isOutdated: boolean,
  isDeprecated: boolean,
  isUnused: boolean,
  licenseIssue: { issue: string; severity: 'low' | 'medium' | 'high' } | undefined,
  hasVulnerabilities: boolean,
  alternatives?: { name: string, url: string }[]
): string {
  const recommendations: string[] = [];
  
  if (isOutdated) {
    recommendations.push(`Update ${name} from ${currentVersion} to ${latestVersion}`);
  }
  
  if (isDeprecated) {
    if (alternatives && alternatives.length > 0) {
      const alternative = alternatives[0];
      recommendations.push(`Replace deprecated ${name} with ${alternative.name} (${alternative.url})`);
    } else {
      recommendations.push(`Remove or replace deprecated dependency ${name}`);
    }
  }
  
  if (isUnused) {
    recommendations.push(`Remove unused dependency ${name}`);
  }
  
  if (licenseIssue) {
    recommendations.push(`Address license issue: ${licenseIssue.issue}`);
  }
  
  if (hasVulnerabilities) {
    recommendations.push(`Update ${name} immediately to address security vulnerabilities`);
  }
  
  if (recommendations.length === 0) {
    recommendations.push(`No immediate action required for ${name}`);
  }
  
  return recommendations.join('. ');
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
 * Helper function to get major version
 */
function getMajorVersion(version: string): number {
  const parts = version.split('.');
  return parseInt(parts[0], 10) || 0;
}

/**
 * Helper function to get minor version
 */
function getMinorVersion(version: string): number {
  const parts = version.split('.');
  return parts.length > 1 ? (parseInt(parts[1], 10) || 0) : 0;
}

/**
 * Helper function for getting a random severity
 */
function getRandomSeverity(): 'low' | 'medium' | 'high' | 'critical' {
  const severities: Array<'low' | 'medium' | 'high' | 'critical'> = ['low', 'medium', 'high', 'critical'];
  return severities[Math.floor(Math.random() * severities.length)];
}

/**
 * Helper function for getting a random license
 */
function getRandomLicense(): string {
  const licenses = ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'GPL-3.0', 'ISC', 'LGPL-3.0', 'Unlicense', 'Custom'];
  return licenses[Math.floor(Math.random() * licenses.length)];
}

/**
 * Convert severity to a numeric security impact score
 */
function securityImpactFromSeverity(severity: 'low' | 'medium' | 'high' | 'critical'): number {
  switch (severity) {
    case 'critical': return 5;
    case 'high': return 4;
    case 'medium': return 3;
    case 'low': return 2;
    default: return 1;
  }
}
