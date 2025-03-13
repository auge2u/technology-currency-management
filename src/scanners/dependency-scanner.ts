import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { glob } from 'glob';
import * as child_process from 'child_process';
import * as semver from 'semver';
import { log } from '../utils/logging';
import { DependencyIssue, VulnerabilityInfo } from '../types/scanning';
import { compareVersions, getVersionChangeType, classifyMigrationRisk } from '../utils/scanner-utils';

const readFileAsync = promisify(fs.readFile);
const execAsync = promisify(child_process.exec);

/**
 * Configuration for dependency scanning
 */
export interface DependencyScannerConfig {
  // Root directory to scan
  rootDirectory: string;
  
  // Package types to check
  packageTypes: Array<'npm' | 'yarn' | 'pnpm' | 'pip' | 'gem' | 'composer' | 'cargo' | 'nuget' | 'maven'>;
  
  // Check for direct dependencies only
  directDependenciesOnly: boolean;
  
  // Whether to check for unused dependencies
  checkUnused: boolean;
  
  // Whether to check for vulnerable dependencies
  checkVulnerabilities: boolean;
  
  // Whether to check licenses
  checkLicenses: boolean;
  
  // Ignore packages with specific names
  ignorePackages?: string[];
  
  // Ignore specific development dependencies
  ignoreDevDependencies?: boolean;
  
  // Whether to use offline mode (don't make API calls)
  offlineMode: boolean;
  
  // API timeout in milliseconds
  apiTimeoutMs: number;
  
  // Directory to store cached data
  cacheDir?: string;
}

/**
 * Detected dependency
 */
interface DetectedDependency {
  name: string;
  type: string;
  version: string;
  location: string;
  isDev: boolean;
  isTransitive: boolean;
}

/**
 * Dependency version info from registry
 */
interface DependencyVersionInfo {
  latestVersion: string;
  latestReleaseDate?: Date;
  isDeprecated: boolean;
  licenseInfo?: {
    name: string;
    url?: string;
    isApproved: boolean;
    issues?: string[];
  };
  vulnerabilities: VulnerabilityInfo[];
  usage?: 'popular' | 'moderate' | 'low';
  downloadCount?: number;
  stars?: number;
  isOutdated: boolean;
  isUnused?: boolean;
}

/**
 * Scanner for detecting outdated, vulnerable, and problematic dependencies
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
        // Skip development dependencies if configured
        if (config.ignoreDevDependencies && dependency.isDev) {
          log.info(`Skipping dev dependency: ${dependency.name}`);
          continue;
        }
        
        // Skip ignored packages
        if (config.ignorePackages && config.ignorePackages.includes(dependency.name)) {
          log.info(`Skipping ignored package: ${dependency.name}`);
          continue;
        }
        
        // Skip transitive dependencies if configured
        if (config.directDependenciesOnly && dependency.isTransitive) {
          log.info(`Skipping transitive dependency: ${dependency.name}`);
          continue;
        }
        
        // Get dependency information
        const dependencyInfo = await getDependencyInfo(
          dependency.name,
          dependency.type,
          dependency.version,
          config.offlineMode,
          config.checkVulnerabilities,
          config.checkLicenses,
          config.cacheDir
        );
        
        // Only create an issue if there's at least one problem
        if (dependencyInfo.isOutdated || dependencyInfo.isDeprecated || 
            dependencyInfo.vulnerabilities.length > 0 || 
            (dependencyInfo.licenseInfo && !dependencyInfo.licenseInfo.isApproved) ||
            dependencyInfo.isUnused) {
          
          // Create the issue
          const issue: DependencyIssue = {
            name: dependency.name,
            type: dependency.type,
            currentVersion: dependency.version,
            latestVersion: dependencyInfo.latestVersion,
            location: dependency.location,
            isOutdated: dependencyInfo.isOutdated,
            isDeprecated: dependencyInfo.isDeprecated,
            isUnused: dependencyInfo.isUnused,
            detectedAt: new Date()
          };
          
          // Add license issue if applicable
          if (dependencyInfo.licenseInfo && !dependencyInfo.licenseInfo.isApproved) {
            issue.licenseIssue = {
              issue: `Non-approved license: ${dependencyInfo.licenseInfo.name}`,
              severity: 'medium' // Default severity
            };
            
            // Adjust severity based on license issues
            if (dependencyInfo.licenseInfo.issues && dependencyInfo.licenseInfo.issues.length > 0) {
              if (dependencyInfo.licenseInfo.issues.some(i => i.includes('copyleft') || i.includes('GPL'))) {
                issue.licenseIssue.severity = 'high';
              }
            }
          }
          
          // Add vulnerability info if any exist
          if (dependencyInfo.vulnerabilities.length > 0) {
            issue.vulnerabilities = dependencyInfo.vulnerabilities;
            
            // Set security impact based on highest vulnerability
            const highestSeverity = getHighestSeverity(dependencyInfo.vulnerabilities);
            switch (highestSeverity) {
              case 'critical':
                issue.securityImpact = 5;
                break;
              case 'high':
                issue.securityImpact = 4;
                break;
              case 'medium':
                issue.securityImpact = 3;
                break;
              case 'low':
                issue.securityImpact = 2;
                break;
              default:
                issue.securityImpact = 1;
            }
          }
          
          // Calculate business impact
          issue.businessImpact = calculateBusinessImpact(
            dependency.name,
            dependency.type,
            dependencyInfo.isOutdated,
            dependencyInfo.isDeprecated,
            dependencyInfo.vulnerabilities.length > 0,
            dependency.isDev
          );
          
          // Calculate migration effort
          if (dependencyInfo.isOutdated) {
            const versionChangeType = getVersionChangeType(
              dependency.version, 
              dependencyInfo.latestVersion
            );
            
            const migrationRisk = classifyMigrationRisk(
              dependency.name,
              versionChangeType,
              dependencyInfo.vulnerabilities.length > 0
            );
            
            // Map migration risk to a numerical score
            switch (migrationRisk) {
              case 'critical':
                issue.migrationEffort = 5;
                break;
              case 'high':
                issue.migrationEffort = 4;
                break;
              case 'medium':
                issue.migrationEffort = 3;
                break;
              case 'low':
                issue.migrationEffort = 2;
                break;
              default:
                issue.migrationEffort = 1;
            }
          }
          
          // Generate recommendation
          issue.recommendation = generateRecommendation(
            dependency,
            dependencyInfo
          );
          
          // Add appropriate tags
          issue.tags = generateTags(
            dependency.type,
            dependency.isDev,
            dependencyInfo.isOutdated,
            dependencyInfo.isDeprecated,
            dependencyInfo.vulnerabilities.length > 0,
            dependencyInfo.isUnused
          );
          
          // Add to issues list
          issues.push(issue);
          log.info(`Added issue for dependency ${dependency.name} ${dependency.version}`);
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
 * Detect dependencies in a project
 */
async function detectDependencies(
  config: DependencyScannerConfig
): Promise<DetectedDependency[]> {
  try {
    const dependencies: DetectedDependency[] = [];
    const rootDir = config.rootDirectory;
    
    // Detect dependencies based on package type
    for (const packageType of config.packageTypes) {
      try {
        log.info(`Detecting ${packageType} dependencies`);
        
        switch (packageType) {
          case 'npm':
          case 'yarn':
          case 'pnpm':
            // Check for package.json
            const packageJsonFiles = await glob(path.join(rootDir, '**/package.json'), {
              ignore: ['**/node_modules/**', '**/.git/**']
            });
            
            for (const packageJsonFile of packageJsonFiles) {
              try {
                const content = await readFileAsync(packageJsonFile, 'utf8');
                const packageJson = JSON.parse(content);
                
                // Process regular dependencies
                if (packageJson.dependencies) {
                  for (const [name, version] of Object.entries(packageJson.dependencies)) {
                    dependencies.push({
                      name,
                      type: 'npm',
                      version: (version as string).replace(/[^0-9.]/g, ''),
                      location: packageJsonFile,
                      isDev: false,
                      isTransitive: false
                    });
                  }
                }
                
                // Process dev dependencies
                if (packageJson.devDependencies) {
                  for (const [name, version] of Object.entries(packageJson.devDependencies)) {
                    dependencies.push({
                      name,
                      type: 'npm',
                      version: (version as string).replace(/[^0-9.]/g, ''),
                      location: packageJsonFile,
                      isDev: true,
                      isTransitive: false
                    });
                  }
                }
              } catch (fileError) {
                log.warn(`Error processing package.json: ${packageJsonFile}`, { error: fileError });
              }
            }
            
            // Check for lock files to get transitive dependencies
            if (!config.directDependenciesOnly) {
              let lockFiles: string[] = [];
              
              if (packageType === 'npm') {
                lockFiles = await glob(path.join(rootDir, '**/package-lock.json'), {
                  ignore: ['**/node_modules/**', '**/.git/**']
                });
              } else if (packageType === 'yarn') {
                lockFiles = await glob(path.join(rootDir, '**/yarn.lock'), {
                  ignore: ['**/node_modules/**', '**/.git/**']
                });
              } else if (packageType === 'pnpm') {
                lockFiles = await glob(path.join(rootDir, '**/pnpm-lock.yaml'), {
                  ignore: ['**/node_modules/**', '**/.git/**']
                });
              }
              
              // Processing lock files is more complex and varies by type
              // For this implementation, we'll skip the detailed parsing
              log.info(`Found ${lockFiles.length} lock files. Full parsing is not implemented.`);
            }
            break;
            
          case 'pip':
            // Check for requirements.txt
            const requirementsFiles = await glob(path.join(rootDir, '**/requirements*.txt'), {
              ignore: ['**/venv/**', '**/.git/**', '**/.env/**']
            });
            
            for (const requirementsFile of requirementsFiles) {
              try {
                const content = await readFileAsync(requirementsFile, 'utf8');
                const lines = content.split('\n');
                
                for (const line of lines) {
                  // Skip comments and empty lines
                  if (line.trim().startsWith('#') || line.trim() === '') {
                    continue;
                  }
                  
                  // Basic parsing of pip requirements
                  // Format can be: package==1.0.0, package>=1.0.0, package, etc.
                  const match = line.match(/^([\w\-_.]+)(?:[=<>!~]+([\w\d.]+))?/);
                  if (match) {
                    const name = match[1];
                    const version = match[2] || '0.0.0'; // Use a placeholder if version not specified
                    
                    dependencies.push({
                      name,
                      type: 'pip',
                      version,
                      location: requirementsFile,
                      isDev: requirementsFile.toLowerCase().includes('dev') || 
                              requirementsFile.toLowerCase().includes('test'),
                      isTransitive: false
                    });
                  }
                }
              } catch (fileError) {
                log.warn(`Error processing requirements file: ${requirementsFile}`, { error: fileError });
              }
            }
            break;
            
          case 'gem':
            // Check for Gemfile
            const gemFiles = await glob(path.join(rootDir, '**/Gemfile'), {
              ignore: ['**/vendor/**', '**/.git/**', '**/.bundle/**']
            });
            
            for (const gemFile of gemFiles) {
              try {
                const content = await readFileAsync(gemFile, 'utf8');
                const lines = content.split('\n');
                
                for (const line of lines) {
                  // Skip comments and empty lines
                  if (line.trim().startsWith('#') || line.trim() === '') {
                    continue;
                  }
                  
                  // Basic parsing of gem dependencies
                  // Format can be: gem 'name', '~> 1.0.0', gem 'name', etc.
                  const match = line.match(/gem\s+['"]([\w\-_.]+)['"](?:,\s+['"]([^'"]+)['"])?/);
                  if (match) {
                    const name = match[1];
                    const version = match[2] ? match[2].replace(/[^0-9.]/g, '') : '0.0.0';
                    
                    // Check if it's a development dependency
                    const isDev = content.includes('group :development') || content.includes('group :test');
                    
                    dependencies.push({
                      name,
                      type: 'gem',
                      version,
                      location: gemFile,
                      isDev,
                      isTransitive: false
                    });
                  }
                }
              } catch (fileError) {
                log.warn(`Error processing Gemfile: ${gemFile}`, { error: fileError });
              }
            }
            break;
            
          case 'composer':
            // Check for composer.json
            const composerFiles = await glob(path.join(rootDir, '**/composer.json'), {
              ignore: ['**/vendor/**', '**/.git/**']
            });
            
            for (const composerFile of composerFiles) {
              try {
                const content = await readFileAsync(composerFile, 'utf8');
                const composerJson = JSON.parse(content);
                
                // Process regular dependencies
                if (composerJson.require) {
                  for (const [name, version] of Object.entries(composerJson.require)) {
                    // Skip php itself
                    if (name === 'php') continue;
                    
                    dependencies.push({
                      name,
                      type: 'composer',
                      version: (version as string).replace(/[^0-9.]/g, ''),
                      location: composerFile,
                      isDev: false,
                      isTransitive: false
                    });
                  }
                }
                
                // Process dev dependencies
                if (composerJson['require-dev']) {
                  for (const [name, version] of Object.entries(composerJson['require-dev'])) {
                    dependencies.push({
                      name,
                      type: 'composer',
                      version: (version as string).replace(/[^0-9.]/g, ''),
                      location: composerFile,
                      isDev: true,
                      isTransitive: false
                    });
                  }
                }
              } catch (fileError) {
                log.warn(`Error processing composer.json: ${composerFile}`, { error: fileError });
              }
            }
            break;
            
          case 'cargo':
            // Check for Cargo.toml
            const cargoFiles = await glob(path.join(rootDir, '**/Cargo.toml'), {
              ignore: ['**/target/**', '**/.git/**']
            });
            
            for (const cargoFile of cargoFiles) {
              try {
                const content = await readFileAsync(cargoFile, 'utf8');
                const lines = content.split('\n');
                
                let inDependencies = false;
                let inDevDependencies = false;
                
                for (const line of lines) {
                  // Track which section we're in
                  if (line.trim() === '[dependencies]') {
                    inDependencies = true;
                    inDevDependencies = false;
                    continue;
                  } else if (line.trim() === '[dev-dependencies]') {
                    inDependencies = false;
                    inDevDependencies = true;
                    continue;
                  } else if (line.trim().startsWith('[') && line.trim().endsWith(']')) {
                    inDependencies = false;
                    inDevDependencies = false;
                    continue;
                  }
                  
                  // Skip if not in a dependencies section
                  if (!inDependencies && !inDevDependencies) {
                    continue;
                  }
                  
                  // Basic parsing of Cargo.toml dependencies
                  // Format can be: name = "1.0.0", name = { version = "1.0.0" }, etc.
                  const simpleMatch = line.match(/^([\w\-_]+)\s*=\s*"([\w\d.]+)"/);
                  if (simpleMatch) {
                    dependencies.push({
                      name: simpleMatch[1],
                      type: 'cargo',
                      version: simpleMatch[2],
                      location: cargoFile,
                      isDev: inDevDependencies,
                      isTransitive: false
                    });
                    continue;
                  }
                  
                  // More complex format with table
                  const tableMatch = line.match(/^([\w\-_]+)\s*=\s*\{/);
                  if (tableMatch) {
                    // For complex declarations, we'd need more sophisticated parsing
                    // Here we'll just capture the name and use a placeholder version
                    dependencies.push({
                      name: tableMatch[1],
                      type: 'cargo',
                      version: '0.0.0', // Placeholder
                      location: cargoFile,
                      isDev: inDevDependencies,
                      isTransitive: false
                    });
                  }
                }
              } catch (fileError) {
                log.warn(`Error processing Cargo.toml: ${cargoFile}`, { error: fileError });
              }
            }
            break;
            
          // Additional package types could be implemented here
          
          default:
            log.info(`Package type not fully implemented: ${packageType}`);
            break;
        }
      } catch (typeError) {
        log.error(`Error scanning ${packageType} dependencies`, { error: typeError });
      }
    }
    
    return dependencies;
  } catch (error) {
    log.error('Error detecting dependencies', { error });
    return [];
  }
}

/**
 * Get dependency information from registry or cache
 */
async function getDependencyInfo(
  name: string,
  type: string,
  version: string,
  offlineMode: boolean,
  checkVulnerabilities: boolean,
  checkLicenses: boolean,
  cacheDir?: string
): Promise<DependencyVersionInfo> {
  // Check cache first
  if (cacheDir) {
    const cacheFile = path.join(cacheDir, `dep-${type}-${name.replace(/[^a-z0-9]/gi, '-').toLowerCase()}.json`);
    
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
      isOutdated: false
    };
  }
  
  // In a real implementation, we would query the package registry
  // For this example, we'll use mock data
  try {
    log.info(`Querying registry for ${type} package: ${name}@${version}`);
    
    // Generate mock data
    const info: DependencyVersionInfo = {
      latestVersion: incrementVersion(version),
      isDeprecated: isDeprecated(name),
      vulnerabilities: [],
      isOutdated: true // Assume it's outdated for demonstration
    };
    
    // Add vulnerabilities if needed
    if (checkVulnerabilities && (isVulnerable(name) || Math.random() < 0.2)) {
      info.vulnerabilities = [
        {
          id: `CVE-2023-${Math.floor(Math.random() * 10000)}`,
          severity: getRandomSeverity(),
          title: `Security issue in ${name}`,
          description: `${getRandomVulnerabilityType()} vulnerability in ${name} affecting versions < ${info.latestVersion}`,
          publishedDate: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000),
          affectedVersions: `<= ${version}`,
          patchedVersions: `>= ${info.latestVersion}`,
          recommendation: `Update to version ${info.latestVersion} or later`
        }
      ];
    }
    
    // Add license info if needed
    if (checkLicenses) {
      info.licenseInfo = {
        name: getRandomLicense(),
        isApproved: Math.random() < 0.9 // 90% chance it's approved
      };
      
      if (!info.licenseInfo.isApproved) {
        info.licenseInfo.issues = [
          `License ${info.licenseInfo.name} does not comply with corporate policy`
        ];
        
        if (info.licenseInfo.name.includes('GPL')) {
          info.licenseInfo.issues.push('Copyleft license may require source code disclosure');
        }
      }
    }
    
    // Add usage stats
    const randomNumber = Math.random();
    if (randomNumber < 0.1) {
      info.usage = 'low';
      info.downloadCount = Math.floor(Math.random() * 1000);
    } else if (randomNumber < 0.6) {
      info.usage = 'moderate';
      info.downloadCount = Math.floor(Math.random() * 10000) + 1000;
    } else {
      info.usage = 'popular';
      info.downloadCount = Math.floor(Math.random() * 1000000) + 10000;
    }
    
    // Add stars
    info.stars = Math.floor(Math.random() * 10000);
    
    // Save to cache if cacheDir is provided
    if (cacheDir) {
      try {
        if (!fs.existsSync(cacheDir)) {
          fs.mkdirSync(cacheDir, { recursive: true });
        }
        
        const cacheFile = path.join(cacheDir, `dep-${type}-${name.replace(/[^a-z0-9]/gi, '-').toLowerCase()}.json`);
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
      isOutdated: false
    };
  }
}

/**
 * Calculate business impact score
 */
function calculateBusinessImpact(
  name: string,
  type: string,
  isOutdated: boolean,
  isDeprecated: boolean,
  hasVulnerabilities: boolean,
  isDev: boolean
): number {
  let score = 1; // Start with minimal impact
  
  // Dev dependencies have less impact
  const multiplier = isDev ? 0.5 : 1;
  
  if (isOutdated) score += 1;
  if (isDeprecated) score += 2;
  if (hasVulnerabilities) score += 3;
  
  // Critical dependencies would have higher impact
  const criticalDependencies = ['react', 'angular', 'vue', 'express', 'axios', 'lodash', 'mongoose', 'sequelize'];
  if (criticalDependencies.includes(name.toLowerCase())) {
    score += 1;
  }
  
  // Apply the dev dependency multiplier
  score = Math.round(score * multiplier);
  
  // Cap at maximum of 5
  return Math.min(score, 5);
}

/**
 * Generate a recommendation
 */
function generateRecommendation(
  dependency: DetectedDependency,
  dependencyInfo: DependencyVersionInfo
): string {
  const recommendations: string[] = [];
  
  if (dependencyInfo.vulnerabilities.length > 0) {
    recommendations.push(
      `Update ${dependency.name} immediately from ${dependency.version} to at least ${dependencyInfo.latestVersion} to address security vulnerabilities`
    );
  } else if (dependencyInfo.isDeprecated) {
    recommendations.push(
      `Replace deprecated dependency ${dependency.name} with a maintained alternative`
    );
  } else if (dependencyInfo.isOutdated) {
    recommendations.push(
      `Update ${dependency.name} from ${dependency.version} to ${dependencyInfo.latestVersion}`
    );
  }
  
  if (dependencyInfo.licenseInfo && !dependencyInfo.licenseInfo.isApproved) {
    recommendations.push(
      `Review license compliance issue with ${dependency.name} (${dependencyInfo.licenseInfo.name})`
    );
  }
  
  if (dependencyInfo.isUnused) {
    recommendations.push(
      `Remove unused dependency ${dependency.name}`
    );
  }
  
  if (recommendations.length === 0) {
    recommendations.push(`No immediate action required for ${dependency.name} ${dependency.version}`);
  }
  
  return recommendations.join('. ');
}

/**
 * Generate tags for categorizing issues
 */
function generateTags(
  type: string,
  isDev: boolean,
  isOutdated: boolean,
  isDeprecated: boolean,
  hasVulnerabilities: boolean,
  isUnused?: boolean
): string[] {
  const tags: string[] = [type];
  
  if (isDev) tags.push('dev-dependency');
  if (isOutdated) tags.push('outdated');
  if (isDeprecated) tags.push('deprecated');
  if (hasVulnerabilities) tags.push('security');
  if (isUnused) tags.push('unused');
  
  return tags;
}

/**
 * Get highest severity from vulnerabilities
 */
function getHighestSeverity(vulnerabilities: VulnerabilityInfo[]): 'critical' | 'high' | 'medium' | 'low' | 'none' {
  if (vulnerabilities.length === 0) return 'none';
  
  const severityRanking = {
    'critical': 4,
    'high': 3,
    'medium': 2,
    'low': 1,
    'none': 0
  };
  
  let highestSeverity = 'none';
  
  for (const vuln of vulnerabilities) {
    if (severityRanking[vuln.severity] > severityRanking[highestSeverity as keyof typeof severityRanking]) {
      highestSeverity = vuln.severity;
    }
  }
  
  return highestSeverity as 'critical' | 'high' | 'medium' | 'low' | 'none';
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
    parts[partToIncrement] = String(partValue + 1 + Math.floor(Math.random() * 3));
    
    return parts.join('.');
  } catch (error) {
    return `${version}.1`; // Fallback
  }
}

/**
 * Helper function to determine if a dependency is deprecated
 */
function isDeprecated(name: string): boolean {
  // Mock logic to determine if deprecated
  // In a real implementation, this would query registries
  const deprecatedPackages = [
    'request', 'gulp', 'left-pad', 'node-sass', 'coffeescript',
    'fibers', 'formidable', 'phantomjs', 'jade', 'express-generator',
    'backbone', 'bower', 'grunt', 'require-uncached', 'istanbul'
  ];
  
  return deprecatedPackages.includes(name.toLowerCase()) || 
         name.toLowerCase().includes('deprecated') || 
         Math.random() < 0.05; // 5% chance of being deprecated for demo
}

/**
 * Helper function to determine if a package has vulnerabilities
 */
function isVulnerable(name: string): boolean {
  // Mock logic to determine if vulnerable
  // In a real implementation, this would query security databases
  const vulnerablePackages = [
    'axios', 'node-fetch', 'lodash', 'log4j', 'jquery',
    'moment', 'async', 'express', 'react-dom', 'minimist',
    'underscore', 'handlebars', 'angular', 'bootstrap'
  ];
  
  return vulnerablePackages.includes(name.toLowerCase()) || 
         name.toLowerCase().includes('vulnerable') || 
         Math.random() < 0.1; // 10% chance of being vulnerable for demo
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
    'remote code execution',
    'privilege escalation',
    'denial of service',
    'information disclosure',
    'cross-site scripting',
    'SQL injection',
    'memory corruption',
    'buffer overflow',
    'prototype pollution',
    'directory traversal',
    'regular expression denial of service',
    'path traversal'
  ];
  return types[Math.floor(Math.random() * types.length)];
}

/**
 * Helper function for getting a random license
 */
function getRandomLicense(): string {
  const licenses = [
    'MIT',
    'Apache-2.0',
    'BSD-3-Clause',
    'BSD-2-Clause',
    'ISC',
    'GPL-3.0',
    'GPL-2.0',
    'LGPL-3.0',
    'MPL-2.0',
    'AGPL-3.0',
    'Unlicense',
    'proprietary'
  ];
  
  const weights = [0.3, 0.2, 0.1, 0.1, 0.1, 0.05, 0.05, 0.03, 0.03, 0.02, 0.01, 0.01];
  const random = Math.random();
  let sum = 0;
  
  for (let i = 0; i < weights.length; i++) {
    sum += weights[i];
    if (random < sum) {
      return licenses[i];
    }
  }
  
  return 'MIT'; // Default fallback
}
