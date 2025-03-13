import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { glob } from 'glob';
import * as child_process from 'child_process';
import { DependencyIssue, VulnerabilityInfo } from '../types/scanning';
import { log } from '../utils/logging';
import { compareVersions } from '../utils/scanner-utils';

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
  
  // Whether to check for license compliance
  checkLicenses: boolean;
  
  // Whether to validate if all dependencies are in use
  checkUnusedDependencies: boolean;
  
  // Skip dependencies with specific names
  ignoreDependencies?: string[];
  
  // Skip dependencies matching specific patterns
  ignorePatterns?: string[];
  
  // API timeout in milliseconds
  apiTimeoutMs: number;
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
    
    // Scan each dependency type
    for (const depType of config.dependencyTypes) {
      try {
        log.info(`Scanning ${depType} dependencies`);
        
        let dependencies: Dependency[] = [];
        
        // Get dependencies for this type
        switch (depType) {
          case 'npm':
            dependencies = await scanNpmDependencies(config.rootDirectory, config.offlineMode);
            break;
          case 'pip':
            dependencies = await scanPipDependencies(config.rootDirectory, config.offlineMode);
            break;
          case 'gem':
            dependencies = await scanGemDependencies(config.rootDirectory, config.offlineMode);
            break;
          case 'composer':
            dependencies = await scanComposerDependencies(config.rootDirectory, config.offlineMode);
            break;
          case 'maven':
            dependencies = await scanMavenDependencies(config.rootDirectory, config.offlineMode);
            break;
          case 'gradle':
            dependencies = await scanGradleDependencies(config.rootDirectory, config.offlineMode);
            break;
          case 'nuget':
            dependencies = await scanNuGetDependencies(config.rootDirectory, config.offlineMode);
            break;
          case 'cargo':
            dependencies = await scanCargoDependencies(config.rootDirectory, config.offlineMode);
            break;
          case 'go':
            dependencies = await scanGoDependencies(config.rootDirectory, config.offlineMode);
            break;
        }
        
        log.info(`Found ${dependencies.length} ${depType} dependencies`);
        
        // Process each dependency
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
            
            // Check if outdated
            if (dependency.currentVersion && dependency.latestVersion) {
              const isOutdated = compareVersions(dependency.currentVersion, dependency.latestVersion) < 0;
              
              if (!isOutdated) {
                log.info(`Dependency ${dependency.name} is up to date`);
                continue;
              }
              
              // Check for vulnerabilities if configured
              let vulnerabilities: VulnerabilityInfo[] = [];
              
              if (config.checkVulnerabilities) {
                vulnerabilities = await getDependencyVulnerabilities(
                  dependency.name,
                  dependency.currentVersion,
                  dependency.type
                );
              }
              
              // Check if dependency is deprecated or abandoned
              const isDeprecated = await checkIfDeprecated(dependency.name, dependency.type);
              
              // Check license compliance if configured
              let licenseIssue = null;
              
              if (config.checkLicenses) {
                licenseIssue = await checkLicenseCompliance(dependency.name, dependency.type);
              }
              
              // Check if unused if configured
              let isUnused = false;
              
              if (config.checkUnusedDependencies) {
                isUnused = await checkIfUnused(
                  dependency.name,
                  dependency.type,
                  config.rootDirectory
                );
              }
              
              // Create issue
              const issue: DependencyIssue = {
                name: dependency.name,
                type: dependency.type,
                currentVersion: dependency.currentVersion,
                latestVersion: dependency.latestVersion,
                isOutdated: true,
                isDeprecated,
                location: dependency.location,
                detectedAt: new Date()
              };
              
              // Add optional information
              if (vulnerabilities.length > 0) {
                issue.vulnerabilities = vulnerabilities;
                issue.securityImpact = Math.max(...vulnerabilities.map(v => securityImpactFromSeverity(v.severity)));
              }
              
              if (licenseIssue) {
                issue.licenseIssue = licenseIssue;
              }
              
              if (isUnused) {
                issue.isUnused = true;
              }
              
              // Add recommendation
              issue.recommendation = generateRecommendation(
                dependency,
                isOutdated,
                isDeprecated,
                vulnerabilities.length > 0,
                isUnused
              );
              
              // Add to issues list
              issues.push(issue);
              log.info(`Added issue for dependency ${dependency.name} ${dependency.currentVersion}`);
            }
          } catch (depError) {
            log.warn(`Error processing dependency: ${dependency.name}`, { error: depError });
          }
        }
      } catch (typeError) {
        log.error(`Error scanning ${depType} dependencies`, { error: typeError });
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
 * Dependency information
 */
interface Dependency {
  // Dependency name
  name: string;
  
  // Current version
  currentVersion?: string;
  
  // Latest available version
  latestVersion?: string;
  
  // Dependency type
  type: 'npm' | 'pip' | 'gem' | 'composer' | 'maven' | 'gradle' | 'nuget' | 'cargo' | 'go';
  
  // Location in the project
  location: string;
  
  // Whether it's a development dependency
  isDev?: boolean;
  
  // Whether it's a direct or transitive dependency
  isDirect?: boolean;
  
  // License information
  license?: string;
}

/**
 * Scan for NPM dependencies
 */
async function scanNpmDependencies(
  rootDirectory: string,
  offlineMode: boolean
): Promise<Dependency[]> {
  try {
    log.info('Scanning NPM dependencies');
    const dependencies: Dependency[] = [];
    
    // Find all package.json files
    const packageJsonPaths = await glob(path.join(rootDirectory, '**/package.json'), {
      ignore: ['**/node_modules/**']
    });
    
    log.info(`Found ${packageJsonPaths.length} package.json files`);
    
    // Process each package.json
    for (const packageJsonPath of packageJsonPaths) {
      try {
        const content = await readFileAsync(packageJsonPath, 'utf8');
        const packageJson = JSON.parse(content);
        
        // Process production dependencies
        if (packageJson.dependencies) {
          for (const [name, version] of Object.entries(packageJson.dependencies)) {
            try {
              const cleanVersion = (version as string).replace(/^[^0-9]*/, '');
              
              // Get latest version (if online)
              let latestVersion = cleanVersion;
              
              if (!offlineMode) {
                try {
                  const { stdout } = await execAsync(`npm view ${name} version`);
                  latestVersion = stdout.trim();
                } catch (npmError) {
                  log.warn(`Error getting latest version for ${name}`, { error: npmError });
                }
              }
              
              dependencies.push({
                name,
                currentVersion: cleanVersion,
                latestVersion,
                type: 'npm',
                location: packageJsonPath,
                isDev: false,
                isDirect: true
              });
            } catch (depError) {
              log.warn(`Error processing NPM dependency: ${name}`, { error: depError });
            }
          }
        }
        
        // Process dev dependencies
        if (packageJson.devDependencies) {
          for (const [name, version] of Object.entries(packageJson.devDependencies)) {
            try {
              const cleanVersion = (version as string).replace(/^[^0-9]*/, '');
              
              // Get latest version (if online)
              let latestVersion = cleanVersion;
              
              if (!offlineMode) {
                try {
                  const { stdout } = await execAsync(`npm view ${name} version`);
                  latestVersion = stdout.trim();
                } catch (npmError) {
                  log.warn(`Error getting latest version for ${name}`, { error: npmError });
                }
              }
              
              dependencies.push({
                name,
                currentVersion: cleanVersion,
                latestVersion,
                type: 'npm',
                location: packageJsonPath,
                isDev: true,
                isDirect: true
              });
            } catch (depError) {
              log.warn(`Error processing NPM dev dependency: ${name}`, { error: depError });
            }
          }
        }
      } catch (fileError) {
        log.warn(`Error processing package.json: ${packageJsonPath}`, { error: fileError });
      }
    }
    
    return dependencies;
  } catch (error) {
    log.error('Error scanning NPM dependencies', { error });
    return [];
  }
}

/**
 * Scan for Python pip dependencies
 */
async function scanPipDependencies(
  rootDirectory: string,
  offlineMode: boolean
): Promise<Dependency[]> {
  try {
    log.info('Scanning pip dependencies');
    const dependencies: Dependency[] = [];
    
    // Find all requirements.txt files and setup.py files
    const requirementsPaths = await glob(path.join(rootDirectory, '**/requirements*.txt'), {
      ignore: ['**/venv/**', '**/.venv/**', '**/.env/**']
    });
    
    const setupPyPaths = await glob(path.join(rootDirectory, '**/setup.py'), {
      ignore: ['**/venv/**', '**/.venv/**', '**/.env/**']
    });
    
    log.info(`Found ${requirementsPaths.length} requirements files and ${setupPyPaths.length} setup.py files`);
    
    // Process requirements.txt files
    for (const requirementsPath of requirementsPaths) {
      try {
        const content = await readFileAsync(requirementsPath, 'utf8');
        const lines = content.split('\n');
        
        for (const line of lines) {
          // Skip comments and empty lines
          if (line.trim().startsWith('#') || !line.trim()) {
            continue;
          }
          
          // Extract package name and version
          const matches = line.match(/^([a-zA-Z0-9_.-]+)(?:[=<>~!]+([0-9a-zA-Z.]+))?/);
          
          if (matches) {
            const name = matches[1];
            const version = matches[2] || '';
            
            // Get latest version (if online)
            let latestVersion = version;
            
            if (!offlineMode) {
              try {
                const { stdout } = await execAsync(`pip index versions ${name} --limit 1`);
                const versionMatch = stdout.match(/([0-9]+\.[0-9]+\.[0-9]+)/);
                if (versionMatch) {
                  latestVersion = versionMatch[1];
                }
              } catch (pipError) {
                log.warn(`Error getting latest version for ${name}`, { error: pipError });
              }
            }
            
            dependencies.push({
              name,
              currentVersion: version,
              latestVersion,
              type: 'pip',
              location: requirementsPath,
              isDirect: true
            });
          }
        }
      } catch (fileError) {
        log.warn(`Error processing requirements file: ${requirementsPath}`, { error: fileError });
      }
    }
    
    return dependencies;
  } catch (error) {
    log.error('Error scanning pip dependencies', { error });
    return [];
  }
}

/**
 * Scan for Ruby gem dependencies
 */
async function scanGemDependencies(
  rootDirectory: string,
  offlineMode: boolean
): Promise<Dependency[]> {
  try {
    log.info('Scanning Ruby gem dependencies');
    const dependencies: Dependency[] = [];
    
    // Find all Gemfile files
    const gemfilePaths = await glob(path.join(rootDirectory, '**/Gemfile'), {
      ignore: ['**/vendor/**']
    });
    
    log.info(`Found ${gemfilePaths.length} Gemfile files`);
    
    // Process each Gemfile
    for (const gemfilePath of gemfilePaths) {
      try {
        const content = await readFileAsync(gemfilePath, 'utf8');
        const lines = content.split('\n');
        
        for (const line of lines) {
          // Skip comments and empty lines
          if (line.trim().startsWith('#') || !line.trim()) {
            continue;
          }
          
          // Extract gem declarations
          const matches = line.match(/gem\s+['"]([\w-]+)['"](?:,\s*['"]?([^'"]+)['"]?)?/);
          
          if (matches) {
            const name = matches[1];
            let version = matches[2] || '';
            
            // Clean version string
            version = version.replace(/^[^0-9]*/, '').replace(/[^0-9.]*$/, '');
            
            // Get latest version (if online)
            let latestVersion = version;
            
            if (!offlineMode) {
              try {
                const { stdout } = await execAsync(`gem info ${name} -r`);
                const versionMatch = stdout.match(/([0-9]+\.[0-9]+\.[0-9]+)/);
                if (versionMatch) {
                  latestVersion = versionMatch[1];
                }
              } catch (gemError) {
                log.warn(`Error getting latest version for ${name}`, { error: gemError });
              }
            }
            
            dependencies.push({
              name,
              currentVersion: version,
              latestVersion,
              type: 'gem',
              location: gemfilePath,
              isDirect: true
            });
          }
        }
      } catch (fileError) {
        log.warn(`Error processing Gemfile: ${gemfilePath}`, { error: fileError });
      }
    }
    
    return dependencies;
  } catch (error) {
    log.error('Error scanning gem dependencies', { error });
    return [];
  }
}

/**
 * Scan for PHP Composer dependencies
 */
async function scanComposerDependencies(
  rootDirectory: string,
  offlineMode: boolean
): Promise<Dependency[]> {
  // Simplified for this example
  return [];
}

/**
 * Scan for Maven dependencies
 */
async function scanMavenDependencies(
  rootDirectory: string,
  offlineMode: boolean
): Promise<Dependency[]> {
  // Simplified for this example
  return [];
}

/**
 * Scan for Gradle dependencies
 */
async function scanGradleDependencies(
  rootDirectory: string,
  offlineMode: boolean
): Promise<Dependency[]> {
  // Simplified for this example
  return [];
}

/**
 * Scan for NuGet dependencies
 */
async function scanNuGetDependencies(
  rootDirectory: string,
  offlineMode: boolean
): Promise<Dependency[]> {
  // Simplified for this example
  return [];
}

/**
 * Scan for Rust Cargo dependencies
 */
async function scanCargoDependencies(
  rootDirectory: string,
  offlineMode: boolean
): Promise<Dependency[]> {
  // Simplified for this example
  return [];
}

/**
 * Scan for Go dependencies
 */
async function scanGoDependencies(
  rootDirectory: string,
  offlineMode: boolean
): Promise<Dependency[]> {
  // Simplified for this example
  return [];
}

/**
 * Get vulnerabilities for a dependency
 */
async function getDependencyVulnerabilities(
  name: string,
  version: string,
  type: string
): Promise<VulnerabilityInfo[]> {
  try {
    // In a real implementation, this would query a vulnerability database
    // For this example, we'll return a hardcoded vulnerability for one dependency
    if (name === 'lodash' && type === 'npm' && compareVersions(version, '4.17.20') < 0) {
      return [
        {
          id: 'CVE-2021-23337',
          severity: 'high',
          cvssScore: 7.2,
          title: 'Prototype Pollution in Lodash',
          description: 'Lodash versions prior to 4.17.20 are vulnerable to prototype pollution via methods such as zipObjectDeep, merge, etc.',
          infoUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337',
          publishedDate: new Date('2021-02-15'),
          affectedVersions: '<4.17.20',
          patchedVersions: '>=4.17.20',
          recommendation: 'Upgrade to lodash 4.17.20 or newer'
        }
      ];
    }
    
    return [];
  } catch (error) {
    log.warn(`Error getting vulnerabilities for dependency ${name} ${version}`, { error });
    return [];
  }
}

/**
 * Check if a dependency is deprecated or abandoned
 */
async function checkIfDeprecated(
  name: string,
  type: string
): Promise<boolean> {
  // In a real implementation, this would query package registries
  // For this example, we'll return a hardcoded response for one dependency
  return name === 'request' && type === 'npm';
}

/**
 * Check license compliance for a dependency
 */
async function checkLicenseCompliance(
  name: string,
  type: string
): Promise<{ issue: string; severity: 'low' | 'medium' | 'high' } | null> {
  // In a real implementation, this would check against a license policy
  // For this example, we'll return a hardcoded response for one dependency
  if (name === 'problematic-license-lib' && type === 'npm') {
    return {
      issue: 'License AGPL-3.0 may not be compatible with your usage',
      severity: 'high'
    };
  }
  
  return null;
}

/**
 * Check if a dependency is unused in the project
 */
async function checkIfUnused(
  name: string,
  type: string,
  rootDirectory: string
): Promise<boolean> {
  // In a real implementation, this would scan source code for usage
  // For this example, we'll return a hardcoded response
  return false;
}

/**
 * Generate a recommendation for addressing a dependency issue
 */
function generateRecommendation(
  dependency: Dependency,
  isOutdated: boolean,
  isDeprecated: boolean,
  hasVulnerabilities: boolean,
  isUnused: boolean
): string {
  const recommendations: string[] = [];
  
  if (isOutdated) {
    recommendations.push(`Update ${dependency.name} from ${dependency.currentVersion} to ${dependency.latestVersion}`);
  }
  
  if (isDeprecated) {
    recommendations.push(`Replace deprecated dependency ${dependency.name} with an actively maintained alternative`);
  }
  
  if (hasVulnerabilities) {
    recommendations.push(`Address security vulnerabilities by updating ${dependency.name}`);
  }
  
  if (isUnused) {
    recommendations.push(`Remove unused dependency ${dependency.name}`);
  }
  
  // Return combined recommendations
  return recommendations.join('. ');
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
