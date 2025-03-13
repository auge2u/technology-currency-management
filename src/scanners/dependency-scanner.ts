import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { exec } from 'child_process';
import { glob } from 'glob';
import { log } from '../utils/logging';
import { DependencyIssue, ScannerConfig } from '../types/scanning';

const readFileAsync = promisify(fs.readFile);
const execAsync = promisify(exec);

/**
 * Configuration specific to dependency scanning
 */
export interface DependencyScannerConfig extends ScannerConfig {
  // Package managers to include in scan
  packageManagers?: Array<'npm' | 'pip' | 'maven' | 'gradle' | 'nuget'>;
  
  // Whether to only check direct dependencies (vs. transitive)
  directDependenciesOnly?: boolean;
  
  // Maximum depth for transitive dependencies
  maxTransitiveDepth?: number;
  
  // Whether to check for vulnerabilities
  checkVulnerabilities?: boolean;
  
  // Whether to assess impact of updates
  assessUpdateImpact?: boolean;
  
  // Custom vulnerability database paths
  vulnerabilityDbPaths?: {
    npm?: string;
    pip?: string;
    maven?: string;
    gradle?: string;
    nuget?: string;
  };
  
  // Package ranges to exclude
  excludePackages?: string[];
  
  // Whether to auto-generate package lock files if missing
  generateLockFiles?: boolean;
}

/**
 * Information about a dependency
 */
interface DependencyInfo {
  name: string;
  version: string;
  latestVersion?: string;
  packageManager: 'npm' | 'pip' | 'maven' | 'gradle' | 'nuget';
  isDirect: boolean;
  depth?: number;
  dependentFiles: string[];
  path?: string; // Path to the package definition file
  dependencies?: Record<string, string>; // Direct dependencies of this package
  devDependency?: boolean;
  peerDependency?: boolean;
  optionalDependency?: boolean;
  repository?: string;
  vulnerabilities?: {
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    cveIds?: string[];
    fixedInVersion?: string;
    url?: string;
  }[];
  isDeprecated?: boolean;
  deprecationMessage?: string;
  isOutdated?: boolean;
}

/**
 * Main function to scan dependencies
 */
export async function scanDependencies(
  config: DependencyScannerConfig
): Promise<DependencyIssue[]> {
  try {
    log.info('Starting dependency scanner');
    const issues: DependencyIssue[] = [];
    
    // Determine which package managers to scan
    const packageManagers = config.packageManagers || ['npm', 'pip', 'maven', 'gradle', 'nuget'];
    log.info(`Scanning for dependencies using: ${packageManagers.join(', ')}`);
    
    // Collect dependencies from all package managers
    const dependencies: DependencyInfo[] = [];
    
    for (const manager of packageManagers) {
      try {
        log.info(`Collecting ${manager} dependencies`);
        const managerDeps = await collectDependencies(manager, config);
        dependencies.push(...managerDeps);
        log.info(`Found ${managerDeps.length} ${manager} dependencies`);
      } catch (managerError) {
        log.error(`Error collecting ${manager} dependencies`, { error: managerError });
      }
    }
    
    log.info(`Found total of ${dependencies.length} dependencies to analyze`);
    
    // Filter dependencies based on configuration
    let filteredDeps = dependencies;
    
    // Filter direct vs. transitive dependencies
    if (config.directDependenciesOnly) {
      filteredDeps = filteredDeps.filter(dep => dep.isDirect);
      log.info(`Filtered to ${filteredDeps.length} direct dependencies`);
    } else if (config.maxTransitiveDepth) {
      filteredDeps = filteredDeps.filter(dep => 
        dep.isDirect || (dep.depth !== undefined && dep.depth <= config.maxTransitiveDepth!)
      );
      log.info(`Filtered to ${filteredDeps.length} dependencies within depth ${config.maxTransitiveDepth}`);
    }
    
    // Process each dependency
    for (const dep of filteredDeps) {
      try {
        // Skip excluded packages
        if (config.excludePackages?.some(pattern => {
          // Handle glob patterns like "eslint-*"
          if (pattern.includes('*')) {
            const regexPattern = pattern
              .replace(/\./g, '\\.')
              .replace(/\*/g, '.*');
            return new RegExp(`^${regexPattern}$`).test(dep.name);
          }
          return pattern === dep.name;
        })) {
          continue;
        }
        
        log.info(`Checking dependency: ${dep.name}@${dep.version} (${dep.packageManager})`);
        
        // Update dependency with latest version info
        await checkDependencyForIssues(dep, config);
        
        // Create issue for problematic dependencies
        if (dep.isOutdated || 
            (dep.vulnerabilities && dep.vulnerabilities.length > 0) || 
            dep.isDeprecated) {
          
          const issue: DependencyIssue = {
            detectedAt: new Date(),
            packageName: dep.name,
            currentVersion: dep.version,
            latestVersion: dep.latestVersion,
            packageManager: dep.packageManager,
            isDirect: dep.isDirect,
            isOutdated: dep.isOutdated || false,
            isVulnerable: (dep.vulnerabilities && dep.vulnerabilities.length > 0) || false,
            vulnerabilities: dep.vulnerabilities || [],
            dependentFiles: dep.dependentFiles,
            updateImpact: await assessUpdateImpact(dep, config),
            riskLevel: calculateRiskLevel(dep),
            recommendation: generateRecommendation(dep),
            tags: generateTags(dep)
          };
          
          issues.push(issue);
        }
      } catch (depError) {
        log.error(`Error checking dependency ${dep.name}`, { error: depError });
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
 * Collect dependencies for a specific package manager
 */
async function collectDependencies(
  packageManager: 'npm' | 'pip' | 'maven' | 'gradle' | 'nuget',
  config: DependencyScannerConfig
): Promise<DependencyInfo[]> {
  switch (packageManager) {
    case 'npm':
      return collectNpmDependencies(config);
    case 'pip':
      return collectPipDependencies(config);
    case 'maven':
      return collectMavenDependencies(config);
    case 'gradle':
      return collectGradleDependencies(config);
    case 'nuget':
      return collectNugetDependencies(config);
    default:
      return [];
  }
}

/**
 * Collect NPM dependencies
 */
async function collectNpmDependencies(
  config: DependencyScannerConfig
): Promise<DependencyInfo[]> {
  const dependencies: DependencyInfo[] = [];
  
  try {
    // Find all package.json files
    const packageJsonPaths = await glob('**/package.json', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/node_modules/**',
        '**/bower_components/**',
        '**/dist/**',
        '**/build/**'
      ]
    });
    
    log.info(`Found ${packageJsonPaths.length} package.json files`);
    
    // Process each package.json file
    for (const packageJsonPath of packageJsonPaths) {
      try {
        const packageDirPath = path.dirname(packageJsonPath);
        const packageJson = JSON.parse(await readFileAsync(packageJsonPath, 'utf8'));
        
        // Direct dependencies from different types
        const directDeps = {
          ...Object.entries(packageJson.dependencies || {}).reduce(
            (acc, [name, version]) => ({ ...acc, [name]: { version, type: 'dependency' } }),
            {}
          ),
          ...Object.entries(packageJson.devDependencies || {}).reduce(
            (acc, [name, version]) => ({ ...acc, [name]: { version, type: 'devDependency' } }),
            {}
          ),
          ...Object.entries(packageJson.peerDependencies || {}).reduce(
            (acc, [name, version]) => ({ ...acc, [name]: { version, type: 'peerDependency' } }),
            {}
          ),
          ...Object.entries(packageJson.optionalDependencies || {}).reduce(
            (acc, [name, version]) => ({ ...acc, [name]: { version, type: 'optionalDependency' } }),
            {}
          )
        };
        
        // Add direct dependencies
        for (const [name, info] of Object.entries(directDeps)) {
          const depInfo: DependencyInfo = {
            name,
            version: String(info.version).replace(/[^0-9.]/g, ''),
            packageManager: 'npm',
            isDirect: true,
            depth: 0,
            dependentFiles: [packageJsonPath],
            path: packageJsonPath,
            devDependency: info.type === 'devDependency',
            peerDependency: info.type === 'peerDependency',
            optionalDependency: info.type === 'optionalDependency'
          };
          
          dependencies.push(depInfo);
        }
        
        // If not limiting to direct dependencies, check for locked dependencies
        if (!config.directDependenciesOnly) {
          // Try package-lock.json first
          const packageLockPath = path.join(packageDirPath, 'package-lock.json');
          if (fs.existsSync(packageLockPath)) {
            const lockFile = JSON.parse(await readFileAsync(packageLockPath, 'utf8'));
            
            if (lockFile.dependencies) {
              addTransitiveDepsFromNpmLock(lockFile.dependencies, dependencies, packageJsonPath, 1);
            }
          }
          // Try npm-shrinkwrap.json next
          else {
            const shrinkwrapPath = path.join(packageDirPath, 'npm-shrinkwrap.json');
            if (fs.existsSync(shrinkwrapPath)) {
              const shrinkwrap = JSON.parse(await readFileAsync(shrinkwrapPath, 'utf8'));
              
              if (shrinkwrap.dependencies) {
                addTransitiveDepsFromNpmLock(shrinkwrap.dependencies, dependencies, packageJsonPath, 1);
              }
            }
            // Try yarn.lock next
            else {
              const yarnLockPath = path.join(packageDirPath, 'yarn.lock');
              if (fs.existsSync(yarnLockPath)) {
                // Yarn lock files are not JSON, but we can still extract some info
                // A proper parser would be more accurate
                const yarnLockContent = await readFileAsync(yarnLockPath, 'utf8');
                addTransitiveDepsFromYarnLock(yarnLockContent, dependencies, packageJsonPath);
              }
              // Try to generate a package lock if configured
              else if (config.generateLockFiles) {
                try {
                  await execAsync('npm install --package-lock-only', { cwd: packageDirPath });
                  
                  if (fs.existsSync(packageLockPath)) {
                    const lockFile = JSON.parse(await readFileAsync(packageLockPath, 'utf8'));
                    
                    if (lockFile.dependencies) {
                      addTransitiveDepsFromNpmLock(lockFile.dependencies, dependencies, packageJsonPath, 1);
                    }
                  }
                } catch (npmError) {
                  log.warn(`Could not generate package-lock.json for ${packageDirPath}`, { error: npmError });
                }
              }
            }
          }
        }
      } catch (packageJsonError) {
        log.warn(`Error processing package.json at ${packageJsonPath}`, { error: packageJsonError });
      }
    }
  } catch (error) {
    log.error('Error collecting npm dependencies', { error });
  }
  
  return dependencies;
}

/**
 * Add transitive dependencies from NPM lock file
 */
function addTransitiveDepsFromNpmLock(
  dependencies: Record<string, any>,
  depInfoList: DependencyInfo[],
  packageJsonPath: string,
  depth: number
) {
  for (const [name, info] of Object.entries(dependencies)) {
    // Skip if already added as direct dependency
    if (depInfoList.some(d => d.name === name && d.isDirect && d.path === packageJsonPath)) {
      continue;
    }
    
    // New transitive dependency
    const depInfo: DependencyInfo = {
      name,
      version: info.version,
      packageManager: 'npm',
      isDirect: false,
      depth,
      dependentFiles: [packageJsonPath],
      path: packageJsonPath
    };
    
    // Avoid duplicates by checking if this exact dependency is already in the list
    if (!depInfoList.some(d => d.name === name && d.version === info.version && 
                           d.packageManager === 'npm' && d.path === packageJsonPath)) {
      depInfoList.push(depInfo);
    } else {
      // Update existing entry's dependent files if needed
      const existing = depInfoList.find(d => d.name === name && d.version === info.version && 
                                        d.packageManager === 'npm' && d.path === packageJsonPath);
      if (existing && !existing.dependentFiles.includes(packageJsonPath)) {
        existing.dependentFiles.push(packageJsonPath);
      }
    }
    
    // Recursively process nested dependencies
    if (info.dependencies && depth < (depInfoList.length > 1000 ? 2 : 5)) { // Limit depth for large projects
      addTransitiveDepsFromNpmLock(info.dependencies, depInfoList, packageJsonPath, depth + 1);
    }
  }
}

/**
 * Add transitive dependencies from Yarn lock file
 * This is a simplified implementation and doesn't handle all yarn.lock formats
 */
function addTransitiveDepsFromYarnLock(
  yarnLockContent: string,
  depInfoList: DependencyInfo[],
  packageJsonPath: string
) {
  // Very basic yarn.lock parsing - a proper parser would be better
  const lines = yarnLockContent.split('\n');
  let currentDep: {name?: string, version?: string} = {};
  
  for (const line of lines) {
    // Each dependency block starts with the name and requested version(s)
    if (line.match(/^"?([^@"]+)@/) && !line.includes('integrity') && !line.includes('resolved')) {
      const match = line.match(/^"?([^@"]+)@/);
      if (match) {
        currentDep = { name: match[1] };
      }
    }
    // Get actual version
    else if (line.match(/^  version/) && currentDep.name) {
      const versionMatch = line.match(/version "?([^"]+)"?/);
      if (versionMatch) {
        currentDep.version = versionMatch[1];
        
        // Skip if already added as direct dependency
        if (!depInfoList.some(d => d.name === currentDep.name && d.isDirect && d.path === packageJsonPath)) {
          // New transitive dependency
          const depInfo: DependencyInfo = {
            name: currentDep.name,
            version: currentDep.version,
            packageManager: 'npm',
            isDirect: false,
            depth: 1, // Simplified, all considered depth 1
            dependentFiles: [packageJsonPath],
            path: packageJsonPath
          };
          
          // Add if not already in the list
          if (!depInfoList.some(d => d.name === currentDep.name && d.version === currentDep.version && 
                                d.packageManager === 'npm' && d.path === packageJsonPath)) {
            depInfoList.push(depInfo);
          } else {
            // Update existing entry if needed
            const existing = depInfoList.find(d => d.name === currentDep.name && 
                                           d.version === currentDep.version && 
                                           d.packageManager === 'npm' && 
                                           d.path === packageJsonPath);
            if (existing && !existing.dependentFiles.includes(packageJsonPath)) {
              existing.dependentFiles.push(packageJsonPath);
            }
          }
        }
        
        currentDep = {}; // Reset for next dependency
      }
    }
  }
}

/**
 * Collect Python (pip) dependencies
 */
async function collectPipDependencies(
  config: DependencyScannerConfig
): Promise<DependencyInfo[]> {
  const dependencies: DependencyInfo[] = [];
  
  try {
    // Find all requirements.txt files
    const reqFilePaths = await glob('**/requirements{,.*}.txt', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/venv/**',
        '**/.venv/**',
        '**/env/**',
        '**/.env/**',
        '**/dist/**',
        '**/build/**'
      ]
    });
    
    // Also find setup.py files
    const setupPyPaths = await glob('**/setup.py', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/venv/**',
        '**/.venv/**',
        '**/env/**',
        '**/.env/**',
        '**/dist/**',
        '**/build/**'
      ]
    });
    
    // Process requirements.txt files
    for (const reqFilePath of reqFilePaths) {
      try {
        const content = await readFileAsync(reqFilePath, 'utf8');
        const lines = content.split('\n');
        
        for (const line of lines) {
          // Skip comments and empty lines
          if (line.trim().startsWith('#') || !line.trim()) {
            continue;
          }
          
          // Parse the requirement line
          const reqLine = line.split('#')[0].trim(); // Remove inline comments
          
          // Extract package name and version
          const parts = reqLine.split('==');
          if (parts.length >= 2) {
            const name = parts[0].trim();
            const version = parts[1].trim().split(/[<>]=?/)[0].trim();
            
            // Add to dependencies list
            dependencies.push({
              name,
              version,
              packageManager: 'pip',
              isDirect: true,
              depth: 0,
              dependentFiles: [reqFilePath],
              path: reqFilePath
            });
          } else {
            // Handle requirements without version
            const match = reqLine.match(/^([^<>=~]+)/);
            if (match) {
              const name = match[1].trim();
              
              dependencies.push({
                name,
                version: 'unknown',
                packageManager: 'pip',
                isDirect: true,
                depth: 0,
                dependentFiles: [reqFilePath],
                path: reqFilePath
              });
            }
          }
        }
      } catch (reqFileError) {
        log.warn(`Error processing requirements file ${reqFilePath}`, { error: reqFileError });
      }
    }
    
    // Process setup.py files for install_requires
    for (const setupPyPath of setupPyPaths) {
      try {
        const content = await readFileAsync(setupPyPath, 'utf8');
        
        // Find install_requires section
        const installReqMatch = content.match(/install_requires\s*=\s*\[([^\]]+)\]/s);
        if (installReqMatch) {
          const requiresList = installReqMatch[1];
          
          // Extract package names
          const packageMatches = requiresList.match(/['"]([^'"]+)['"]\s*,?/g);
          if (packageMatches) {
            for (const packageMatch of packageMatches) {
              const strippedPackage = packageMatch.replace(/['",\s]/g, '');
              
              // Parse for name and version
              const parts = strippedPackage.split('==');
              if (parts.length >= 2) {
                const name = parts[0].trim();
                const version = parts[1].trim().split(/[<>]=?/)[0].trim();
                
                // Add to dependencies list
                dependencies.push({
                  name,
                  version,
                  packageManager: 'pip',
                  isDirect: true,
                  depth: 0,
                  dependentFiles: [setupPyPath],
                  path: setupPyPath
                });
              } else {
                // Handle requirements without version
                const match = strippedPackage.match(/^([^<>=~]+)/);
                if (match) {
                  const name = match[1].trim();
                  
                  dependencies.push({
                    name,
                    version: 'unknown',
                    packageManager: 'pip',
                    isDirect: true,
                    depth: 0,
                    dependentFiles: [setupPyPath],
                    path: setupPyPath
                  });
                }
              }
            }
          }
        }
      } catch (setupPyError) {
        log.warn(`Error processing setup.py ${setupPyPath}`, { error: setupPyError });
      }
    }
    
    // If configured and Python is available, try to get transitive dependencies
    if (!config.directDependenciesOnly && reqFilePaths.length > 0) {
      try {
        for (const reqFilePath of reqFilePaths) {
          const reqDir = path.dirname(reqFilePath);
          
          // Run pip-compile to get the dependency tree
          try {
            await execAsync(`pip-compile --dry-run ${path.basename(reqFilePath)}`, { cwd: reqDir });
          } catch (pipCompileError) {
            log.debug(`pip-compile not available for ${reqFilePath}`);
            continue; // Skip if pip-compile fails
          }
          
          // Run pipdeptree if available
          try {
            const { stdout } = await execAsync('pipdeptree --json', { cwd: reqDir });
            const depsTree = JSON.parse(stdout);
            
            // Process dependency tree
            for (const pkg of depsTree) {
              const directDep = dependencies.find(d => 
                d.name === pkg.package.key && 
                d.packageManager === 'pip' && 
                d.path === reqFilePath
              );
              
              if (directDep && pkg.dependencies) {
                // Process the transitive dependencies
                addPipTransitiveDependencies(pkg.dependencies, dependencies, reqFilePath, 1);
              }
            }
          } catch (pipdeptreeError) {
            log.debug(`pipdeptree not available for ${reqFilePath}`);
          }
        }
      } catch (transitiveError) {
        log.warn('Error collecting transitive pip dependencies', { error: transitiveError });
      }
    }
  } catch (error) {
    log.error('Error collecting pip dependencies', { error });
  }
  
  return dependencies;
}

/**
 * Add transitive dependencies from pip dependency tree
 */
function addPipTransitiveDependencies(
  dependencies: Array<{key: string, package_name: string, installed_version: string, dependencies: any[]}>,
  depInfoList: DependencyInfo[],
  requiredPath: string,
  depth: number
) {
  for (const dep of dependencies) {
    // Skip if already added as direct dependency
    if (depInfoList.some(d => d.name === dep.key && d.isDirect && d.path === requiredPath)) {
      continue;
    }
    
    // New transitive dependency
    const depInfo: DependencyInfo = {
      name: dep.key,
      version: dep.installed_version,
      packageManager: 'pip',
      isDirect: false,
      depth,
      dependentFiles: [requiredPath],
      path: requiredPath
    };
    
    // Add if not already in the list
    if (!depInfoList.some(d => d.name === dep.key && d.version === dep.installed_version && 
                         d.packageManager === 'pip' && d.path === requiredPath)) {
      depInfoList.push(depInfo);
    } else {
      // Update existing entry if needed
      const existing = depInfoList.find(d => d.name === dep.key && 
                                     d.version === dep.installed_version && 
                                     d.packageManager === 'pip' && 
                                     d.path === requiredPath);
      if (existing && !existing.dependentFiles.includes(requiredPath)) {
        existing.dependentFiles.push(requiredPath);
      }
    }
    
    // Recursively process nested dependencies
    if (dep.dependencies && depth < (depInfoList.length > 1000 ? 2 : 5)) { // Limit depth for large projects
      addPipTransitiveDependencies(dep.dependencies, depInfoList, requiredPath, depth + 1);
    }
  }
}

/**
 * Collect Maven dependencies
 */
async function collectMavenDependencies(
  config: DependencyScannerConfig
): Promise<DependencyInfo[]> {
  const dependencies: DependencyInfo[] = [];
  
  try {
    // Find all pom.xml files
    const pomPaths = await glob('**/pom.xml', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/target/**',
        '**/build/**'
      ]
    });
    
    for (const pomPath of pomPaths) {
      try {
        const content = await readFileAsync(pomPath, 'utf8');
        
        // Very basic XML parsing - a proper XML parser would be better
        // Extract dependency elements
        const dependencyMatches = content.match(/<dependency>([\s\S]*?)<\/dependency>/g);
        
        if (dependencyMatches) {
          for (const depMatch of dependencyMatches) {
            const groupIdMatch = depMatch.match(/<groupId>([^<]+)<\/groupId>/);
            const artifactIdMatch = depMatch.match(/<artifactId>([^<]+)<\/artifactId>/);
            const versionMatch = depMatch.match(/<version>([^<]+)<\/version>/);
            const scopeMatch = depMatch.match(/<scope>([^<]+)<\/scope>/);
            
            if (groupIdMatch && artifactIdMatch) {
              const groupId = groupIdMatch[1].trim();
              const artifactId = artifactIdMatch[1].trim();
              const version = versionMatch ? versionMatch[1].trim() : 'unknown';
              const scope = scopeMatch ? scopeMatch[1].trim() : 'compile';
              
              // Maven dependency name format: groupId:artifactId
              const name = `${groupId}:${artifactId}`;
              
              // Add to dependencies list
              dependencies.push({
                name,
                version,
                packageManager: 'maven',
                isDirect: true,
                depth: 0,
                dependentFiles: [pomPath],
                path: pomPath,
                devDependency: scope === 'test',
                optionalDependency: scope === 'provided'
              });
            }
          }
        }
      } catch (pomError) {
        log.warn(`Error processing pom.xml ${pomPath}`, { error: pomError });
      }
    }
    
    // If configured and Maven is available, try to get transitive dependencies
    if (!config.directDependenciesOnly && pomPaths.length > 0) {
      for (const pomPath of pomPaths) {
        try {
          const pomDir = path.dirname(pomPath);
          
          // Run Maven dependency:tree to get transitive dependencies
          try {
            const { stdout } = await execAsync('mvn dependency:tree -DoutputType=text', { cwd: pomDir });
            
            // Parse the dependency tree output
            const lines = stdout.split('\n');
            let currentDepth = 0;
            let depStack: {name: string, version: string, depth: number}[] = [];
            
            for (const line of lines) {
              // Skip until we find the dependency tree section
              if (!line.includes('--- ')) {
                continue;
              }
              
              // Parse the dependency line
              // Format is usually: [INFO] [level]groupId:artifactId:type:version:scope
              const depMatch = line.match(/\[INFO\]\s*(\|\s+)*([+\\-]+-\s+)(.+):(\w+):([^:]+)(?::(\w+))?/);
              
              if (depMatch) {
                const indentLevel = (depMatch[1] || '').split('|').length - 1;
                const groupArtifact = `${depMatch[3]}:${depMatch[4]}`;
                const version = depMatch[5];
                const scope = depMatch[6] || 'compile';
                
                // Direct dependencies were already added from the POM file
                if (indentLevel > 0) {
                  // This is a transitive dependency
                  
                  // Update the stack to maintain proper parent-child relationships
                  while (depStack.length > 0 && depStack[depStack.length - 1].depth >= indentLevel) {
                    depStack.pop();
                  }
                  
                  // Add to dependencies list if not already there
                  if (!dependencies.some(d => d.name === groupArtifact && 
                                        d.version === version && 
                                        d.packageManager === 'maven' && 
                                        d.path === pomPath)) {
                    
                    dependencies.push({
                      name: groupArtifact,
                      version,
                      packageManager: 'maven',
                      isDirect: false,
                      depth: indentLevel,
                      dependentFiles: [pomPath],
                      path: pomPath,
                      devDependency: scope === 'test',
                      optionalDependency: scope === 'provided'
                    });
                  }
                  
                  // Update the stack
                  depStack.push({ name: groupArtifact, version, depth: indentLevel });
                }
              }
            }
          } catch (mvnError) {
            log.debug(`Maven dependency:tree failed for ${pomPath}`, { error: mvnError });
          }
        } catch (transitiveError) {
          log.warn(`Error collecting transitive Maven dependencies for ${pomPath}`, { error: transitiveError });
        }
      }
    }
  } catch (error) {
    log.error('Error collecting Maven dependencies', { error });
  }
  
  return dependencies;
}

/**
 * Collect Gradle dependencies
 */
async function collectGradleDependencies(
  config: DependencyScannerConfig
): Promise<DependencyInfo[]> {
  const dependencies: DependencyInfo[] = [];
  
  try {
    // Find all build.gradle files (both Groovy and Kotlin DSL)
    const gradlePaths = await glob('**/{build.gradle,build.gradle.kts}', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/build/**',
        '**/.gradle/**'
      ]
    });
    
    for (const gradlePath of gradlePaths) {
      try {
        const content = await readFileAsync(gradlePath, 'utf8');
        
        // Extract dependencies from build.gradle
        // This is a simplified approach - a proper Gradle parser would be better
        const dependencyRegexes = [
          // Groovy syntax: implementation 'group:name:version'
          /(?:implementation|api|compile|runtime|testImplementation|testCompile|testRuntime)\s+(?:'|")([^:]+):([^:]+):([^'"]+)(?:'|")/g,
          // Kotlin DSL syntax: implementation("group:name:version")
          /(?:implementation|api|compile|runtime|testImplementation|testCompile|testRuntime)\s*\(\s*(?:'|")([^:]+):([^:]+):([^'"]+)(?:'|")\s*\)/g
        ];
        
        for (const regex of dependencyRegexes) {
          let match;
          while ((match = regex.exec(content)) !== null) {
            const groupId = match[1].trim();
            const artifactId = match[2].trim();
            const version = match[3].trim();
            
            // Gradle dependency name format: groupId:artifactId
            const name = `${groupId}:${artifactId}`;
            
            // Check if the configuration suggests test or optional
            const configType = match[0].includes('test') ? 'test' : 
                               match[0].includes('runtime') ? 'runtime' : 'compile';
            
            // Add to dependencies list
            dependencies.push({
              name,
              version,
              packageManager: 'gradle',
              isDirect: true,
              depth: 0,
              dependentFiles: [gradlePath],
              path: gradlePath,
              devDependency: configType === 'test',
              optionalDependency: configType === 'runtime'
            });
          }
        }
      } catch (gradleError) {
        log.warn(`Error processing build.gradle ${gradlePath}`, { error: gradleError });
      }
    }
    
    // If configured and Gradle is available, try to get transitive dependencies
    if (!config.directDependenciesOnly && gradlePaths.length > 0) {
      for (const gradlePath of gradlePaths) {
        try {
          const gradleDir = path.dirname(gradlePath);
          
          // Create a temporary task to output dependencies if needed
          const tempTaskPath = path.join(gradleDir, 'dependencies-output.gradle');
          
          try {
            // Add the task if it doesn't exist
            const taskContent = `
task printAllDependencies {
  doLast {
    configurations.findAll { it.canBeResolved }.each { config ->
      println "\n--- " + config.name + " dependencies ---"
      config.resolvedConfiguration.lenientConfiguration.allModuleDependencies.each { dep ->
        println "${dep.module.id.group}:${dep.module.id.name}:${dep.module.id.version} (${config.name})"
        dep.children.each { child ->
          println "  ${child.module.id.group}:${child.module.id.name}:${child.module.id.version}"
          printChildren(child, 4)
        }
      }
    }
  }
}

def printChildren(dep, indent) {
  dep.children.each { child ->
    println "${' ' * indent}${child.module.id.group}:${child.module.id.name}:${child.module.id.version}"
    printChildren(child, indent + 2)
  }
}
`;
            
            await fs.promises.writeFile(tempTaskPath, taskContent);
            
            // Run the task
            const { stdout } = await execAsync('./gradlew -q printAllDependencies -I dependencies-output.gradle', { cwd: gradleDir });
            
            // Parse the output
            const lines = stdout.split('\n');
            let currentConfig = '';
            
            for (const line of lines) {
              // Check for configuration section
              const configMatch = line.match(/--- ([\w-]+) dependencies ---/);
              if (configMatch) {
                currentConfig = configMatch[1];
                continue;
              }
              
              // Skip empty lines
              if (!line.trim()) {
                continue;
              }
              
              // Parse dependency line
              const indentLevel = line.search(/\S/) / 2;
              const depMatch = line.trim().match(/([^:]+):([^:]+):([^ ]+)(?: \((.+)\))?/);
              
              if (depMatch) {
                const groupId = depMatch[1].trim();
                const artifactId = depMatch[2].trim();
                const version = depMatch[3].trim();
                const config = depMatch[4] || currentConfig;
                
                // Gradle dependency name format: groupId:artifactId
                const name = `${groupId}:${artifactId}`;
                
                // Skip if already added as direct dependency
                if (indentLevel > 0 && !dependencies.some(d => d.name === name && 
                                                  d.version === version && 
                                                  d.packageManager === 'gradle' && 
                                                  d.path === gradlePath)) {
                  
                  // Add to dependencies list
                  dependencies.push({
                    name,
                    version,
                    packageManager: 'gradle',
                    isDirect: false,
                    depth: indentLevel,
                    dependentFiles: [gradlePath],
                    path: gradlePath,
                    devDependency: config.includes('test'),
                    optionalDependency: config.includes('runtime')
                  });
                }
              }
            }
            
            // Clean up
            await fs.promises.unlink(tempTaskPath).catch(() => {});
          } catch (gradleTaskError) {
            log.debug(`Gradle dependency resolution failed for ${gradlePath}`, { error: gradleTaskError });
          }
        } catch (transitiveError) {
          log.warn(`Error collecting transitive Gradle dependencies for ${gradlePath}`, { error: transitiveError });
        }
      }
    }
  } catch (error) {
    log.error('Error collecting Gradle dependencies', { error });
  }
  
  return dependencies;
}

/**
 * Collect NuGet dependencies
 */
async function collectNugetDependencies(
  config: DependencyScannerConfig
): Promise<DependencyInfo[]> {
  const dependencies: DependencyInfo[] = [];
  
  try {
    // Find all .csproj, .fsproj, and packages.config files
    const projFilePaths = await glob('**/*.{csproj,fsproj}', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/bin/**',
        '**/obj/**',
        '**/build/**'
      ]
    });
    
    const packagesConfigPaths = await glob('**/packages.config', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/bin/**',
        '**/obj/**',
        '**/build/**'
      ]
    });
    
    // Process .csproj and .fsproj files (new PackageReference format)
    for (const projPath of projFilePaths) {
      try {
        const content = await readFileAsync(projPath, 'utf8');
        
        // Extract PackageReference elements
        const packageRefMatches = content.match(/<PackageReference [^>]*>/g);
        
        if (packageRefMatches) {
          for (const pkgRef of packageRefMatches) {
            const includeMatch = pkgRef.match(/Include="([^"]+)"/i);
            const versionMatch = pkgRef.match(/Version="([^"]+)"/i);
            
            if (includeMatch) {
              const name = includeMatch[1].trim();
              const version = versionMatch ? versionMatch[1].trim() : 'unknown';
              
              // Add to dependencies list
              dependencies.push({
                name,
                version,
                packageManager: 'nuget',
                isDirect: true,
                depth: 0,
                dependentFiles: [projPath],
                path: projPath
              });
            }
          }
        }
      } catch (projError) {
        log.warn(`Error processing project file ${projPath}`, { error: projError });
      }
    }
    
    // Process packages.config files (old format)
    for (const pkgConfigPath of packagesConfigPaths) {
      try {
        const content = await readFileAsync(pkgConfigPath, 'utf8');
        
        // Extract package elements
        const packageMatches = content.match(/<package [^>]*>/g);
        
        if (packageMatches) {
          for (const pkg of packageMatches) {
            const idMatch = pkg.match(/id="([^"]+)"/i);
            const versionMatch = pkg.match(/version="([^"]+)"/i);
            
            if (idMatch) {
              const name = idMatch[1].trim();
              const version = versionMatch ? versionMatch[1].trim() : 'unknown';
              
              // Add to dependencies list
              dependencies.push({
                name,
                version,
                packageManager: 'nuget',
                isDirect: true,
                depth: 0,
                dependentFiles: [pkgConfigPath],
                path: pkgConfigPath
              });
            }
          }
        }
      } catch (pkgConfigError) {
        log.warn(`Error processing packages.config ${pkgConfigPath}`, { error: pkgConfigError });
      }
    }
    
    // If configured and dotnet is available, try to get transitive dependencies
    if (!config.directDependenciesOnly && projFilePaths.length > 0) {
      for (const projPath of projFilePaths) {
        try {
          const projDir = path.dirname(projPath);
          
          // Run dotnet list package to get transitive dependencies
          try {
            const { stdout } = await execAsync(`dotnet list ${path.basename(projPath)} package --include-transitive`, { cwd: projDir });
            
            // Parse the output
            const lines = stdout.split('\n');
            let inTransitiveSection = false;
            let currentTopLevel = '';
            
            for (const line of lines) {
              // Look for the transitive dependencies section
              if (line.includes('Transitive Package')) {
                inTransitiveSection = true;
                continue;
              }
              
              // Skip until we get to the transitive section
              if (!inTransitiveSection) {
                continue;
              }
              
              // Parse top-level dependency that has transitives
              const topLevelMatch = line.match(/> ([^ ]+)/);
              if (topLevelMatch) {
                currentTopLevel = topLevelMatch[1].trim();
                continue;
              }
              
              // Parse transitive dependency line
              const depMatch = line.match(/\s+([^ ]+)\s+([^ ]+)/);
              if (depMatch) {
                const name = depMatch[1].trim();
                const version = depMatch[2].trim();
                
                // Add if not already in the list
                if (!dependencies.some(d => d.name === name && 
                                     d.version === version && 
                                     d.packageManager === 'nuget' && 
                                     d.path === projPath)) {
                  
                  dependencies.push({
                    name,
                    version,
                    packageManager: 'nuget',
                    isDirect: false,
                    depth: 1, // Simplified, all considered depth 1
                    dependentFiles: [projPath],
                    path: projPath
                  });
                }
              }
            }
          } catch (dotnetError) {
            log.debug(`dotnet list package failed for ${projPath}`, { error: dotnetError });
          }
        } catch (transitiveError) {
          log.warn(`Error collecting transitive NuGet dependencies for ${projPath}`, { error: transitiveError });
        }
      }
    }
  } catch (error) {
    log.error('Error collecting NuGet dependencies', { error });
  }
  
  return dependencies;
}

/**
 * Check dependencies for issues
 */
async function checkDependencyForIssues(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Check for updates
    await checkForUpdates(dep, config);
    
    // Check for vulnerabilities if configured
    if (config.checkVulnerabilities) {
      await checkForVulnerabilities(dep, config);
    }
    
    // Check if deprecated
    await checkIfDeprecated(dep, config);
  } catch (error) {
    log.warn(`Error checking dependency ${dep.name} for issues`, { error });
  }
}

/**
 * Check if a dependency has updates available
 */
async function checkForUpdates(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Check based on package manager
    switch (dep.packageManager) {
      case 'npm':
        await checkNpmUpdates(dep, config);
        break;
      case 'pip':
        await checkPipUpdates(dep, config);
        break;
      case 'maven':
        await checkMavenUpdates(dep, config);
        break;
      case 'gradle':
        await checkGradleUpdates(dep, config);
        break;
      case 'nuget':
        await checkNugetUpdates(dep, config);
        break;
    }
  } catch (error) {
    log.warn(`Error checking for updates for ${dep.name}`, { error });
  }
}

/**
 * Check for NPM package updates
 */
async function checkNpmUpdates(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use npm registry API to check for latest version
    const { stdout } = await execAsync(`npm view ${dep.name} version --json`);
    
    try {
      const latestVersion = JSON.parse(stdout.trim());
      dep.latestVersion = latestVersion;
      
      // Compare versions to determine if outdated
      if (dep.version !== 'unknown' && dep.version !== latestVersion) {
        // Use semver to compare versions if available
        try {
          const semver = require('semver');
          dep.isOutdated = semver.lt(dep.version, latestVersion);
        } catch (semverError) {
          // Basic version comparison if semver is not available
          dep.isOutdated = dep.version !== latestVersion;
        }
      }
    } catch (jsonError) {
      log.warn(`Error parsing npm view output for ${dep.name}`, { error: jsonError });
    }
  } catch (error) {
    log.warn(`Error checking NPM updates for ${dep.name}`, { error });
  }
}

/**
 * Check for Python package updates
 */
async function checkPipUpdates(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use PyPI API to check for latest version
    const { stdout } = await execAsync(`curl -s https://pypi.org/pypi/${dep.name}/json`);
    
    try {
      const packageInfo = JSON.parse(stdout);
      dep.latestVersion = packageInfo.info.version;
      
      // Compare versions to determine if outdated
      if (dep.version !== 'unknown' && dep.version !== dep.latestVersion) {
        // Basic version comparison
        dep.isOutdated = dep.version !== dep.latestVersion;
      }
    } catch (jsonError) {
      log.warn(`Error parsing PyPI API output for ${dep.name}`, { error: jsonError });
    }
  } catch (error) {
    log.warn(`Error checking Python updates for ${dep.name}`, { error });
  }
}

/**
 * Check for Maven package updates
 */
async function checkMavenUpdates(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Extract groupId and artifactId
    const [groupId, artifactId] = dep.name.split(':');
    
    // Use Maven Central API to check for latest version
    const { stdout } = await execAsync(`curl -s "https://search.maven.org/solrsearch/select?q=g:%22${groupId}%22+AND+a:%22${artifactId}%22&rows=1&wt=json"`);
    
    try {
      const searchResult = JSON.parse(stdout);
      
      if (searchResult.response && searchResult.response.docs && searchResult.response.docs.length > 0) {
        dep.latestVersion = searchResult.response.docs[0].latestVersion;
        
        // Compare versions to determine if outdated
        if (dep.version !== 'unknown' && dep.version !== dep.latestVersion) {
          // Basic version comparison
          dep.isOutdated = dep.version !== dep.latestVersion;
        }
      }
    } catch (jsonError) {
      log.warn(`Error parsing Maven Central API output for ${dep.name}`, { error: jsonError });
    }
  } catch (error) {
    log.warn(`Error checking Maven updates for ${dep.name}`, { error });
  }
}

/**
 * Check for Gradle package updates
 * (Similar to Maven since many Gradle dependencies are from Maven repositories)
 */
async function checkGradleUpdates(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Extract groupId and artifactId
    const [groupId, artifactId] = dep.name.split(':');
    
    // Use Maven Central API to check for latest version
    const { stdout } = await execAsync(`curl -s "https://search.maven.org/solrsearch/select?q=g:%22${groupId}%22+AND+a:%22${artifactId}%22&rows=1&wt=json"`);
    
    try {
      const searchResult = JSON.parse(stdout);
      
      if (searchResult.response && searchResult.response.docs && searchResult.response.docs.length > 0) {
        dep.latestVersion = searchResult.response.docs[0].latestVersion;
        
        // Compare versions to determine if outdated
        if (dep.version !== 'unknown' && dep.version !== dep.latestVersion) {
          // Basic version comparison
          dep.isOutdated = dep.version !== dep.latestVersion;
        }
      }
    } catch (jsonError) {
      log.warn(`Error parsing Maven Central API output for ${dep.name}`, { error: jsonError });
    }
  } catch (error) {
    log.warn(`Error checking Gradle updates for ${dep.name}`, { error });
  }
}

/**
 * Check for NuGet package updates
 */
async function checkNugetUpdates(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use NuGet API to check for latest version
    const { stdout } = await execAsync(`curl -s "https://api.nuget.org/v3-flatcontainer/${dep.name.toLowerCase()}/index.json"`);
    
    try {
      const packageInfo = JSON.parse(stdout);
      
      if (packageInfo.versions && packageInfo.versions.length > 0) {
        // Get the latest non-preview version
        const stableVersions = packageInfo.versions.filter((v: string) => !v.includes('-'));
        dep.latestVersion = stableVersions.length > 0 ? 
          stableVersions[stableVersions.length - 1] : 
          packageInfo.versions[packageInfo.versions.length - 1];
        
        // Compare versions to determine if outdated
        if (dep.version !== 'unknown' && dep.version !== dep.latestVersion) {
          // Basic version comparison
          dep.isOutdated = dep.version !== dep.latestVersion;
        }
      }
    } catch (jsonError) {
      log.warn(`Error parsing NuGet API output for ${dep.name}`, { error: jsonError });
    }
  } catch (error) {
    log.warn(`Error checking NuGet updates for ${dep.name}`, { error });
  }
}

/**
 * Check for vulnerabilities in a dependency
 */
async function checkForVulnerabilities(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Check for vulnerabilities based on package manager
    switch (dep.packageManager) {
      case 'npm':
        await checkNpmVulnerabilities(dep, config);
        break;
      case 'pip':
        await checkPipVulnerabilities(dep, config);
        break;
      case 'maven':
      case 'gradle':
        await checkMavenVulnerabilities(dep, config);
        break;
      case 'nuget':
        await checkNugetVulnerabilities(dep, config);
        break;
    }
  } catch (error) {
    log.warn(`Error checking vulnerabilities for ${dep.name}`, { error });
  }
}

/**
 * Check for vulnerabilities in NPM packages
 */
async function checkNpmVulnerabilities(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Check custom database first if configured
    if (config.vulnerabilityDbPaths?.npm && fs.existsSync(config.vulnerabilityDbPaths.npm)) {
      try {
        const vulnDb = JSON.parse(await readFileAsync(config.vulnerabilityDbPaths.npm, 'utf8'));
        
        if (vulnDb[dep.name]) {
          const vulnerabilities = [];
          
          for (const vuln of vulnDb[dep.name]) {
            // Check if this version is affected
            if (isVersionAffected(dep.version, vuln.affected_versions || '*')) {
              vulnerabilities.push({
                severity: vuln.severity || 'medium',
                description: vuln.description || 'Vulnerability in package',
                fixedInVersion: vuln.fixed_in_version,
                url: vuln.more_info_url,
                cveIds: vuln.cve_ids
              });
            }
          }
          
          if (vulnerabilities.length > 0) {
            dep.vulnerabilities = vulnerabilities;
          }
        }
      } catch (dbError) {
        log.warn(`Error reading npm vulnerability database`, { error: dbError });
      }
    }
    
    // If no vulnerabilities found yet, try npm audit
    if (!dep.vulnerabilities || dep.vulnerabilities.length === 0) {
      try {
        // Create a temporary package.json to audit just this package
        const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dep-audit-'));
        const tempPackageJson = {
          name: 'temp-audit-package',
          version: '1.0.0',
          dependencies: {
            [dep.name]: dep.version
          }
        };
        
        fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(tempPackageJson, null, 2));
        
        // Run npm audit
        try {
          const { stdout } = await execAsync('npm audit --json', { cwd: tempDir });
          
          try {
            const auditResult = JSON.parse(stdout);
            const vulnerabilities = [];
            
            if (auditResult.vulnerabilities && auditResult.vulnerabilities[dep.name]) {
              const vulnInfo = auditResult.vulnerabilities[dep.name];
              
              for (const vuln of vulnInfo.via) {
                if (typeof vuln === 'object') {
                  vulnerabilities.push({
                    severity: vuln.severity,
                    description: vuln.title,
                    cveIds: [vuln.url.includes('advisories/') ? `GHSA-${vuln.url.split('advisories/')[1]}` : ''],
                    fixedInVersion: vulnInfo.fixAvailable?.version,
                    url: vuln.url
                  });
                }
              }
              
              if (vulnerabilities.length > 0) {
                dep.vulnerabilities = vulnerabilities;
              }
            }
          } catch (jsonError) {
            log.warn(`Error parsing npm audit output for ${dep.name}`, { error: jsonError });
          }
        } catch (auditError) {
          // npm audit can exit with non-zero when vulnerabilities are found
          try {
            const output = auditError.stdout || '';
            if (output) {
              const auditResult = JSON.parse(output);
              const vulnerabilities = [];
              
              if (auditResult.vulnerabilities && auditResult.vulnerabilities[dep.name]) {
                const vulnInfo = auditResult.vulnerabilities[dep.name];
                
                for (const vuln of vulnInfo.via) {
                  if (typeof vuln === 'object') {
                    vulnerabilities.push({
                      severity: vuln.severity,
                      description: vuln.title,
                      cveIds: [vuln.url.includes('advisories/') ? `GHSA-${vuln.url.split('advisories/')[1]}` : ''],
                      fixedInVersion: vulnInfo.fixAvailable?.version,
                      url: vuln.url
                    });
                  }
                }
                
                if (vulnerabilities.length > 0) {
                  dep.vulnerabilities = vulnerabilities;
                }
              }
            }
          } catch (parseError) {
            log.warn(`Error handling npm audit error output for ${dep.name}`, { error: parseError });
          }
        }
        
        // Clean up temp directory
        try {
          fs.rmSync(tempDir, { recursive: true, force: true });
        } catch (cleanupError) {
          log.warn(`Error cleaning up temp directory ${tempDir}`, { error: cleanupError });
        }
      } catch (auditError) {
        log.warn(`Error running npm audit for ${dep.name}`, { error: auditError });
      }
    }
  } catch (error) {
    log.warn(`Error checking npm vulnerabilities for ${dep.name}`, { error });
  }
}

/**
 * Check for vulnerabilities in Python packages
 */
async function checkPipVulnerabilities(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Check custom database first if configured
    if (config.vulnerabilityDbPaths?.pip && fs.existsSync(config.vulnerabilityDbPaths.pip)) {
      try {
        const vulnDb = JSON.parse(await readFileAsync(config.vulnerabilityDbPaths.pip, 'utf8'));
        
        if (vulnDb[dep.name]) {
          const vulnerabilities = [];
          
          for (const vuln of vulnDb[dep.name]) {
            // Check if this version is affected
            if (isVersionAffected(dep.version, vuln.affected_versions || '*')) {
              vulnerabilities.push({
                severity: vuln.severity || 'medium',
                description: vuln.description || 'Vulnerability in package',
                fixedInVersion: vuln.fixed_in_version,
                url: vuln.more_info_url,
                cveIds: vuln.cve_ids
              });
            }
          }
          
          if (vulnerabilities.length > 0) {
            dep.vulnerabilities = vulnerabilities;
          }
        }
      } catch (dbError) {
        log.warn(`Error reading pip vulnerability database`, { error: dbError });
      }
    }
    
    // If no vulnerabilities found yet, try safety check
    if (!dep.vulnerabilities || dep.vulnerabilities.length === 0) {
      try {
        // Create a temporary requirements.txt for this package
        const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dep-safety-'));
        fs.writeFileSync(path.join(tempDir, 'requirements.txt'), `${dep.name}==${dep.version}\n`);
        
        // Run safety check
        try {
          const { stdout } = await execAsync('safety check --json -r requirements.txt', { cwd: tempDir });
          
          try {
            const safetyResult = JSON.parse(stdout);
            const vulnerabilities = [];
            
            for (const vuln of safetyResult) {
              if (vuln[0] === dep.name) {
                vulnerabilities.push({
                  severity: mapSafetySeverity(vuln[4]),
                  description: vuln[3],
                  cveIds: [vuln[1]],
                  fixedInVersion: vuln[5],
                  url: vuln[6]
                });
              }
            }
            
            if (vulnerabilities.length > 0) {
              dep.vulnerabilities = vulnerabilities;
            }
          } catch (jsonError) {
            log.warn(`Error parsing safety check output for ${dep.name}`, { error: jsonError });
          }
        } catch (safetyError) {
          log.warn(`Safety check failed for ${dep.name}`, { error: safetyError });
        }
        
        // Clean up temp directory
        try {
          fs.rmSync(tempDir, { recursive: true, force: true });
        } catch (cleanupError) {
          log.warn(`Error cleaning up temp directory ${tempDir}`, { error: cleanupError });
        }
      } catch (safetyError) {
        log.warn(`Error running safety check for ${dep.name}`, { error: safetyError });
      }
    }
  } catch (error) {
    log.warn(`Error checking pip vulnerabilities for ${dep.name}`, { error });
  }
}

/**
 * Map Safety severity to standard severity
 */
function mapSafetySeverity(safetySeverity: string): 'low' | 'medium' | 'high' | 'critical' {
  const severity = safetySeverity.toLowerCase();
  
  if (severity.includes('critical')) {
    return 'critical';
  } else if (severity.includes('high')) {
    return 'high';
  } else if (severity.includes('moderate') || severity.includes('medium')) {
    return 'medium';
  } else {
    return 'low';
  }
}

/**
 * Check for vulnerabilities in Maven/Gradle packages
 */
async function checkMavenVulnerabilities(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Check custom database first if configured
    const dbPath = config.vulnerabilityDbPaths?.maven || config.vulnerabilityDbPaths?.gradle;
    
    if (dbPath && fs.existsSync(dbPath)) {
      try {
        const vulnDb = JSON.parse(await readFileAsync(dbPath, 'utf8'));
        
        if (vulnDb[dep.name]) {
          const vulnerabilities = [];
          
          for (const vuln of vulnDb[dep.name]) {
            // Check if this version is affected
            if (isVersionAffected(dep.version, vuln.affected_versions || '*')) {
              vulnerabilities.push({
                severity: vuln.severity || 'medium',
                description: vuln.description || 'Vulnerability in package',
                fixedInVersion: vuln.fixed_in_version,
                url: vuln.more_info_url,
                cveIds: vuln.cve_ids
              });
            }
          }
          
          if (vulnerabilities.length > 0) {
            dep.vulnerabilities = vulnerabilities;
          }
        }
      } catch (dbError) {
        log.warn(`Error reading Maven/Gradle vulnerability database`, { error: dbError });
      }
    }
    
    // If no vulnerabilities found yet, try dependency-check or OWASP Dependency Check
    if (!dep.vulnerabilities || dep.vulnerabilities.length === 0) {
      // For a complete implementation, you would integrate with dependency-check or OWASP Dependency Check
    }
  } catch (error) {
    log.warn(`Error checking Maven/Gradle vulnerabilities for ${dep.name}`, { error });
  }
}

/**
 * Check for vulnerabilities in NuGet packages
 */
async function checkNugetVulnerabilities(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Check custom database first if configured
    if (config.vulnerabilityDbPaths?.nuget && fs.existsSync(config.vulnerabilityDbPaths.nuget)) {
      try {
        const vulnDb = JSON.parse(await readFileAsync(config.vulnerabilityDbPaths.nuget, 'utf8'));
        
        if (vulnDb[dep.name]) {
          const vulnerabilities = [];
          
          for (const vuln of vulnDb[dep.name]) {
            // Check if this version is affected
            if (isVersionAffected(dep.version, vuln.affected_versions || '*')) {
              vulnerabilities.push({
                severity: vuln.severity || 'medium',
                description: vuln.description || 'Vulnerability in package',
                fixedInVersion: vuln.fixed_in_version,
                url: vuln.more_info_url,
                cveIds: vuln.cve_ids
              });
            }
          }
          
          if (vulnerabilities.length > 0) {
            dep.vulnerabilities = vulnerabilities;
          }
        }
      } catch (dbError) {
        log.warn(`Error reading NuGet vulnerability database`, { error: dbError });
      }
    }
    
    // If no vulnerabilities found yet, try to query known vulnerabilities
    if (!dep.vulnerabilities || dep.vulnerabilities.length === 0) {
      // For a complete implementation, you could query NVD or other vulnerability databases
    }
  } catch (error) {
    log.warn(`Error checking NuGet vulnerabilities for ${dep.name}`, { error });
  }
}

/**
 * Check if a dependency is deprecated
 */
async function checkIfDeprecated(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Check for deprecation based on package manager
    switch (dep.packageManager) {
      case 'npm':
        await checkNpmDeprecation(dep, config);
        break;
      case 'pip':
        await checkPipDeprecation(dep, config);
        break;
      case 'maven':
      case 'gradle':
        await checkMavenDeprecation(dep, config);
        break;
      case 'nuget':
        await checkNugetDeprecation(dep, config);
        break;
    }
  } catch (error) {
    log.warn(`Error checking if ${dep.name} is deprecated`, { error });
  }
}

/**
 * Check if an NPM package is deprecated
 */
async function checkNpmDeprecation(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Query npm registry for package info
    const { stdout } = await execAsync(`npm view ${dep.name} deprecated --json`);
    
    try {
      const deprecationInfo = JSON.parse(stdout.trim());
      
      if (deprecationInfo && typeof deprecationInfo === 'string') {
        dep.isDeprecated = true;
        dep.deprecationMessage = deprecationInfo;
      }
    } catch (jsonError) {
      // If not valid JSON, it might be "undefined" which means not deprecated
      if (stdout.trim() !== 'undefined') {
        log.warn(`Error parsing npm deprecation info for ${dep.name}`, { error: jsonError });
      }
    }
  } catch (error) {
    // npm view can exit with an error if the package doesn't exist
    log.warn(`Error checking NPM deprecation for ${dep.name}`, { error });
  }
}

/**
 * Check if a Python package is deprecated
 */
async function checkPipDeprecation(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use PyPI API to check for deprecation markers
    const { stdout } = await execAsync(`curl -s https://pypi.org/pypi/${dep.name}/json`);
    
    try {
      const packageInfo = JSON.parse(stdout);
      
      // Check description and summary for deprecation keywords
      const description = (packageInfo.info.description || '').toLowerCase();
      const summary = (packageInfo.info.summary || '').toLowerCase();
      
      if (description.includes('deprecated') || 
          summary.includes('deprecated') || 
          description.includes('no longer maintained') || 
          summary.includes('no longer maintained')) {
        
        dep.isDeprecated = true;
        dep.deprecationMessage = 'Package appears to be deprecated based on its description';
      }
      
      // Check if there's a specific classifier for deprecated
      if (packageInfo.info.classifiers && 
          packageInfo.info.classifiers.some((c: string) => 
            c.toLowerCase().includes('deprecated') || 
            c.toLowerCase().includes('inactive')
          )) {
        
        dep.isDeprecated = true;
        dep.deprecationMessage = 'Package is marked with deprecated/inactive classifier';
      }
      
      // Check development status
      const devStatus = packageInfo.info.classifiers.find((c: string) => 
        c.toLowerCase().includes('development status')
      );
      
      if (devStatus && 
          (devStatus.includes('Inactive') || 
           devStatus.includes('7 - Inactive'))) {
        
        dep.isDeprecated = true;
        dep.deprecationMessage = `Package development status: ${devStatus}`;
      }
    } catch (jsonError) {
      log.warn(`Error parsing PyPI API output for ${dep.name} deprecation check`, { error: jsonError });
    }
  } catch (error) {
    log.warn(`Error checking Python deprecation for ${dep.name}`, { error });
  }
}

/**
 * Check if a Maven/Gradle package is deprecated
 */
async function checkMavenDeprecation(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Extract groupId and artifactId
    const [groupId, artifactId] = dep.name.split(':');
    
    // Use Maven Central API to check for potential deprecation markers
    const { stdout } = await execAsync(`curl -s "https://search.maven.org/solrsearch/select?q=g:%22${groupId}%22+AND+a:%22${artifactId}%22&rows=1&wt=json"`);
    
    try {
      const searchResult = JSON.parse(stdout);
      
      if (searchResult.response && searchResult.response.docs && searchResult.response.docs.length > 0) {
        const latestVersion = searchResult.response.docs[0].latestVersion;
        
        // If the latest version is very old (e.g., >5 years), it might be abandoned
        const timestamp = searchResult.response.docs[0].timestamp;
        if (timestamp) {
          const lastUpdateDate = new Date(timestamp);
          const fiveYearsAgo = new Date();
          fiveYearsAgo.setFullYear(fiveYearsAgo.getFullYear() - 5);
          
          if (lastUpdateDate < fiveYearsAgo) {
            dep.isDeprecated = true;
            dep.deprecationMessage = `Package has not been updated since ${lastUpdateDate.toISOString().split('T')[0]} and may be abandoned`;
          }
        }
      }
    } catch (jsonError) {
      log.warn(`Error parsing Maven Central API output for ${dep.name} deprecation check`, { error: jsonError });
    }
  } catch (error) {
    log.warn(`Error checking Maven/Gradle deprecation for ${dep.name}`, { error });
  }
}

/**
 * Check if a NuGet package is deprecated
 */
async function checkNugetDeprecation(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use NuGet API to check for deprecation
    const { stdout } = await execAsync(`curl -s "https://api.nuget.org/v3/registration5-semver1/${dep.name.toLowerCase()}/index.json"`);
    
    try {
      const packageInfo = JSON.parse(stdout);
      
      // Check if there's deprecation info
      // See: https://docs.microsoft.com/en-us/nuget/api/registration-base-url-resource#package-deprecation
      if (packageInfo.items && packageInfo.items.length > 0) {
        for (const item of packageInfo.items) {
          if (item.items && item.items.length > 0) {
            for (const version of item.items) {
              if (version.catalogEntry && 
                  version.catalogEntry.version === dep.version && 
                  version.catalogEntry.deprecation) {
                
                dep.isDeprecated = true;
                dep.deprecationMessage = version.catalogEntry.deprecation.message || 'Package is deprecated';
                return;
              }
            }
          }
        }
      }
      
      // Also check for packages that haven't been updated in a long time
      if (packageInfo.items && packageInfo.items.length > 0) {
        const lastItem = packageInfo.items[packageInfo.items.length - 1];
        if (lastItem.items && lastItem.items.length > 0) {
          const lastVersion = lastItem.items[lastItem.items.length - 1];
          
          if (lastVersion.catalogEntry && lastVersion.catalogEntry.published) {
            const publishedDate = new Date(lastVersion.catalogEntry.published);
            const fiveYearsAgo = new Date();
            fiveYearsAgo.setFullYear(fiveYearsAgo.getFullYear() - 5);
            
            if (publishedDate < fiveYearsAgo) {
              dep.isDeprecated = true;
              dep.deprecationMessage = `Package has not been updated since ${publishedDate.toISOString().split('T')[0]} and may be abandoned`;
            }
          }
        }
      }
    } catch (jsonError) {
      log.warn(`Error parsing NuGet API output for ${dep.name} deprecation check`, { error: jsonError });
    }
  } catch (error) {
    log.warn(`Error checking NuGet deprecation for ${dep.name}`, { error });
  }
}

/**
 * Assess the impact of updating a dependency
 */
async function assessUpdateImpact(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<{
  breakingChanges: boolean;
  affectedComponents?: string[];
  estimatedEffort: 'low' | 'medium' | 'high';
}> {
  // Default impact assessment
  const impact = {
    breakingChanges: false,
    affectedComponents: [] as string[],
    estimatedEffort: 'low' as 'low' | 'medium' | 'high'
  };
  
  try {
    if (!config.assessUpdateImpact || !dep.latestVersion || dep.version === dep.latestVersion) {
      return impact;
    }
    
    // If version info suggests breaking changes, update impact
    if (isMajorVersionUpdate(dep.version, dep.latestVersion)) {
      impact.breakingChanges = true;
      impact.estimatedEffort = 'medium';
    }
    
    // Determine affected components based on files that depend on this
    if (dep.dependentFiles.length > 0) {
      // Extract component names from file paths
      const components = new Set<string>();
      
      for (const file of dep.dependentFiles) {
        const parts = file.split('/');
        if (parts.length >= 3) {
          // Use the top 2-3 directories as the "component"
          const component = parts.slice(parts.length - 3, parts.length - 1).join('/');
          components.add(component);
        }
      }
      
      impact.affectedComponents = Array.from(components);
      
      // If many components are affected, increase effort
      if (impact.affectedComponents.length > 3) {
        impact.estimatedEffort = 'medium';
      }
      
      if (impact.affectedComponents.length > 8) {
        impact.estimatedEffort = 'high';
      }
    }
    
    // If it's both a breaking change and affects many components, that's high effort
    if (impact.breakingChanges && impact.affectedComponents && impact.affectedComponents.length > 3) {
      impact.estimatedEffort = 'high';
    }
    
    // If it's a major library upgrade, consider it high effort
    const knownMajorLibraries = [
      'react', 'angular', 'vue', 'next', 'nuxt', 
      'express', 'koa', 'django', 'flask', 'spring', 
      'hibernate', 'tensorflow', 'pytorch', 'pandas', 
      'numpy', 'symfony', 'laravel', 'dotnet'
    ];
    
    if (knownMajorLibraries.some(lib => dep.name === lib || dep.name.startsWith(`${lib}-`)) && 
        impact.breakingChanges) {
      impact.estimatedEffort = 'high';
    }
    
    // Vulnerabilities often require targeted testing
    if (dep.vulnerabilities && dep.vulnerabilities.length > 0) {
      // Critical vulnerabilities may require urgent changes
      if (dep.vulnerabilities.some(v => v.severity === 'critical')) {
        impact.breakingChanges = true; // Assume high risk of changes
        impact.estimatedEffort = 'high';
      }
    }
    
    return impact;
  } catch (error) {
    log.warn(`Error assessing update impact for ${dep.name}`, { error });
    return impact;
  }
}

/**
 * Check if a version update is a major version change
 * This is a simplified implementation - in a real system, use semver
 */
function isMajorVersionUpdate(currentVersion: string, latestVersion: string): boolean {
  try {
    const current = currentVersion.split('.');
    const latest = latestVersion.split('.');
    
    // If major version number changed, it's a major update
    if (parseInt(current[0], 10) < parseInt(latest[0], 10)) {
      return true;
    }
    
    return false;
  } catch (error) {
    // If can't parse, assume it's a major update to be safe
    return true;
  }
}

/**
 * Calculate risk level for a dependency issue
 */
function calculateRiskLevel(
  dep: DependencyInfo
): 'low' | 'medium' | 'high' | 'critical' {
  // Start with low risk
  let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
  
  // Prioritize vulnerabilities
  if (dep.vulnerabilities && dep.vulnerabilities.length > 0) {
    // Use the highest vulnerability severity
    for (const vuln of dep.vulnerabilities) {
      if (vuln.severity === 'critical') {
        return 'critical';
      } else if (vuln.severity === 'high' && riskLevel !== 'critical') {
        riskLevel = 'high';
      } else if (vuln.severity === 'medium' && riskLevel !== 'critical' && riskLevel !== 'high') {
        riskLevel = 'medium';
      }
    }
  }
  
  // Then consider deprecation
  if (dep.isDeprecated) {
    // Deprecated packages are at least medium risk
    if (riskLevel === 'low') riskLevel = 'medium';
    
    // If already has vulnerabilities and is deprecated, raise to high
    if (dep.vulnerabilities && dep.vulnerabilities.length > 0 && riskLevel === 'medium') {
      riskLevel = 'high';
    }
  }
  
  // Consider how outdated the package is
  if (dep.isOutdated && dep.version && dep.latestVersion) {
    try {
      // Check if it's a major version behind
      if (isMajorVersionUpdate(dep.version, dep.latestVersion)) {
        // Being a major version behind is at least medium risk
        if (riskLevel === 'low') riskLevel = 'medium';
        
        // Multiple major versions behind is high risk
        const currentMajor = parseInt(dep.version.split('.')[0], 10);
        const latestMajor = parseInt(dep.latestVersion.split('.')[0], 10);
        
        if (latestMajor - currentMajor >= 2) {
          if (riskLevel === 'medium') riskLevel = 'high';
        }
      }
    } catch (parseError) {
      // If version parsing fails, default to medium for outdated packages
      if (riskLevel === 'low') riskLevel = 'medium';
    }
  }
  
  // Consider criticality based on usage
  // For direct dependencies in key files, increase risk
  if (dep.isDirect && isKeyCriticalDependency(dep)) {
    if (riskLevel === 'low') riskLevel = 'medium';
    if (riskLevel === 'medium') riskLevel = 'high';
  }
  
  return riskLevel;
}

/**
 * Determine if a dependency is critical based on name and usage
 */
function isKeyCriticalDependency(dep: DependencyInfo): boolean {
  // Known critical packages by type
  const criticalPackages: Record<string, string[]> = {
    npm: [
      'react', 'angular', 'vue', 'next', 'nuxt', 'express', 'koa',
      'aws-sdk', 'azure-sdk', 'google-cloud', 'firebase',
      'sequelize', 'mongoose', 'typeorm', 'prisma',
      'axios', 'node-fetch', 'got',
      'jsonwebtoken', 'passport', 'auth0',
      'webpack', 'babel', 'typescript'
    ],
    pip: [
      'django', 'flask', 'fastapi', 'tornado', 'pyramid',
      'sqlalchemy', 'django-orm', 'peewee',
      'boto3', 'azure-sdk', 'google-cloud-storage',
      'requests', 'httpx', 'aiohttp',
      'numpy', 'scipy', 'pandas', 'tensorflow', 'pytorch',
      'jwt', 'python-jose', 'authlib'
    ],
    maven: [
      'org.springframework', 'javax.servlet', 'jakarta.servlet',
      'org.hibernate', 'javax.persistence', 'jakarta.persistence',
      'com.amazonaws', 'com.azure', 'com.google.cloud',
      'com.fasterxml.jackson', 'org.json', 'com.google.code.gson',
      'org.apache.httpcomponents', 'java.net.http',
      'io.jsonwebtoken', 'org.springframework.security'
    ],
    gradle: [
      'org.springframework', 'javax.servlet', 'jakarta.servlet',
      'org.hibernate', 'javax.persistence', 'jakarta.persistence',
      'com.amazonaws', 'com.azure', 'com.google.cloud',
      'com.fasterxml.jackson', 'org.json', 'com.google.code.gson',
      'org.apache.httpcomponents', 'java.net.http',
      'io.jsonwebtoken', 'org.springframework.security'
    ],
    nuget: [
      'Microsoft.AspNetCore', 'Microsoft.EntityFrameworkCore',
      'Microsoft.Extensions', 'Microsoft.Azure', 'AWS.SDK',
      'Newtonsoft.Json', 'System.Text.Json',
      'Microsoft.Data.SqlClient', 'System.Data.SqlClient',
      'Microsoft.IdentityModel.Tokens', 'System.IdentityModel.Tokens.Jwt'
    ]
  };
  
  // Check if the dependency is in the critical list for its package manager
  if (criticalPackages[dep.packageManager]) {
    for (const criticalPkg of criticalPackages[dep.packageManager]) {
      if (dep.name === criticalPkg || dep.name.startsWith(criticalPkg + '.') || 
          dep.name.startsWith(criticalPkg + '-') || dep.name.startsWith(criticalPkg + '/')) {
        return true;
      }
    }
  }
  
  // Check for criticality based on dependent files
  const criticalPathPatterns = [
    'src/main/', 'src/app/', 'app/main.', 'index.js', 'index.ts',
    'core/', 'auth/', 'security/', 'database/', 'api/',
    'server.js', 'server.ts', 'app.js', 'app.ts', 'main.py'
  ];
  
  // If the dependency is used in critical files, it's likely important
  for (const filePath of dep.dependentFiles) {
    for (const pattern of criticalPathPatterns) {
      if (filePath.includes(pattern)) {
        return true;
      }
    }
  }
  
  return false;
}

/**
 * Generate tags for a dependency issue
 */
function generateTags(
  dep: DependencyInfo
): string[] {
  const tags: string[] = [dep.packageManager];
  
  // Add descriptive tags based on issue type
  if (dep.isOutdated) {
    tags.push('outdated');
  }
  
  if (dep.vulnerabilities && dep.vulnerabilities.length > 0) {
    tags.push('vulnerable');
    
    // Add highest severity level
    let highestSeverity = 'low';
    for (const vuln of dep.vulnerabilities) {
      if (vuln.severity === 'critical') {
        highestSeverity = 'critical';
        break;
      } else if (vuln.severity === 'high' && highestSeverity !== 'critical') {
        highestSeverity = 'high';
      } else if (vuln.severity === 'medium' && highestSeverity !== 'critical' && highestSeverity !== 'high') {
        highestSeverity = 'medium';
      }
    }
    tags.push(`vulnerability:${highestSeverity}`);
  }
  
  if (dep.isDeprecated) {
    tags.push('deprecated');
  }
  
  // Add dependency type tags
  if (dep.devDependency) {
    tags.push('dev-dependency');
  }
  
  if (dep.peerDependency) {
    tags.push('peer-dependency');
  }
  
  if (dep.optionalDependency) {
    tags.push('optional-dependency');
  }
  
  if (dep.isDirect) {
    tags.push('direct');
  } else {
    tags.push('transitive');
  }
  
  // Add tags for known package types
  const packageTypeTags = getPackageTypeTags(dep);
  tags.push(...packageTypeTags);
  
  return tags;
}

/**
 * Get package type tags based on package name and content
 */
function getPackageTypeTags(dep: DependencyInfo): string[] {
  const tags: string[] = [];
  const name = dep.name.toLowerCase();
  
  // Frontend frameworks
  if (['react', 'vue', 'angular', 'svelte', 'preact'].some(fw => 
      name === fw || name.startsWith(`${fw}-`) || name.startsWith(`@${fw}/`))) {
    tags.push('frontend', 'framework');
  }
  
  // Backend frameworks
  if (['express', 'koa', 'hapi', 'fastify', 'nest', 'spring', 'django', 'flask', 'rails'].some(fw => 
      name === fw || name.startsWith(`${fw}-`) || name.startsWith(`@${fw}/`))) {
    tags.push('backend', 'framework');
  }
  
  // Data and databases
  if (['sequelize', 'mongoose', 'typeorm', 'prisma', 'knex', 'sqlalchemy', 
       'mongodb', 'mysql', 'postgres', 'sqlite', 'redis'].some(db => 
      name === db || name.startsWith(`${db}-`) || name.includes('database') || name.includes('db'))) {
    tags.push('database');
  }
  
  // Testing libraries
  if (['jest', 'mocha', 'chai', 'jasmine', 'karma', 'cypress', 'selenium', 
       'puppeteer', 'pytest', 'unittest', 'testng', 'junit'].some(test => 
      name === test || name.includes('test') || name.includes('spec'))) {
    tags.push('testing');
  }
  
  // Security related
  if (['helmet', 'passport', 'jwt', 'auth', 'oauth', 'permission', 'acl', 'rbac',
       'bcrypt', 'crypto', 'hash', 'security', 'firewall'].some(sec =>
      name === sec || name.includes(sec))) {
    tags.push('security');
  }
  
  // UI libraries
  if (['material-ui', 'bootstrap', 'tailwind', 'bulma', 'semantic', 'antd', 
       'chakra', 'fontawesome', 'styled'].some(ui =>
      name.includes(ui) || name.includes('ui-') || name.includes('-ui'))) {
    tags.push('ui', 'frontend');
  }
  
  // Cloud providers
  if (['aws', 'azure', 'gcp', 'google-cloud', 'firebase', 'cloudflare', 'netlify', 
       'vercel', 'heroku', 'digitalocean'].some(cloud =>
      name.includes(cloud))) {
    tags.push('cloud');
  }
  
  // Data science/AI
  if (['tensorflow', 'pytorch', 'keras', 'scikit', 'numpy', 'pandas', 'scipy', 
       'matplotlib', 'seaborn', 'jupyter', 'ai', 'ml', 'machine-learning', 'data-science'].some(ds =>
      name.includes(ds))) {
    tags.push('data-science', 'ai');
  }
  
  return tags;
}

/**
 * Generate a recommendation for a dependency issue
 */
function generateRecommendation(
  dep: DependencyInfo
): string {
  const recommendations: string[] = [];
  
  // Start with header based on risk level
  let riskStr = ``;
  
  // Handle vulnerable dependencies with highest priority
  if (dep.vulnerabilities && dep.vulnerabilities.length > 0) {
    recommendations.push(
      `Found ${dep.vulnerabilities.length} ${dep.vulnerabilities.length === 1 ? 'vulnerability' : 'vulnerabilities'} in ${dep.packageManager} package ${dep.name}@${dep.version}.`
    );
    
    // Group vulnerabilities by severity for better readability
    const bySeverity: Record<string, any[]> = {};
    for (const vuln of dep.vulnerabilities) {
      if (!bySeverity[vuln.severity]) {
        bySeverity[vuln.severity] = [];
      }
      bySeverity[vuln.severity].push(vuln);
    }
    
    // Report vulnerabilities from highest to lowest severity
    for (const severity of ['critical', 'high', 'medium', 'low']) {
      if (bySeverity[severity] && bySeverity[severity].length > 0) {
        recommendations.push(
          `${bySeverity[severity].length} ${severity} severity ${bySeverity[severity].length === 1 ? 'issue' : 'issues'} found:`
        );
        
        // List the vulnerabilities at this severity
        for (const vuln of bySeverity[severity]) {
          let vulnDesc = `- ${vuln.description}`;
          
          if (vuln.cveIds && vuln.cveIds.length > 0) {
            vulnDesc += ` (${vuln.cveIds.join(', ')})`;
          }
          
          if (vuln.fixedInVersion) {
            vulnDesc += ` - Fixed in version ${vuln.fixedInVersion}`;
          }
          
          recommendations.push(vulnDesc);
        }
      }
    }
    
    // Recommend updating
    if (dep.latestVersion) {
      recommendations.push(
        `Update to the latest version (${dep.latestVersion}) to resolve these security issues.`
      );
    } else {
      recommendations.push(
        `Update to the latest version to resolve these security issues.`
      );
    }
  }
  
  // Handle deprecated dependencies
  if (dep.isDeprecated) {
    recommendations.push(
      `The ${dep.packageManager} package ${dep.name} is deprecated.`
    );
    
    if (dep.deprecationMessage) {
      recommendations.push(`Deprecation message: ${dep.deprecationMessage}`);
    }
    
    recommendations.push(
      `Find and migrate to an actively maintained alternative package.`
    );
  }
  
  // Handle outdated dependencies
  if (dep.isOutdated && dep.latestVersion) {
    // Only add this if not already covered by vulnerabilities
    if (!dep.vulnerabilities || dep.vulnerabilities.length === 0) {
      recommendations.push(
        `The ${dep.packageManager} package ${dep.name} (${dep.version}) is outdated. Latest version is ${dep.latestVersion}.`
      );
      
      // Check if it's a major version update
      try {
        if (isMajorVersionUpdate(dep.version, dep.latestVersion)) {
          recommendations.push(
            `This is a major version update which may include breaking changes. Review the changelog before updating.`
          );
        } else {
          recommendations.push(
            `Update to the latest version to receive bug fixes and enhancements.`
          );
        }
      } catch (versionError) {
        recommendations.push(
          `Update to the latest version to receive bug fixes and enhancements.`
        );
      }
    }
  }
  
  // If no specific recommendations were made, add generic advice
  if (recommendations.length === 0) {
    recommendations.push(
      `Review ${dep.packageManager} package ${dep.name} for potential updates or replacements as part of regular maintenance.`
    );
  }
  
  // Add update command example
  recommendations.push(getUpdateCommandExample(dep));
  
  return recommendations.join('\n');
}

/**
 * Get an example command to update the dependency
 */
function getUpdateCommandExample(dep: DependencyInfo): string {
  const latestVersion = dep.latestVersion || 'latest';
  
  switch (dep.packageManager) {
    case 'npm':
      const isDev = dep.devDependency ? ' --save-dev' : '';
      return `Update command: npm install ${dep.name}@${latestVersion}${isDev}`;
    
    case 'pip':
      return `Update command: pip install --upgrade ${dep.name}==${latestVersion}`;
    
    case 'maven':
      const [groupId, artifactId] = dep.name.split(':');
      return `Update in pom.xml: <dependency>\n  <groupId>${groupId}</groupId>\n  <artifactId>${artifactId}</artifactId>\n  <version>${latestVersion}</version>\n</dependency>`;
    
    case 'gradle':
      const [gradleGroup, gradleArtifact] = dep.name.split(':');
      return `Update in build.gradle: implementation '${gradleGroup}:${gradleArtifact}:${latestVersion}'`;
    
    case 'nuget':
      return `Update command: dotnet add package ${dep.name} --version ${latestVersion}`;
    
    default:
      return `Update ${dep.name} to version ${latestVersion}`;
  }
}

/**
 * Check if a version is affected by a specified range
 * This is a simplified implementation
 */
function isVersionAffected(version: string, affectedVersions: string): boolean {
  if (version === 'unknown') {
    return true; // Assume unknown versions are affected
  }
  
  // Very simplified version check - in a real implementation use semver or similar
  if (affectedVersions === '*') {
    return true;
  }
  
  // Check exact version match
  if (affectedVersions === version) {
    return true;
  }
  
  // Check range using commas
  if (affectedVersions.includes(',')) {
    const versions = affectedVersions.split(',').map(v => v.trim());
    return versions.includes(version);
  }
  
  // Check range with operators (very simplified)
  if (affectedVersions.startsWith('<=')) {
    const maxVersion = affectedVersions.substring(2);
    return version <= maxVersion;
  }
  
  if (affectedVersions.startsWith('<')) {
    const maxVersion = affectedVersions.substring(1);
    return version < maxVersion;
  }
  
  if (affectedVersions.startsWith('>=')) {
    const minVersion = affectedVersions.substring(2);
    return version >= minVersion;
  }
  
  if (affectedVersions.startsWith('>')) {
    const minVersion = affectedVersions.substring(1);
    return version > minVersion;
  }
  
  return false;
}

/**
 * Utility imports
 */
import * as os from 'os';