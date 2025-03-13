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
  // Types of dependencies to scan
  dependencyTypes?: Array<
    | 'direct'
    | 'dev'
    | 'peer'
    | 'optional'
    | 'transitive'
  >;
  
  // Types of package managers to scan
  packageManagers?: Array<
    | 'npm'
    | 'yarn'
    | 'pnpm'
    | 'pip'
    | 'pipenv'
    | 'poetry'
    | 'maven'
    | 'gradle'
    | 'composer'
    | 'nuget'
    | 'cargo'
    | 'go'
    | 'gem'
    | 'cocoapods'
    | 'swift'
  >;
  
  // Whether to check for known vulnerabilities
  checkVulnerabilities?: boolean;
  
  // Whether to check dependency licenses
  checkLicenses?: boolean;
  
  // Whether to check for duplicate dependencies
  checkDuplicates?: boolean;
  
  // Whether to check for unused dependencies
  checkUnused?: boolean;
  
  // Whether to check if the dependency is being maintained
  checkMaintained?: boolean;
  
  // Maximum age of a dependency update in days before flagging
  maxUpdateAge?: number;
  
  // Custom vulnerability database paths
  vulnerabilityDbPaths?: {
    dependencies?: string;
  };
  
  // Custom license allowlist/blocklist
  licenses?: {
    allowlist?: string[];
    blocklist?: string[];
  };
  
  // Dependencies to exclude from scanning
  excludeDependencies?: string[];
  
  // Scan depth - how deep to check transitive dependencies
  scanDepth?: number;
}

/**
 * Information about a dependency
 */
interface DependencyInfo {
  name: string;
  version: string;
  type: 'direct' | 'dev' | 'peer' | 'optional' | 'transitive';
  packageManager: string;
  manifestPath: string;
  latestVersion?: string;
  latestReleaseDate?: Date;
  isOutdated?: boolean;
  isVulnerable?: boolean;
  isDeprecated?: boolean;
  isUnused?: boolean;
  isLicenseIssue?: boolean;
  dependencyChain?: string[];
  homepageUrl?: string;
  repositoryUrl?: string;
  license?: string;
  lastPublishDate?: Date;
  isNotMaintained?: boolean;
  vulnerabilities?: {
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    cveIds?: string[];
    affectedVersions?: string;
    fixedInVersion?: string;
    url?: string;
  }[];
  licenseIssue?: {
    license: string;
    reason: string;
  };
  duplicates?: {
    paths: string[];
    versions: string[];
  };
  upgradeBreaking?: boolean;
  dependents?: string[];
  author?: string;
  maintainers?: string[];
  dependsOn?: string[];
}

/**
 * Main function to scan for dependencies
 */
export async function scanDependencies(
  config: DependencyScannerConfig
): Promise<DependencyIssue[]> {
  try {
    log.info('Starting dependency scanner');
    const issues: DependencyIssue[] = [];
    
    // Determine which dependency types to scan
    const dependencyTypes = config.dependencyTypes || [
      'direct', 'dev', 'peer', 'optional'
    ];
    log.info(`Scanning dependency types: ${dependencyTypes.join(', ')}`);
    
    // Determine which package managers to scan
    const packageManagers = config.packageManagers || [
      'npm', 'yarn', 'pnpm', 'pip', 'pipenv', 'poetry', 'maven', 'gradle',
      'composer', 'nuget', 'cargo', 'go', 'gem', 'cocoapods', 'swift'
    ];
    log.info(`Scanning package managers: ${packageManagers.join(', ')}`);
    
    // Scan for all dependencies
    const dependencies: DependencyInfo[] = [];
    
    // JavaScript/TypeScript (npm, yarn, pnpm)
    if (packageManagers.some(pm => ['npm', 'yarn', 'pnpm'].includes(pm))) {
      try {
        log.info('Scanning for JavaScript/TypeScript dependencies');
        const jsDependencies = await scanJavaScriptDependencies(config);
        dependencies.push(...jsDependencies);
        log.info(`Found ${jsDependencies.length} JavaScript/TypeScript dependencies`);
      } catch (jsError) {
        log.error('Error scanning JavaScript/TypeScript dependencies', { error: jsError });
      }
    }
    
    // Python (pip, pipenv, poetry)
    if (packageManagers.some(pm => ['pip', 'pipenv', 'poetry'].includes(pm))) {
      try {
        log.info('Scanning for Python dependencies');
        const pythonDependencies = await scanPythonDependencies(config);
        dependencies.push(...pythonDependencies);
        log.info(`Found ${pythonDependencies.length} Python dependencies`);
      } catch (pythonError) {
        log.error('Error scanning Python dependencies', { error: pythonError });
      }
    }
    
    // Java (maven, gradle)
    if (packageManagers.some(pm => ['maven', 'gradle'].includes(pm))) {
      try {
        log.info('Scanning for Java dependencies');
        const javaDependencies = await scanJavaDependencies(config);
        dependencies.push(...javaDependencies);
        log.info(`Found ${javaDependencies.length} Java dependencies`);
      } catch (javaError) {
        log.error('Error scanning Java dependencies', { error: javaError });
      }
    }
    
    // PHP (composer)
    if (packageManagers.includes('composer')) {
      try {
        log.info('Scanning for PHP dependencies');
        const phpDependencies = await scanPhpDependencies(config);
        dependencies.push(...phpDependencies);
        log.info(`Found ${phpDependencies.length} PHP dependencies`);
      } catch (phpError) {
        log.error('Error scanning PHP dependencies', { error: phpError });
      }
    }
    
    // .NET (nuget)
    if (packageManagers.includes('nuget')) {
      try {
        log.info('Scanning for .NET dependencies');
        const dotnetDependencies = await scanDotNetDependencies(config);
        dependencies.push(...dotnetDependencies);
        log.info(`Found ${dotnetDependencies.length} .NET dependencies`);
      } catch (dotnetError) {
        log.error('Error scanning .NET dependencies', { error: dotnetError });
      }
    }
    
    // Rust (cargo)
    if (packageManagers.includes('cargo')) {
      try {
        log.info('Scanning for Rust dependencies');
        const rustDependencies = await scanRustDependencies(config);
        dependencies.push(...rustDependencies);
        log.info(`Found ${rustDependencies.length} Rust dependencies`);
      } catch (rustError) {
        log.error('Error scanning Rust dependencies', { error: rustError });
      }
    }
    
    // Go (go modules)
    if (packageManagers.includes('go')) {
      try {
        log.info('Scanning for Go dependencies');
        const goDependencies = await scanGoDependencies(config);
        dependencies.push(...goDependencies);
        log.info(`Found ${goDependencies.length} Go dependencies`);
      } catch (goError) {
        log.error('Error scanning Go dependencies', { error: goError });
      }
    }
    
    // Ruby (gem)
    if (packageManagers.includes('gem')) {
      try {
        log.info('Scanning for Ruby dependencies');
        const rubyDependencies = await scanRubyDependencies(config);
        dependencies.push(...rubyDependencies);
        log.info(`Found ${rubyDependencies.length} Ruby dependencies`);
      } catch (rubyError) {
        log.error('Error scanning Ruby dependencies', { error: rubyError });
      }
    }
    
    // iOS/macOS (cocoapods, swift)
    if (packageManagers.some(pm => ['cocoapods', 'swift'].includes(pm))) {
      try {
        log.info('Scanning for iOS/macOS dependencies');
        const iosDependencies = await scanAppleDependencies(config);
        dependencies.push(...iosDependencies);
        log.info(`Found ${iosDependencies.length} iOS/macOS dependencies`);
      } catch (iosError) {
        log.error('Error scanning iOS/macOS dependencies', { error: iosError });
      }
    }
    
    log.info(`Found total of ${dependencies.length} dependencies to analyze`);
    
    // Filter dependencies based on type if specified
    let filteredDependencies = dependencies.filter(dep => 
      dependencyTypes.includes(dep.type)
    );
    log.info(`Filtered to ${filteredDependencies.length} dependencies of specified types`);
    
    // Filter out excluded dependencies
    if (config.excludeDependencies && config.excludeDependencies.length > 0) {
      filteredDependencies = filteredDependencies.filter(dep => {
        return !config.excludeDependencies!.some(excluded => {
          if (excluded === dep.name) {
            return true;
          }
          if (excluded.includes('*')) {
            const pattern = excluded.replace(/\*/g, '.*');
            return new RegExp(`^${pattern}$`).test(dep.name);
          }
          return false;
        });
      });
      log.info(`Filtered out excluded dependencies, ${filteredDependencies.length} remaining`);
    }
    
    // Process each dependency
    for (const dep of filteredDependencies) {
      try {
        log.info(`Checking dependency: ${dep.name}@${dep.version} (${dep.packageManager})`);
        
        // Check for issues
        await checkDependencyForIssues(dep, config);
        
        // Create issue for problematic dependencies
        if (dep.isOutdated || 
            dep.isVulnerable || 
            dep.isDeprecated || 
            dep.isUnused || 
            dep.isLicenseIssue ||
            dep.isNotMaintained) {
          
          const issue: DependencyIssue = {
            detectedAt: new Date(),
            name: dep.name,
            version: dep.version,
            type: dep.type,
            packageManager: dep.packageManager,
            manifestPath: dep.manifestPath,
            latestVersion: dep.latestVersion,
            isOutdated: dep.isOutdated || false,
            isVulnerable: dep.isVulnerable || false,
            vulnerabilities: dep.vulnerabilities || [],
            isDeprecated: dep.isDeprecated || false,
            isUnused: dep.isUnused || false,
            isLicenseIssue: dep.isLicenseIssue || false,
            licenseIssue: dep.licenseIssue,
            license: dep.license,
            isNotMaintained: dep.isNotMaintained || false,
            lastPublishDate: dep.lastPublishDate,
            duplicates: dep.duplicates,
            upgradeBreaking: dep.upgradeBreaking,
            dependents: dep.dependents,
            dependsOn: dep.dependsOn,
            repositoryUrl: dep.repositoryUrl,
            homepageUrl: dep.homepageUrl,
            author: dep.author,
            maintainers: dep.maintainers,
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
 * Scan for JavaScript/TypeScript dependencies
 */
async function scanJavaScriptDependencies(
  config: DependencyScannerConfig
): Promise<DependencyInfo[]> {
  const dependencies: DependencyInfo[] = [];
  
  try {
    // Find package.json files
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
    
    for (const packageJsonPath of packageJsonPaths) {
      try {
        const content = await readFileAsync(packageJsonPath, 'utf8');
        const packageJson = JSON.parse(content);
        
        // Determine the package manager
        let packageManager = 'npm'; // Default
        try {
          // Check for lockfiles to determine package manager
          const dirPath = path.dirname(packageJsonPath);
          if (fs.existsSync(path.join(dirPath, 'yarn.lock'))) {
            packageManager = 'yarn';
          } else if (fs.existsSync(path.join(dirPath, 'pnpm-lock.yaml'))) {
            packageManager = 'pnpm';
          }
        } catch (lockError) {
          log.debug(`Error detecting package manager for ${packageJsonPath}`, { error: lockError });
        }
        
        // Process direct dependencies
        if (packageJson.dependencies) {
          await processDependencyObject(packageJson.dependencies, 'direct', packageManager, packageJsonPath, dependencies);
        }
        
        // Process dev dependencies
        if (packageJson.devDependencies) {
          await processDependencyObject(packageJson.devDependencies, 'dev', packageManager, packageJsonPath, dependencies);
        }
        
        // Process peer dependencies
        if (packageJson.peerDependencies) {
          await processDependencyObject(packageJson.peerDependencies, 'peer', packageManager, packageJsonPath, dependencies);
        }
        
        // Process optional dependencies
        if (packageJson.optionalDependencies) {
          await processDependencyObject(packageJson.optionalDependencies, 'optional', packageManager, packageJsonPath, dependencies);
        }
      } catch (packageJsonError) {
        log.warn(`Error processing package.json at ${packageJsonPath}`, { error: packageJsonError });
      }
    }
    
    // Check for transitive dependencies if scan depth > 1
    if ((config.scanDepth || 1) > 1) {
      // In a complete implementation, this would involve parsing lockfiles (package-lock.json, yarn.lock, etc.)
      // and extracting transitive dependency information
    }
    
    // Check for unused dependencies if configured
    if (config.checkUnused) {
      await checkUnusedJSDependencies(dependencies, config);
    }
  } catch (error) {
    log.error('Error scanning JavaScript/TypeScript dependencies', { error });
  }
  
  return dependencies;
}

/**
 * Process a dependency object from package.json
 */
async function processDependencyObject(
  dependencyObject: Record<string, string>,
  type: 'direct' | 'dev' | 'peer' | 'optional' | 'transitive',
  packageManager: string,
  manifestPath: string,
  dependencies: DependencyInfo[]
): Promise<void> {
  for (const [name, versionSpec] of Object.entries(dependencyObject)) {
    try {
      // Extract the version from the version spec
      let version = versionSpec.replace(/[^0-9.]/g, '');
      
      // Handle complex version specs like "~1.2.3", "^1.2.3", etc.
      if (!version) {
        if (versionSpec.includes('#')) {
          // Handle GitHub URLs with hashes
          version = versionSpec.split('#')[1] || 'unknown';
        } else if (versionSpec.includes('/')) {
          // Handle local paths or GitHub URLs
          version = 'local';
        } else {
          version = 'unknown';
        }
      }
      
      dependencies.push({
        name,
        version,
        type,
        packageManager,
        manifestPath
      });
    } catch (depError) {
      log.debug(`Error processing dependency ${name}`, { error: depError });
    }
  }
}

/**
 * Check for unused JS dependencies
 */
async function checkUnusedJSDependencies(
  dependencies: DependencyInfo[],
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Group dependencies by their manifest path
    const depsByManifest: Record<string, DependencyInfo[]> = {};
    
    for (const dep of dependencies) {
      if (!depsByManifest[dep.manifestPath]) {
        depsByManifest[dep.manifestPath] = [];
      }
      depsByManifest[dep.manifestPath].push(dep);
    }
    
    // Check each package.json separately
    for (const [manifestPath, deps] of Object.entries(depsByManifest)) {
      const projectDir = path.dirname(manifestPath);
      
      // Find all JS/TS files in the project
      const sourceFiles = await glob('**/*.{js,jsx,ts,tsx}', {
        cwd: projectDir,
        absolute: true,
        ignore: [
          'node_modules/**',
          'dist/**',
          'build/**'
        ]
      });
      
      // Read all source files and create a combined content string
      let combinedContent = '';
      for (const filePath of sourceFiles) {
        try {
          const content = await readFileAsync(filePath, 'utf8');
          combinedContent += content + '\n';
        } catch (fileError) {
          log.debug(`Error reading file ${filePath}`, { error: fileError });
        }
      }
      
      // Check each dependency for usage
      for (const dep of deps) {
        // Skip dev dependencies as they might be used in config files or scripts
        if (dep.type === 'dev') continue;
        
        // Check if the dependency name appears in the source code
        // This is a simplified check - a complete solution would parse imports properly
        if (!combinedContent.includes(`'${dep.name}'`) && 
            !combinedContent.includes(`"${dep.name}"`) && 
            !combinedContent.includes(`require('${dep.name}`) && 
            !combinedContent.includes(`require("${dep.name}`) && 
            !combinedContent.includes(`from '${dep.name}`) && 
            !combinedContent.includes(`from "${dep.name}`)) {
          
          dep.isUnused = true;
        }
      }
    }
  } catch (error) {
    log.error('Error checking for unused JS dependencies', { error });
  }
}

/**
 * Scan for Python dependencies
 */
async function scanPythonDependencies(
  config: DependencyScannerConfig
): Promise<DependencyInfo[]> {
  const dependencies: DependencyInfo[] = [];
  
  try {
    // Find requirements.txt files
    const requirementsPaths = await glob('**/requirements{,.*}.txt', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/venv/**',
        '**/.venv/**',
        '**/env/**',
        '**/.env/**'
      ]
    });
    
    for (const requirementsPath of requirementsPaths) {
      try {
        const content = await readFileAsync(requirementsPath, 'utf8');
        const lines = content.split('\n');
        
        for (const line of lines) {
          // Skip comments and empty lines
          if (line.trim().startsWith('#') || !line.trim()) {
            continue;
          }
          
          // Parse the requirement line
          const reqLine = line.split('#')[0].trim(); // Remove inline comments
          const parts = reqLine.split(/[=<>!~]+/); // Split by version operators
          const name = parts[0].trim();
          const version = parts.length > 1 ? parts[1].trim() : 'unknown';
          
          dependencies.push({
            name,
            version,
            type: 'direct', // requirements.txt doesn't distinguish between direct/dev
            packageManager: 'pip',
            manifestPath: requirementsPath
          });
        }
      } catch (requirementsError) {
        log.warn(`Error processing requirements.txt at ${requirementsPath}`, { error: requirementsError });
      }
    }
    
    // Find setup.py files
    const setupPyPaths = await glob('**/setup.py', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/venv/**',
        '**/.venv/**',
        '**/env/**',
        '**/.env/**'
      ]
    });
    
    for (const setupPyPath of setupPyPaths) {
      try {
        const content = await readFileAsync(setupPyPath, 'utf8');
        
        // This is a very simple parser - a real implementation would use a Python parser
        // Look for install_requires=['package1', 'package2>=1.0']
        const installRequiresMatch = content.match(/install_requires\s*=\s*\[([^\]]+)\]/s);
        
        if (installRequiresMatch && installRequiresMatch[1]) {
          const requiresStr = installRequiresMatch[1];
          const requireItems = requiresStr.match(/(['"])(.+?)\1/g) || [];
          
          for (const item of requireItems) {
            // Remove quotes
            const reqStr = item.substring(1, item.length - 1);
            
            // Parse the requirement
            const parts = reqStr.split(/[=<>!~]+/); // Split by version operators
            const name = parts[0].trim();
            const version = parts.length > 1 ? parts[1].trim() : 'unknown';
            
            dependencies.push({
              name,
              version,
              type: 'direct',
              packageManager: 'pip',
              manifestPath: setupPyPath
            });
          }
        }
        
        // Look for extras_require={'dev': ['package1', 'package2>=1.0']}
        const extrasRequireMatch = content.match(/extras_require\s*=\s*\{([^\}]+)\}/s);
        
        if (extrasRequireMatch && extrasRequireMatch[1]) {
          const extrasStr = extrasRequireMatch[1];
          const extrasSections = extrasStr.split(':');
          
          for (let i = 0; i < extrasSections.length - 1; i++) {
            const sectionName = extrasSections[i].match(/(['"])(.+?)\1/)?.[2] || 'unknown';
            const requireItems = extrasSections[i + 1].match(/(['"])(.+?)\1/g) || [];
            
            for (const item of requireItems) {
              // Remove quotes
              const reqStr = item.substring(1, item.length - 1);
              
              // Parse the requirement
              const parts = reqStr.split(/[=<>!~]+/); // Split by version operators
              const name = parts[0].trim();
              const version = parts.length > 1 ? parts[1].trim() : 'unknown';
              
              dependencies.push({
                name,
                version,
                type: sectionName === 'dev' || sectionName === 'test' ? 'dev' : 'optional',
                packageManager: 'pip',
                manifestPath: setupPyPath
              });
            }
          }
        }
      } catch (setupPyError) {
        log.warn(`Error processing setup.py at ${setupPyPath}`, { error: setupPyError });
      }
    }
    
    // Find Pipfile files
    const pipfilePaths = await glob('**/Pipfile', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/venv/**',
        '**/.venv/**',
        '**/env/**',
        '**/.env/**'
      ]
    });
    
    for (const pipfilePath of pipfilePaths) {
      try {
        const content = await readFileAsync(pipfilePath, 'utf8');
        const lines = content.split('\n');
        
        let currentSection = '';
        for (const line of lines) {
          // Skip comments and empty lines
          if (line.trim().startsWith('#') || !line.trim()) {
            continue;
          }
          
          // Check for section headers
          if (line.trim().startsWith('[') && line.trim().endsWith(']')) {
            currentSection = line.trim().slice(1, -1).toLowerCase();
            continue;
          }
          
          if (currentSection === 'packages' || currentSection === 'dev-packages') {
            const match = line.match(/^([\w-_\.]+)\s*=\s*["']?([^"']+)["']?$/i);
            if (match) {
              const name = match[1].trim();
              const versionSpec = match[2].trim();
              
              // Extract version from spec
              let version = 'unknown';
              if (versionSpec.startsWith('==')) {
                version = versionSpec.substring(2).trim();
              } else if (versionSpec.startsWith('>=')) {
                version = versionSpec.substring(2).trim();
              } else if (versionSpec.startsWith('>')) {
                version = versionSpec.substring(1).trim();
              } else if (versionSpec.startsWith('~=')) {
                version = versionSpec.substring(2).trim();
              } else if (versionSpec.startsWith('~')) {
                version = versionSpec.substring(1).trim();
              }
              
              dependencies.push({
                name,
                version,
                type: currentSection === 'dev-packages' ? 'dev' : 'direct',
                packageManager: 'pipenv',
                manifestPath: pipfilePath
              });
            }
          }
        }
      } catch (pipfileError) {
        log.warn(`Error processing Pipfile at ${pipfilePath}`, { error: pipfileError });
      }
    }
    
    // Find pyproject.toml files (Poetry)
    const pyprojectPaths = await glob('**/pyproject.toml', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/venv/**',
        '**/.venv/**',
        '**/env/**',
        '**/.env/**'
      ]
    });
    
    for (const pyprojectPath of pyprojectPaths) {
      try {
        const content = await readFileAsync(pyprojectPath, 'utf8');
        const lines = content.split('\n');
        
        let inDependencies = false;
        let inDevDependencies = false;
        
        for (const line of lines) {
          // Skip comments and empty lines
          if (line.trim().startsWith('#') || !line.trim()) {
            continue;
          }
          
          // Check for section headers
          if (line.trim() === '[tool.poetry.dependencies]') {
            inDependencies = true;
            inDevDependencies = false;
            continue;
          } else if (line.trim() === '[tool.poetry.dev-dependencies]') {
            inDependencies = false;
            inDevDependencies = true;
            continue;
          } else if (line.trim().startsWith('[') && line.trim().endsWith(']')) {
            inDependencies = false;
            inDevDependencies = false;
            continue;
          }
          
          if (inDependencies || inDevDependencies) {
            // Skip python dependency
            if (line.trim().startsWith('python =')) {
              continue;
            }
            
            const match = line.match(/^([\w-_\.]+)\s*=\s*["']?([^"']+)["']?$/i);
            if (match) {
              const name = match[1].trim();
              const versionSpec = match[2].trim();
              
              // Extract version from spec
              let version = 'unknown';
              const versionMatch = versionSpec.match(/["']([^"']+)["']/);
              if (versionMatch) {
                version = versionMatch[1];
              }
              
              dependencies.push({
                name,
                version,
                type: inDevDependencies ? 'dev' : 'direct',
                packageManager: 'poetry',
                manifestPath: pyprojectPath
              });
            }
          }
        }
      } catch (poetryError) {
        log.warn(`Error processing pyproject.toml at ${pyprojectPath}`, { error: poetryError });
      }
    }
    
    // Check for unused dependencies if configured
    if (config.checkUnused) {
      await checkUnusedPythonDependencies(dependencies, config);
    }
  } catch (error) {
    log.error('Error scanning Python dependencies', { error });
  }
  
  return dependencies;
}

/**
 * Check for unused Python dependencies
 */
async function checkUnusedPythonDependencies(
  dependencies: DependencyInfo[],
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Group dependencies by their manifest path
    const depsByManifest: Record<string, DependencyInfo[]> = {};
    
    for (const dep of dependencies) {
      if (!depsByManifest[dep.manifestPath]) {
        depsByManifest[dep.manifestPath] = [];
      }
      depsByManifest[dep.manifestPath].push(dep);
    }
    
    // Check each project separately
    for (const [manifestPath, deps] of Object.entries(depsByManifest)) {
      const projectDir = path.dirname(manifestPath);
      
      // Find all Python files in the project
      const sourceFiles = await glob('**/*.py', {
        cwd: projectDir,
        absolute: true,
        ignore: [
          'venv/**',
          '.venv/**',
          'env/**',
          '.env/**'
        ]
      });
      
      // Read all source files and create a combined content string
      let combinedContent = '';
      for (const filePath of sourceFiles) {
        try {
          const content = await readFileAsync(filePath, 'utf8');
          combinedContent += content + '\n';
        } catch (fileError) {
          log.debug(`Error reading file ${filePath}`, { error: fileError });
        }
      }
      
      // Check each dependency for usage
      for (const dep of deps) {
        // Skip dev dependencies as they might be used in tests or development tools
        if (dep.type === 'dev') continue;
        
        // Check if the dependency name appears in the source code
        // This is a simplified check - a complete solution would parse imports properly
        if (!combinedContent.includes(`import ${dep.name}`) && 
            !combinedContent.includes(`from ${dep.name} import`) && 
            !combinedContent.includes(`import ${dep.name.replace('-', '_')}`) && 
            !combinedContent.includes(`from ${dep.name.replace('-', '_')} import`)) {
          
          dep.isUnused = true;
        }
      }
    }
  } catch (error) {
    log.error('Error checking for unused Python dependencies', { error });
  }
}

/**
 * Scan for Java dependencies
 */
async function scanJavaDependencies(
  config: DependencyScannerConfig
): Promise<DependencyInfo[]> {
  const dependencies: DependencyInfo[] = [];
  
  try {
    // Find pom.xml files (Maven)
    const pomPaths = await glob('**/pom.xml', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/target/**'
      ]
    });
    
    for (const pomPath of pomPaths) {
      try {
        const content = await readFileAsync(pomPath, 'utf8');
        
        // Extract dependencies - this is a simplified approach
        // A complete solution would use an XML parser
        const dependencyMatches = content.match(/<dependency>[\s\S]*?<\/dependency>/g) || [];
        
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
            
            // Determine dependency type based on scope
            let type: 'direct' | 'dev' | 'peer' | 'optional' | 'transitive' = 'direct';
            if (scope === 'test') {
              type = 'dev';
            } else if (scope === 'provided') {
              type = 'peer';
            } else if (scope === 'runtime') {
              type = 'direct';
            }
            
            dependencies.push({
              name: `${groupId}:${artifactId}`,
              version,
              type,
              packageManager: 'maven',
              manifestPath: pomPath
            });
          }
        }
      } catch (pomError) {
        log.warn(`Error processing pom.xml at ${pomPath}`, { error: pomError });
      }
    }
    
    // Find build.gradle files (Gradle)
    const gradlePaths = await glob('**/build.gradle{,.kts}', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/build/**'
      ]
    });
    
    for (const gradlePath of gradlePaths) {
      try {
        const content = await readFileAsync(gradlePath, 'utf8');
        
        // Match different Gradle dependency formats
        // This is a simplified approach - a complete solution would use a proper Gradle parser
        
        // Format: implementation 'group:artifact:version'
        let dependencyMatches = content.match(/(?:implementation|api|compile|testImplementation|testCompile|runtimeOnly|compileOnly)\s+['"](.*?)['"]\)?/g) || [];
        
        for (const depMatch of dependencyMatches) {
          const typeMatch = depMatch.match(/^(\w+)/);
          const coordsMatch = depMatch.match(/['"]([^'"]+)['"]/);
          
          if (typeMatch && coordsMatch) {
            const depType = typeMatch[1].trim();
            const coords = coordsMatch[1].trim();
            
            // Split coordinates
            const parts = coords.split(':');
            if (parts.length >= 2) {
              const groupId = parts[0].trim();
              const artifactId = parts[1].trim();
              const version = parts.length > 2 ? parts[2].trim() : 'unknown';
              
              // Determine dependency type based on Gradle configuration
              let type: 'direct' | 'dev' | 'peer' | 'optional' | 'transitive' = 'direct';
              if (depType.startsWith('test')) {
                type = 'dev';
              } else if (depType === 'compileOnly') {
                type = 'peer';
              } else if (depType === 'runtimeOnly') {
                type = 'direct';
              }
              
              dependencies.push({
                name: `${groupId}:${artifactId}`,
                version,
                type,
                packageManager: 'gradle',
                manifestPath: gradlePath
              });
            }
          }
        }
        
        // Format: implementation(group: 'org.example', name: 'library', version: '1.0')
        dependencyMatches = content.match(/(?:implementation|api|compile|testImplementation|testCompile|runtimeOnly|compileOnly)\s*\([^)]*group\s*:\s*['"]([^'"]+)['"]\s*,\s*name\s*:\s*['"]([^'"]+)['"]\s*,\s*version\s*:\s*['"]([^'"]+)['"][^)]*\)/g) || [];
        
        for (const depMatch of dependencyMatches) {
          const typeMatch = depMatch.match(/^(\w+)/);
          const groupMatch = depMatch.match(/group\s*:\s*['"]([^'"]+)['"]/);
          const nameMatch = depMatch.match(/name\s*:\s*['"]([^'"]+)['"]/);
          const versionMatch = depMatch.match(/version\s*:\s*['"]([^'"]+)['"]/);
          
          if (typeMatch && groupMatch && nameMatch) {
            const depType = typeMatch[1].trim();
            const groupId = groupMatch[1].trim();
            const artifactId = nameMatch[1].trim();
            const version = versionMatch ? versionMatch[1].trim() : 'unknown';
            
            // Determine dependency type based on Gradle configuration
            let type: 'direct' | 'dev' | 'peer' | 'optional' | 'transitive' = 'direct';
            if (depType.startsWith('test')) {
              type = 'dev';
            } else if (depType === 'compileOnly') {
              type = 'peer';
            } else if (depType === 'runtimeOnly') {
              type = 'direct';
            }
            
            dependencies.push({
              name: `${groupId}:${artifactId}`,
              version,
              type,
              packageManager: 'gradle',
              manifestPath: gradlePath
            });
          }
        }
      } catch (gradleError) {
        log.warn(`Error processing build.gradle at ${gradlePath}`, { error: gradleError });
      }
    }
  } catch (error) {
    log.error('Error scanning Java dependencies', { error });
  }
  
  return dependencies;
}

/**
 * Scan for PHP dependencies
 */
async function scanPhpDependencies(
  config: DependencyScannerConfig
): Promise<DependencyInfo[]> {
  const dependencies: DependencyInfo[] = [];
  
  try {
    // Find composer.json files
    const composerPaths = await glob('**/composer.json', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/vendor/**'
      ]
    });
    
    for (const composerPath of composerPaths) {
      try {
        const content = await readFileAsync(composerPath, 'utf8');
        const composerJson = JSON.parse(content);
        
        // Process require dependencies
        if (composerJson.require) {
          for (const [name, versionSpec] of Object.entries(composerJson.require)) {
            // Skip PHP itself
            if (name === 'php') continue;
            
            const version = String(versionSpec).replace(/[^0-9.]/g, '') || 'unknown';
            
            dependencies.push({
              name,
              version,
              type: 'direct',
              packageManager: 'composer',
              manifestPath: composerPath
            });
          }
        }
        
        // Process require-dev dependencies
        if (composerJson['require-dev']) {
          for (const [name, versionSpec] of Object.entries(composerJson['require-dev'])) {
            const version = String(versionSpec).replace(/[^0-9.]/g, '') || 'unknown';
            
            dependencies.push({
              name,
              version,
              type: 'dev',
              packageManager: 'composer',
              manifestPath: composerPath
            });
          }
        }
      } catch (composerError) {
        log.warn(`Error processing composer.json at ${composerPath}`, { error: composerError });
      }
    }
  } catch (error) {
    log.error('Error scanning PHP dependencies', { error });
  }
  
  return dependencies;
}

/**
 * Scan for .NET dependencies
 */
async function scanDotNetDependencies(
  config: DependencyScannerConfig
): Promise<DependencyInfo[]> {
  const dependencies: DependencyInfo[] = [];
  
  try {
    // Find .csproj files
    const csprojPaths = await glob('**/*.{csproj,fsproj,vbproj}', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/bin/**',
        '**/obj/**'
      ]
    });
    
    for (const csprojPath of csprojPaths) {
      try {
        const content = await readFileAsync(csprojPath, 'utf8');
        
        // Extract package references
        // This is a simplified approach - a complete solution would use an XML parser
        const packageRefMatches = content.match(/<PackageReference[^>]*>/g) || [];
        
        for (const refMatch of packageRefMatches) {
          const includeMatch = refMatch.match(/Include="([^"]+)"/i);
          const versionMatch = refMatch.match(/Version="([^"]+)"/i);
          
          if (includeMatch) {
            const name = includeMatch[1].trim();
            const version = versionMatch ? versionMatch[1].trim() : 'unknown';
            
            // Check if it's a development dependency
            const privateAssetsMatch = refMatch.match(/PrivateAssets="([^"]+)"/i);
            const isDevDependency = privateAssetsMatch && privateAssetsMatch[1].includes('all');
            
            dependencies.push({
              name,
              version,
              type: isDevDependency ? 'dev' : 'direct',
              packageManager: 'nuget',
              manifestPath: csprojPath
            });
          }
        }
        
        // Extract project references
        const projectRefMatches = content.match(/<ProjectReference[^>]*>/g) || [];
        
        for (const refMatch of projectRefMatches) {
          const includeMatch = refMatch.match(/Include="([^"]+)"/i);
          
          if (includeMatch) {
            const projectPath = includeMatch[1].trim();
            const projectName = path.basename(projectPath, path.extname(projectPath));
            
            dependencies.push({
              name: projectName,
              version: 'local',
              type: 'direct',
              packageManager: 'nuget',
              manifestPath: csprojPath
            });
          }
        }
      } catch (csprojError) {
        log.warn(`Error processing .csproj at ${csprojPath}`, { error: csprojError });
      }
    }
    
    // Find packages.config files (older NuGet format)
    const packagesConfigPaths = await glob('**/packages.config', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/bin/**',
        '**/obj/**'
      ]
    });
    
    for (const packagesConfigPath of packagesConfigPaths) {
      try {
        const content = await readFileAsync(packagesConfigPath, 'utf8');
        
        // Extract package references
        const packageMatches = content.match(/<package[^>]*>/g) || [];
        
        for (const packageMatch of packageMatches) {
          const idMatch = packageMatch.match(/id="([^"]+)"/i);
          const versionMatch = packageMatch.match(/version="([^"]+)"/i);
          const developmentDependencyMatch = packageMatch.match(/developmentDependency="([^"]+)"/i);
          
          if (idMatch && versionMatch) {
            const name = idMatch[1].trim();
            const version = versionMatch[1].trim();
            const isDevDependency = developmentDependencyMatch && developmentDependencyMatch[1].toLowerCase() === 'true';
            
            dependencies.push({
              name,
              version,
              type: isDevDependency ? 'dev' : 'direct',
              packageManager: 'nuget',
              manifestPath: packagesConfigPath
            });
          }
        }
      } catch (packagesConfigError) {
        log.warn(`Error processing packages.config at ${packagesConfigPath}`, { error: packagesConfigError });
      }
    }
  } catch (error) {
    log.error('Error scanning .NET dependencies', { error });
  }
  
  return dependencies;
}

/**
 * Scan for Rust dependencies
 */
async function scanRustDependencies(
  config: DependencyScannerConfig
): Promise<DependencyInfo[]> {
  const dependencies: DependencyInfo[] = [];
  
  try {
    // Find Cargo.toml files
    const cargoTomlPaths = await glob('**/Cargo.toml', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/target/**'
      ]
    });
    
    for (const cargoTomlPath of cargoTomlPaths) {
      try {
        const content = await readFileAsync(cargoTomlPath, 'utf8');
        const lines = content.split('\n');
        
        let inDependencies = false;
        let inDevDependencies = false;
        let inBuildDependencies = false;
        
        for (const line of lines) {
          // Skip comments and empty lines
          if (line.trim().startsWith('#') || !line.trim()) {
            continue;
          }
          
          // Check for section headers
          if (line.trim() === '[dependencies]') {
            inDependencies = true;
            inDevDependencies = false;
            inBuildDependencies = false;
            continue;
          } else if (line.trim() === '[dev-dependencies]') {
            inDependencies = false;
            inDevDependencies = true;
            inBuildDependencies = false;
            continue;
          } else if (line.trim() === '[build-dependencies]') {
            inDependencies = false;
            inDevDependencies = false;
            inBuildDependencies = true;
            continue;
          } else if (line.trim().startsWith('[') && line.trim().endsWith(']')) {
            inDependencies = false;
            inDevDependencies = false;
            inBuildDependencies = false;
            continue;
          }
          
          if (inDependencies || inDevDependencies || inBuildDependencies) {
            // Simple key = "value" format
            let match = line.match(/^([\w_-]+)\s*=\s*["']([^"']+)["']/);
            
            if (match) {
              const name = match[1].trim();
              const version = match[2].trim();
              
              dependencies.push({
                name,
                version,
                type: inDevDependencies ? 'dev' : inBuildDependencies ? 'dev' : 'direct',
                packageManager: 'cargo',
                manifestPath: cargoTomlPath
              });
              continue;
            }
            
            // Complex format with table
            match = line.match(/^([\w_-]+)\s*=\s*\{/);
            
            if (match) {
              const name = match[1].trim();
              
              // Try to find the version in this line or the next few lines
              let versionMatch = line.match(/version\s*=\s*["']([^"']+)["']/);
              if (!versionMatch) {
                // Look in the next 5 lines at most
                for (let i = 1; i <= 5; i++) {
                  const lineIndex = lines.indexOf(line) + i;
                  if (lineIndex < lines.length) {
                    versionMatch = lines[lineIndex].match(/version\s*=\s*["']([^"']+)["']/);
                    if (versionMatch) break;
                  }
                }
              }
              
              const version = versionMatch ? versionMatch[1].trim() : 'unknown';
              
              dependencies.push({
                name,
                version,
                type: inDevDependencies ? 'dev' : inBuildDependencies ? 'dev' : 'direct',
                packageManager: 'cargo',
                manifestPath: cargoTomlPath
              });
            }
          }
        }
      } catch (cargoTomlError) {
        log.warn(`Error processing Cargo.toml at ${cargoTomlPath}`, { error: cargoTomlError });
      }
    }
  } catch (error) {
    log.error('Error scanning Rust dependencies', { error });
  }
  
  return dependencies;
}

/**
 * Scan for Go dependencies
 */
async function scanGoDependencies(
  config: DependencyScannerConfig
): Promise<DependencyInfo[]> {
  const dependencies: DependencyInfo[] = [];
  
  try {
    // Find go.mod files
    const goModPaths = await glob('**/go.mod', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || [])
      ]
    });
    
    for (const goModPath of goModPaths) {
      try {
        const content = await readFileAsync(goModPath, 'utf8');
        const lines = content.split('\n');
        
        // Get module name (first line: module github.com/example/myproject)
        const moduleLine = lines.find(line => line.trim().startsWith('module '));
        const moduleName = moduleLine ? moduleLine.replace('module', '').trim() : 'unknown';
        
        // Find require sections
        let inRequireBlock = false;
        for (const line of lines) {
          const trimmedLine = line.trim();
          
          if (trimmedLine === 'require (') {
            inRequireBlock = true;
            continue;
          }
          
          if (inRequireBlock && trimmedLine === ')') {
            inRequireBlock = false;
            continue;
          }
          
          // Single-line require: require github.com/example/package v1.2.3
          if (trimmedLine.startsWith('require ') && !inRequireBlock) {
            const parts = trimmedLine.replace('require ', '').trim().split(' ');
            if (parts.length >= 2) {
              const name = parts[0].trim();
              const version = parts[1].trim();
              
              dependencies.push({
                name,
                version,
                type: 'direct',
                packageManager: 'go',
                manifestPath: goModPath
              });
            }
          }
          
          // Multi-line require block
          if (inRequireBlock && trimmedLine && !trimmedLine.startsWith('//')) {
            const parts = trimmedLine.split(' ');
            if (parts.length >= 2) {
              const name = parts[0].trim();
              const version = parts[1].trim();
              
              dependencies.push({
                name,
                version,
                type: 'direct',
                packageManager: 'go',
                manifestPath: goModPath
              });
            }
          }
        }
      } catch (goModError) {
        log.warn(`Error processing go.mod at ${goModPath}`, { error: goModError });
      }
    }
  } catch (error) {
    log.error('Error scanning Go dependencies', { error });
  }
  
  return dependencies;
}

/**
 * Scan for Ruby dependencies
 */
async function scanRubyDependencies(
  config: DependencyScannerConfig
): Promise<DependencyInfo[]> {
  const dependencies: DependencyInfo[] = [];
  
  try {
    // Find Gemfile files
    const gemfilePaths = await glob('**/Gemfile', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || [])
      ]
    });
    
    for (const gemfilePath of gemfilePaths) {
      try {
        const content = await readFileAsync(gemfilePath, 'utf8');
        const lines = content.split('\n');
        
        for (const line of lines) {
          // Skip comments and empty lines
          if (line.trim().startsWith('#') || !line.trim()) {
            continue;
          }
          
          // Match gem declarations with version
          const gemMatch = line.match(/^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]?([^'"\s]+)['"]?)?/);
          
          if (gemMatch) {
            const name = gemMatch[1].trim();
            const version = gemMatch[2] ? gemMatch[2].trim() : 'unknown';
            
            let type: 'direct' | 'dev' | 'peer' | 'optional' | 'transitive' = 'direct';
            
            // Check if it's in a group block (simplified - a complete solution would track blocks)
            if (line.includes(':development') || line.includes(':test')) {
              type = 'dev';
            }
            
            dependencies.push({
              name,
              version,
              type,
              packageManager: 'gem',
              manifestPath: gemfilePath
            });
          }
        }
      } catch (gemfileError) {
        log.warn(`Error processing Gemfile at ${gemfilePath}`, { error: gemfileError });
      }
    }
    
    // Find .gemspec files
    const gemspecPaths = await glob('**/*.gemspec', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || [])
      ]
    });
    
    for (const gemspecPath of gemspecPaths) {
      try {
        const content = await readFileAsync(gemspecPath, 'utf8');
        const lines = content.split('\n');
        
        for (const line of lines) {
          // Skip comments and empty lines
          if (line.trim().startsWith('#') || !line.trim()) {
            continue;
          }
          
          // Match add_dependency and add_development_dependency declarations
          const depMatch = line.match(/\.(add_(?:development_)?dependency)\s*\(['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?/);
          
          if (depMatch) {
            const method = depMatch[1].trim();
            const name = depMatch[2].trim();
            const version = depMatch[3] ? depMatch[3].trim() : 'unknown';
            
            const type: 'direct' | 'dev' = method.includes('development') ? 'dev' : 'direct';
            
            dependencies.push({
              name,
              version,
              type,
              packageManager: 'gem',
              manifestPath: gemspecPath
            });
          }
        }
      } catch (gemspecError) {
        log.warn(`Error processing .gemspec at ${gemspecPath}`, { error: gemspecError });
      }
    }
  } catch (error) {
    log.error('Error scanning Ruby dependencies', { error });
  }
  
  return dependencies;
}

/**
 * Scan for iOS/macOS dependencies
 */
async function scanAppleDependencies(
  config: DependencyScannerConfig
): Promise<DependencyInfo[]> {
  const dependencies: DependencyInfo[] = [];
  
  try {
    // Find Podfile files (CocoaPods)
    const podfilePaths = await glob('**/Podfile', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || [])
      ]
    });
    
    for (const podfilePath of podfilePaths) {
      try {
        const content = await readFileAsync(podfilePath, 'utf8');
        const lines = content.split('\n');
        
        let currentTarget = '';
        
        for (const line of lines) {
          // Skip comments and empty lines
          if (line.trim().startsWith('#') || !line.trim()) {
            continue;
          }
          
          // Check for target definitions
          const targetMatch = line.match(/target\s+['"]([^'"]+)['"]\s+do/);
          if (targetMatch) {
            currentTarget = targetMatch[1].trim();
            continue;
          }
          
          // Check for pod declarations
          const podMatch = line.match(/pod\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?/);
          
          if (podMatch) {
            const name = podMatch[1].trim();
            const version = podMatch[2] ? podMatch[2].trim() : 'unknown';
            
            dependencies.push({
              name,
              version,
              type: 'direct',
              packageManager: 'cocoapods',
              manifestPath: podfilePath
            });
          }
        }
      } catch (podfileError) {
        log.warn(`Error processing Podfile at ${podfilePath}`, { error: podfileError });
      }
    }
    
    // Find Package.swift files (Swift Package Manager)
    const packageSwiftPaths = await glob('**/Package.swift', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || [])
      ]
    });
    
    for (const packageSwiftPath of packageSwiftPaths) {
      try {
        const content = await readFileAsync(packageSwiftPath, 'utf8');
        
        // This is a very simplified parser for Swift Package dependencies
        // A complete solution would use a Swift parser
        
        // Match dependency declarations
        const dependencies_section = content.match(/dependencies\s*:\s*\[([^\]]+)\]/s);
        
        if (dependencies_section && dependencies_section[1]) {
          const dependenciesBlock = dependencies_section[1];
          
          // Match package dependencies
          const packageMatches = dependenciesBlock.match(/\.package\s*\(\s*url\s*:\s*["']([^"']+)["']\s*,\s*(?:from\s*:|exact\s*:|branch\s*:|revision\s*:)\s*["']([^"']+)["']/g) || [];
          
          for (const packageMatch of packageMatches) {
            const urlMatch = packageMatch.match(/url\s*:\s*["']([^"']+)["']/);
            const versionMatch = packageMatch.match(/(?:from|exact|branch|revision)\s*:\s*["']([^"']+)["']/);
            
            if (urlMatch) {
              const url = urlMatch[1].trim();
              const version = versionMatch ? versionMatch[1].trim() : 'unknown';
              
              // Extract name from URL
              const urlParts = url.split('/');
              const name = urlParts.length > 0 ? urlParts[urlParts.length - 1] : url;
              
              dependencies.push({
                name,
                version,
                type: 'direct',
                packageManager: 'swift',
                manifestPath: packageSwiftPath
              });
            }
          }
        }
      } catch (packageSwiftError) {
        log.warn(`Error processing Package.swift at ${packageSwiftPath}`, { error: packageSwiftError });
      }
    }
  } catch (error) {
    log.error('Error scanning iOS/macOS dependencies', { error });
  }
  
  return dependencies;
}

/**
 * Check dependency for issues
 */
async function checkDependencyForIssues(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Check for updates
    await checkForDependencyUpdates(dep, config);
    
    // Check for vulnerabilities if configured
    if (config.checkVulnerabilities) {
      await checkForDependencyVulnerabilities(dep, config);
    }
    
    // Check for license issues if configured
    if (config.checkLicenses) {
      await checkDependencyLicense(dep, config);
    }
    
    // Check if dependency is maintained if configured
    if (config.checkMaintained) {
      await checkIfDependencyMaintained(dep, config);
    }
  } catch (error) {
    log.warn(`Error checking dependency ${dep.name} for issues`, { error });
  }
}

/**
 * Check if dependency has available updates
 */
async function checkForDependencyUpdates(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use different approaches based on package manager
    switch (dep.packageManager) {
      case 'npm':
      case 'yarn':
      case 'pnpm':
        await checkNpmUpdates(dep, config);
        break;
      case 'pip':
      case 'pipenv':
      case 'poetry':
        await checkPyPIUpdates(dep, config);
        break;
      case 'maven':
      case 'gradle':
        await checkMavenUpdates(dep, config);
        break;
      case 'composer':
        await checkPackagistUpdates(dep, config);
        break;
      case 'nuget':
        await checkNuGetUpdates(dep, config);
        break;
      case 'cargo':
        await checkCargoUpdates(dep, config);
        break;
      case 'go':
        await checkGoUpdates(dep, config);
        break;
      case 'gem':
        await checkRubyGemsUpdates(dep, config);
        break;
      case 'cocoapods':
        await checkCocoaPodsUpdates(dep, config);
        break;
      case 'swift':
        await checkSwiftUpdates(dep, config);
        break;
    }
  } catch (error) {
    log.warn(`Error checking updates for dependency ${dep.name}`, { error });
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
    const { stdout } = await execAsync(`npm view ${dep.name} dist-tags.latest time --json`);
    
    try {
      const info = JSON.parse(stdout.trim());
      dep.latestVersion = info['dist-tags'] ? info['dist-tags'].latest : Object.keys(info.time).pop();
      
      // Get last publish date
      if (info.time && dep.latestVersion) {
        dep.lastPublishDate = new Date(info.time[dep.latestVersion]);
      }
      
      // Compare versions to determine if outdated
      if (dep.version !== 'unknown' && dep.version !== 'local' && dep.latestVersion !== dep.version) {
        // Use semver to compare versions if available
        try {
          const semver = require('semver');
          dep.isOutdated = semver.lt(dep.version, dep.latestVersion);
          
          // Check if update is breaking (major version change)
          if (dep.isOutdated) {
            const currentMajor = semver.major(dep.version);
            const latestMajor = semver.major(dep.latestVersion);
            dep.upgradeBreaking = currentMajor < latestMajor;
          }
        } catch (semverError) {
          // Basic version comparison if semver is not available
          dep.isOutdated = dep.version !== dep.latestVersion;
          dep.upgradeBreaking = false;
        }
      }
      
      // Try to get repository and homepage URLs
      try {
        const { stdout: pkgInfo } = await execAsync(`npm view ${dep.name} repository.url homepage --json`);
        const pkgInfoJson = JSON.parse(pkgInfo.trim());
        
        dep.repositoryUrl = pkgInfoJson.repository ? pkgInfoJson.repository.url : undefined;
        dep.homepageUrl = pkgInfoJson.homepage;
      } catch (pkgInfoError) {
        log.debug(`Error getting package info for ${dep.name}`, { error: pkgInfoError });
      }
    } catch (jsonError) {
      log.warn(`Error parsing npm view output for ${dep.name}`, { error: jsonError });
    }
  } catch (error) {
    log.warn(`Error checking NPM updates for ${dep.name}`, { error });
  }
}

/**
 * Check for PyPI package updates
 */
async function checkPyPIUpdates(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use PyPI API to check for latest version
    const { stdout } = await execAsync(`curl -s https://pypi.org/pypi/${dep.name}/json`);
    
    try {
      const packageInfo = JSON.parse(stdout);
      dep.latestVersion = packageInfo.info.version;
      
      // Get last release date
      if (packageInfo.releases && dep.latestVersion && packageInfo.releases[dep.latestVersion]) {
        const releaseInfo = packageInfo.releases[dep.latestVersion][0];
        if (releaseInfo && releaseInfo.upload_time) {
          dep.lastPublishDate = new Date(releaseInfo.upload_time);
        }
      }
      
      // Compare versions to determine if outdated
      if (dep.version !== 'unknown' && dep.version !== 'local' && dep.latestVersion !== dep.version) {
        // Basic version comparison for Python packages
        dep.isOutdated = dep.version !== dep.latestVersion;
        
        // Try to determine if update is breaking (major version change)
        try {
          const currentParts = dep.version.split('.');
          const latestParts = dep.latestVersion.split('.');
          
          if (currentParts.length > 0 && latestParts.length > 0) {
            const currentMajor = parseInt(currentParts[0], 10);
            const latestMajor = parseInt(latestParts[0], 10);
            dep.upgradeBreaking = currentMajor < latestMajor;
          }
        } catch (parseError) {
          dep.upgradeBreaking = false;
        }
      }
      
      // Get repository and homepage URLs
      dep.homepageUrl = packageInfo.info.home_page;
      dep.repositoryUrl = packageInfo.info.project_urls?.Source || packageInfo.info.project_urls?.Homepage;
      
      // Get author info
      dep.author = packageInfo.info.author;
    } catch (jsonError) {
      log.warn(`Error parsing PyPI API output for ${dep.name}`, { error: jsonError });
    }
  } catch (error) {
    log.warn(`Error checking PyPI updates for ${dep.name}`, { error });
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
    
    if (!groupId || !artifactId) {
      log.warn(`Invalid Maven dependency name: ${dep.name}`);
      return;
    }
    
    // Use Maven Central API to check for latest version
    const { stdout } = await execAsync(`curl -s "https://search.maven.org/solrsearch/select?q=g:%22${groupId}%22+AND+a:%22${artifactId}%22&rows=1&wt=json"`);
    
    try {
      const searchResult = JSON.parse(stdout);
      
      if (searchResult.response && searchResult.response.docs && searchResult.response.docs.length > 0) {
        dep.latestVersion = searchResult.response.docs[0].latestVersion;
        dep.lastPublishDate = new Date(searchResult.response.docs[0].timestamp);
        
        // Compare versions to determine if outdated
        if (dep.version !== 'unknown' && dep.version !== 'local' && dep.latestVersion !== dep.version) {
          // Basic version comparison for Maven packages
          dep.isOutdated = dep.version !== dep.latestVersion;
          
          // Try to determine if update is breaking (major version change)
          try {
            const currentParts = dep.version.split('.');
            const latestParts = dep.latestVersion.split('.');
            
            if (currentParts.length > 0 && latestParts.length > 0) {
              const currentMajor = parseInt(currentParts[0], 10);
              const latestMajor = parseInt(latestParts[0], 10);
              dep.upgradeBreaking = currentMajor < latestMajor;
            }
          } catch (parseError) {
            dep.upgradeBreaking = false;
          }
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
 * Check for Packagist updates (PHP/Composer)
 */
async function checkPackagistUpdates(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use Packagist API to check for latest version
    const { stdout } = await execAsync(`curl -s https://repo.packagist.org/p2/${dep.name}.json`);
    
    try {
      const packageInfo = JSON.parse(stdout);
      
      if (packageInfo.packages && packageInfo.packages[dep.name]) {
        const versions = Object.keys(packageInfo.packages[dep.name])
          .filter(v => !v.includes('-') && !v.includes('dev') && !v.includes('alpha') && !v.includes('beta') && !v.includes('RC'));
        
        if (versions.length > 0) {
          // Sort versions and get the latest
          versions.sort((a, b) => {
            try {
              const semver = require('semver');
              return semver.gt(a, b) ? -1 : 1;
            } catch (semverError) {
              return a > b ? -1 : 1; // Basic comparison
            }
          });
          
          dep.latestVersion = versions[0];
          
          // Get last release date and other metadata
          const latestVersionInfo = packageInfo.packages[dep.name][dep.latestVersion];
          if (latestVersionInfo) {
            if (latestVersionInfo.time) {
              dep.lastPublishDate = new Date(latestVersionInfo.time);
            }
            
            dep.homepageUrl = latestVersionInfo.homepage;
            dep.repositoryUrl = latestVersionInfo.source?.url;
            dep.author = latestVersionInfo.authors?.[0]?.name;
          }
          
          // Compare versions to determine if outdated
          if (dep.version !== 'unknown' && dep.version !== 'local' && dep.latestVersion !== dep.version) {
            // Use semver to compare versions if available
            try {
              const semver = require('semver');
              dep.isOutdated = semver.lt(dep.version, dep.latestVersion);
              
              // Check if update is breaking (major version change)
              if (dep.isOutdated) {
                const currentMajor = semver.major(dep.version);
                const latestMajor = semver.major(dep.latestVersion);
                dep.upgradeBreaking = currentMajor < latestMajor;
              }
            } catch (semverError) {
              // Basic version comparison if semver is not available
              dep.isOutdated = dep.version !== dep.latestVersion;
              dep.upgradeBreaking = false;
            }
          }
        }
      }
    } catch (jsonError) {
      log.warn(`Error parsing Packagist API output for ${dep.name}`, { error: jsonError });
    }
  } catch (error) {
    log.warn(`Error checking Packagist updates for ${dep.name}`, { error });
  }
}

/**
 * Check for NuGet updates (.NET)
 */
async function checkNuGetUpdates(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use NuGet API to check for latest version
    const { stdout } = await execAsync(`curl -s "https://api-v2v3search-0.nuget.org/query?q=PackageId:${dep.name}&prerelease=false"`);
    
    try {
      const searchResult = JSON.parse(stdout);
      
      if (searchResult.data && searchResult.data.length > 0) {
        // Find exact match for the package
        const pkg = searchResult.data.find((p: any) => p.id.toLowerCase() === dep.name.toLowerCase());
        
        if (pkg) {
          dep.latestVersion = pkg.version;
          dep.homepageUrl = pkg.projectUrl;
          dep.repositoryUrl = pkg.repositoryUrl;
          dep.author = pkg.authors;
          
          // Get last publish date if available
          if (pkg.lastUpdated) {
            dep.lastPublishDate = new Date(pkg.lastUpdated);
          }
          
          // Compare versions to determine if outdated
          if (dep.version !== 'unknown' && dep.version !== 'local' && dep.latestVersion !== dep.version) {
            // Use semver to compare versions if available
            try {
              const semver = require('semver');
              dep.isOutdated = semver.lt(dep.version, dep.latestVersion);
              
              // Check if update is breaking (major version change)
              if (dep.isOutdated) {
                const currentMajor = semver.major(dep.version);
                const latestMajor = semver.major(dep.latestVersion);
                dep.upgradeBreaking = currentMajor < latestMajor;
              }
            } catch (semverError) {
              // Basic version comparison if semver is not available
              dep.isOutdated = dep.version !== dep.latestVersion;
              dep.upgradeBreaking = false;
            }
          }
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
 * Check for Cargo updates (Rust)
 */
async function checkCargoUpdates(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use crates.io API to check for latest version
    const { stdout } = await execAsync(`curl -s https://crates.io/api/v1/crates/${dep.name}`);
    
    try {
      const crateInfo = JSON.parse(stdout);
      
      if (crateInfo.crate) {
        dep.latestVersion = crateInfo.crate.max_stable_version;
        dep.homepageUrl = crateInfo.crate.homepage;
        dep.repositoryUrl = crateInfo.crate.repository;
        
        // Get last publish date
        if (crateInfo.versions && crateInfo.versions.length > 0) {
          dep.lastPublishDate = new Date(crateInfo.versions[0].updated_at);
        }
        
        // Compare versions to determine if outdated
        if (dep.version !== 'unknown' && dep.version !== 'local' && dep.latestVersion !== dep.version) {
            // Use semver to compare versions if available
            try {
              const semver = require('semver');
              dep.isOutdated = semver.lt(dep.version, dep.latestVersion);
              
              // Check if update is breaking (major version change)
              if (dep.isOutdated) {
                const currentMajor = semver.major(dep.version);
                const latestMajor = semver.major(dep.latestVersion);
                dep.upgradeBreaking = currentMajor < latestMajor;
              }
            } catch (semverError) {
              // Basic version comparison if semver is not available
              dep.isOutdated = dep.version !== dep.latestVersion;
              dep.upgradeBreaking = false;
            }
          }
      }
    } catch (jsonError) {
      log.warn(`Error parsing crates.io API output for ${dep.name}`, { error: jsonError });
    }
  } catch (error) {
    log.warn(`Error checking Cargo updates for ${dep.name}`, { error });
  }
}

/**
 * Check for Go module updates
 */
async function checkGoUpdates(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use proxy.golang.org API to check for latest version
    const { stdout } = await execAsync(`curl -s "https://proxy.golang.org/${dep.name}/@v/list"`);
    
    if (stdout.trim()) {
      const versions = stdout.trim().split('\n');
      
      // Filter out pre-releases and get the latest version
      const stableVersions = versions.filter(v => 
        !v.includes('-beta') && 
        !v.includes('-alpha') && 
        !v.includes('-rc')
      );
      
      if (stableVersions.length > 0) {
        // Sort versions and get the latest
        stableVersions.sort((a, b) => {
          try {
            const semver = require('semver');
            return semver.gt(a, b) ? -1 : 1;
          } catch (semverError) {
            return a > b ? -1 : 1; // Basic comparison
          }
        });
        
        dep.latestVersion = stableVersions[0];
        
        // Compare versions to determine if outdated
        if (dep.version !== 'unknown' && dep.version !== 'local' && dep.latestVersion !== dep.version) {
          // Use semver to compare versions if available
          try {
            const semver = require('semver');
            dep.isOutdated = semver.lt(dep.version, dep.latestVersion);
            
            // Check if update is breaking (major version change)
            if (dep.isOutdated) {
              const currentMajor = semver.major(dep.version);
              const latestMajor = semver.major(dep.latestVersion);
              dep.upgradeBreaking = currentMajor < latestMajor;
            }
          } catch (semverError) {
            // Basic version comparison if semver is not available
            dep.isOutdated = dep.version !== dep.latestVersion;
            dep.upgradeBreaking = false;
          }
        }
      }
    }
  } catch (error) {
    log.warn(`Error checking Go updates for ${dep.name}`, { error });
  }
}

/**
 * Check for RubyGems updates
 */
async function checkRubyGemsUpdates(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use RubyGems API to check for latest version
    const { stdout } = await execAsync(`curl -s https://rubygems.org/api/v1/gems/${dep.name}.json`);
    
    try {
      const gemInfo = JSON.parse(stdout);
      
      dep.latestVersion = gemInfo.version;
      dep.homepageUrl = gemInfo.homepage_uri || gemInfo.project_uri;
      dep.repositoryUrl = gemInfo.source_code_uri;
      dep.author = gemInfo.authors;
      
      // Get last publish date
      if (gemInfo.version_created_at) {
        dep.lastPublishDate = new Date(gemInfo.version_created_at);
      }
      
      // Compare versions to determine if outdated
      if (dep.version !== 'unknown' && dep.version !== 'local' && dep.latestVersion !== dep.version) {
        // Use semver to compare versions if available
        try {
          const semver = require('semver');
          dep.isOutdated = semver.lt(dep.version, dep.latestVersion);
          
          // Check if update is breaking (major version change)
          if (dep.isOutdated) {
            const currentMajor = semver.major(dep.version);
            const latestMajor = semver.major(dep.latestVersion);
            dep.upgradeBreaking = currentMajor < latestMajor;
          }
        } catch (semverError) {
          // Basic version comparison if semver is not available
          dep.isOutdated = dep.version !== dep.latestVersion;
          dep.upgradeBreaking = false;
        }
      }
    } catch (jsonError) {
      log.warn(`Error parsing RubyGems API output for ${dep.name}`, { error: jsonError });
    }
  } catch (error) {
    log.warn(`Error checking RubyGems updates for ${dep.name}`, { error });
  }
}

/**
 * Check for CocoaPods updates
 */
async function checkCocoaPodsUpdates(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use CocoaPods API to check for latest version
    const { stdout } = await execAsync(`curl -s https://trunk.cocoapods.org/api/v1/pods/${dep.name}`);
    
    try {
      const podInfo = JSON.parse(stdout);
      
      if (podInfo.version) {
        dep.latestVersion = podInfo.version;
        
        // Compare versions to determine if outdated
        if (dep.version !== 'unknown' && dep.version !== 'local' && dep.latestVersion !== dep.version) {
          // Use semver to compare versions if available
          try {
            const semver = require('semver');
            dep.isOutdated = semver.lt(dep.version, dep.latestVersion);
            
            // Check if update is breaking (major version change)
            if (dep.isOutdated) {
              const currentMajor = semver.major(dep.version);
              const latestMajor = semver.major(dep.latestVersion);
              dep.upgradeBreaking = currentMajor < latestMajor;
            }
          } catch (semverError) {
            // Basic version comparison if semver is not available
            dep.isOutdated = dep.version !== dep.latestVersion;
            dep.upgradeBreaking = false;
          }
        }
      }
      
      // Extract other metadata if available
      if (podInfo.pod) {
        dep.homepageUrl = podInfo.pod.homepage;
        dep.repositoryUrl = podInfo.pod.source?.git;
        dep.author = podInfo.pod.authors;
      }
    } catch (jsonError) {
      log.warn(`Error parsing CocoaPods API output for ${dep.name}`, { error: jsonError });
    }
  } catch (error) {
    log.warn(`Error checking CocoaPods updates for ${dep.name}`, { error });
  }
}

/**
 * Check for Swift Package updates
 */
async function checkSwiftUpdates(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // For Swift packages, we have less standardized means to check
    // This would generally involve checking the git repository directly
    
    // If the name looks like a GitHub repository, we can try to use the GitHub API
    if (dep.name.includes('/') && !dep.name.startsWith('http')) {
      // Extract owner and repo
      const parts = dep.name.split('/');
      if (parts.length >= 2) {
        const owner = parts[parts.length - 2];
        const repo = parts[parts.length - 1];
        
        // Use GitHub API to get latest release
        try {
          const { stdout } = await execAsync(`curl -s https://api.github.com/repos/${owner}/${repo}/releases/latest`);
          
          try {
            const releaseInfo = JSON.parse(stdout);
            
            if (releaseInfo.tag_name) {
              // Extract version from tag name
              let version = releaseInfo.tag_name;
              if (version.startsWith('v')) {
                version = version.substring(1);
              }
              
              dep.latestVersion = version;
              
              // Get last release date
              if (releaseInfo.published_at) {
                dep.lastPublishDate = new Date(releaseInfo.published_at);
              }
              
              // Compare versions to determine if outdated
              if (dep.version !== 'unknown' && dep.version !== 'local' && dep.latestVersion !== dep.version) {
                // Remove 'v' prefix if present
                let currentVersion = dep.version;
                if (currentVersion.startsWith('v')) {
                  currentVersion = currentVersion.substring(1);
                }
                
                // Use semver to compare versions if available
                try {
                  const semver = require('semver');
                  dep.isOutdated = semver.lt(currentVersion, dep.latestVersion);
                  
                  // Check if update is breaking (major version change)
                  if (dep.isOutdated) {
                    const currentMajor = semver.major(currentVersion);
                    const latestMajor = semver.major(dep.latestVersion);
                    dep.upgradeBreaking = currentMajor < latestMajor;
                  }
                } catch (semverError) {
                  // Basic version comparison if semver is not available
                  dep.isOutdated = currentVersion !== dep.latestVersion;
                  dep.upgradeBreaking = false;
                }
              }
              
              // Get repository URL
              dep.repositoryUrl = releaseInfo.html_url?.replace(/\/releases\/tag\/.*$/, '');
            }
          } catch (jsonError) {
            log.warn(`Error parsing GitHub API output for ${dep.name}`, { error: jsonError });
          }
        } catch (githubError) {
          log.debug(`Error getting GitHub release info for ${dep.name}`, { error: githubError });
        }
      }
    }
  } catch (error) {
    log.warn(`Error checking Swift updates for ${dep.name}`, { error });
  }
}

/**
 * Check for dependency vulnerabilities
 */
async function checkForDependencyVulnerabilities(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Check custom database first if configured
    if (config.vulnerabilityDbPaths?.dependencies && fs.existsSync(config.vulnerabilityDbPaths.dependencies)) {
      try {
        const vulnDb = JSON.parse(await readFileAsync(config.vulnerabilityDbPaths.dependencies, 'utf8'));
        
        // Normalize dependency name for lookup (case-insensitive)
        const normalizedName = dep.name.toLowerCase();
        
        // Check for vulnerabilities by package name
        let vulnEntries = vulnDb[normalizedName];
        
        // For Java, try by groupId only if not found by full name
        if (!vulnEntries && dep.packageManager === 'maven' || dep.packageManager === 'gradle') {
          const groupId = dep.name.split(':')[0];
          if (groupId) {
            vulnEntries = vulnDb[groupId.toLowerCase()];
          }
        }
        
        if (vulnEntries) {
          processVulnerabilityData(dep, vulnEntries);
        }
      } catch (dbError) {
        log.warn(`Error reading dependency vulnerability database`, { error: dbError });
      }
    }
    
    // If no custom database or no vulnerabilities found, try to check npm audit, safety, etc.
    // based on package manager
    await checkVulnerabilitiesByPackageManager(dep, config);
  } catch (error) {
    log.warn(`Error checking vulnerabilities for dependency ${dep.name}`, { error });
  }
}

/**
 * Process vulnerability data from a database
 */
function processVulnerabilityData(
  dep: DependencyInfo,
  vulnerabilities: Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    affected_versions: string;
    fixed_in_version?: string;
    cve_ids?: string[];
    url?: string;
  }>
): void {
  const affectedVulns = vulnerabilities.filter(vuln => 
    isVersionAffected(dep.version, vuln.affected_versions)
  );
  
  if (affectedVulns.length > 0) {
    dep.vulnerabilities = affectedVulns.map(vuln => ({
      severity: vuln.severity,
      description: vuln.description,
      affectedVersions: vuln.affected_versions,
      fixedInVersion: vuln.fixed_in_version,
      url: vuln.url,
      cveIds: vuln.cve_ids
    }));
    
    dep.isVulnerable = true;
  }
}

/**
 * Check vulnerabilities by package manager
 */
async function checkVulnerabilitiesByPackageManager(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use different approaches based on package manager
    switch (dep.packageManager) {
      case 'npm':
      case 'yarn':
      case 'pnpm':
        await checkNpmVulnerabilities(dep, config);
        break;
      case 'pip':
      case 'pipenv':
      case 'poetry':
        await checkPythonVulnerabilities(dep, config);
        break;
      case 'maven':
      case 'gradle':
        await checkMavenVulnerabilities(dep, config);
        break;
      case 'composer':
        await checkComposerVulnerabilities(dep, config);
        break;
      case 'nuget':
        await checkNuGetVulnerabilities(dep, config);
        break;
      case 'cargo':
        await checkCargoVulnerabilities(dep, config);
        break;
      // Other package managers would have similar implementations
    }
  } catch (error) {
    log.warn(`Error checking vulnerabilities by package manager for ${dep.name}`, { error });
  }
}

/**
 * Check for npm vulnerabilities
 */
async function checkNpmVulnerabilities(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use npm audit API to check for vulnerabilities
    const { stdout } = await execAsync(`npm view ${dep.name} --json`);
    
    // Complete implementation would use npm audit directly on the package
    // This is a simplified approach checking security advisories
    const packageInfo = JSON.parse(stdout);
    
    // Check if the package has security advisories
    if (packageInfo.security?.vulnerabilities) {
      const vulns = [];
      
      for (const [severity, info] of Object.entries(packageInfo.security.vulnerabilities)) {
        vulns.push({
          severity: mapNpmSeverity(severity),
          description: `Security vulnerability in ${dep.name}`,
          affectedVersions: dep.version, // Simplified - would need to check version ranges
          fixedInVersion: undefined // Simplified - would need to check fixed versions
        });
      }
      
      if (vulns.length > 0) {
        dep.vulnerabilities = vulns;
        dep.isVulnerable = true;
      }
    }
  } catch (error) {
    log.debug(`Error checking npm vulnerabilities for ${dep.name}`, { error });
  }
}

/**
 * Map npm severity to standard severity
 */
function mapNpmSeverity(severity: string): 'low' | 'medium' | 'high' | 'critical' {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'moderate':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return 'medium';
  }
}

/**
 * Check for Python vulnerabilities
 */
async function checkPythonVulnerabilities(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use PyPI JSON API to check for known vulnerabilities
    const { stdout } = await execAsync(`curl -s https://pypi.org/pypi/${dep.name}/json`);
    
    try {
      const packageInfo = JSON.parse(stdout);
      
      // Check for security issues in the package info
      // This is a simplified approach - a complete solution would use safety-db
      if (packageInfo.info && packageInfo.info.classifiers) {
        const classifiers = packageInfo.info.classifiers;
        
        // Look for deprecation or security warnings in classifiers
        for (const classifier of classifiers) {
          if (classifier.includes('Development Status :: 7 - Inactive') || 
              classifier.includes('Development Status :: 6 - Mature')) {
            // These packages might be at higher risk for security issues
            if (dep.version !== dep.latestVersion && dep.isOutdated) {
              // If using an outdated version of a package marked as inactive or mature,
              // flag as potential vulnerability
              dep.vulnerabilities = [{
                severity: 'medium',
                description: `Using outdated version of possibly inactive package ${dep.name}`,
                affectedVersions: `<=${dep.version}`,
                fixedInVersion: dep.latestVersion
              }];
              dep.isVulnerable = true;
              break;
            }
          }
        }
      }
    } catch (jsonError) {
      log.warn(`Error parsing PyPI API output for ${dep.name}`, { error: jsonError });
    }
  } catch (error) {
    log.debug(`Error checking Python vulnerabilities for ${dep.name}`, { error });
  }
}

/**
 * Check for Maven vulnerabilities
 */
async function checkMavenVulnerabilities(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // This is a simplified approach - a complete solution would use tools like OWASP Dependency Check
    // Extract groupId and artifactId
    const [groupId, artifactId] = dep.name.split(':');
    
    if (!groupId || !artifactId) {
      return;
    }
    
    // Check for common vulnerabilities in well-known packages
    // This is just a demonstration - a real implementation would use a comprehensive database
    const knownVulnerablePackages: Record<string, Array<{
      artifactId: string;
      severity: 'low' | 'medium' | 'high' | 'critical';
      description: string;
      affected_versions: string;
      fixed_in_version?: string;
      cve_ids?: string[];
    }>> = {
      'org.apache.logging.log4j': [
        {
          artifactId: 'log4j-core',
          severity: 'critical',
          description: 'Remote Code Execution (RCE) vulnerability (Log4Shell)',
          affected_versions: '>=2.0.0,<=2.14.1',
          fixed_in_version: '2.15.0',
          cve_ids: ['CVE-2021-44228']
        }
      ],
      'org.springframework': [
        {
          artifactId: 'spring-core',
          severity: 'critical',
          description: 'Spring Framework RCE vulnerability (Spring4Shell)',
          affected_versions: '<=5.3.17,<=5.2.19',
          fixed_in_version: '5.3.18,5.2.20',
          cve_ids: ['CVE-2022-22965']
        }
      ]
    };
    
    if (knownVulnerablePackages[groupId]) {
      // Find matching artifactId
      const vulnForArtifact = knownVulnerablePackages[groupId].find(v => 
        v.artifactId === artifactId || artifactId.includes(v.artifactId)
      );
      
      if (vulnForArtifact && isVersionAffected(dep.version, vulnForArtifact.affected_versions)) {
        dep.vulnerabilities = [{
          severity: vulnForArtifact.severity,
          description: vulnForArtifact.description,
          affectedVersions: vulnForArtifact.affected_versions,
          fixedInVersion: vulnForArtifact.fixed_in_version,
          cveIds: vulnForArtifact.cve_ids
        }];
        dep.isVulnerable = true;
      }
    }
  } catch (error) {
    log.debug(`Error checking Maven vulnerabilities for ${dep.name}`, { error });
  }
}

/**
 * Check for Composer vulnerabilities
 */
async function checkComposerVulnerabilities(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // This is a simplified approach - a real implementation would use the Security Advisories API
    // or a more comprehensive database
    
    // Check for common vulnerabilities in well-known packages
    const knownVulnerablePackages: Record<string, Array<{
      severity: 'low' | 'medium' | 'high' | 'critical';
      description: string;
      affected_versions: string;
      fixed_in_version?: string;
      cve_ids?: string[];
    }>> = {
      'laravel/framework': [
        {
          severity: 'high',
          description: 'Remote code execution vulnerability in Laravel Framework',
          affected_versions: '<8.4.3',
          fixed_in_version: '8.4.3',
          cve_ids: ['CVE-2021-3129']
        }
      ],
      'symfony/symfony': [
        {
          severity: 'high',
          description: 'Symfony Security Component vulnerability',
          affected_versions: '>=4.4.0,<4.4.18',
          fixed_in_version: '4.4.18',
          cve_ids: ['CVE-2020-15094']
        }
      ]
    };
    
    if (knownVulnerablePackages[dep.name] && isVersionAffected(dep.version, knownVulnerablePackages[dep.name][0].affected_versions)) {
      dep.vulnerabilities = knownVulnerablePackages[dep.name].map(vuln => ({
        severity: vuln.severity,
        description: vuln.description,
        affectedVersions: vuln.affected_versions,
        fixedInVersion: vuln.fixed_in_version,
        cveIds: vuln.cve_ids
      }));
      dep.isVulnerable = true;
    }
  } catch (error) {
    log.debug(`Error checking Composer vulnerabilities for ${dep.name}`, { error });
  }
}

/**
 * Check for NuGet vulnerabilities
 */
async function checkNuGetVulnerabilities(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // This is a simplified approach - a real implementation would use the NuGet Security API
    // or a more comprehensive database
    
    // Check for common vulnerabilities in well-known packages
    const knownVulnerablePackages: Record<string, Array<{
      severity: 'low' | 'medium' | 'high' | 'critical';
      description: string;
      affected_versions: string;
      fixed_in_version?: string;
      cve_ids?: string[];
    }>> = {
      'Newtonsoft.Json': [
        {
          severity: 'medium',
          description: 'Denial of Service vulnerability in Newtonsoft.Json',
          affected_versions: '<12.0.3',
          fixed_in_version: '12.0.3',
          cve_ids: ['CVE-2020-10204']
        }
      ],
      'Microsoft.AspNetCore.SignalR': [
        {
          severity: 'high',
          description: 'Denial of Service vulnerability in SignalR',
          affected_versions: '<1.1.5',
          fixed_in_version: '1.1.5',
          cve_ids: ['CVE-2020-1597']
        }
      ]
    };
    
    if (knownVulnerablePackages[dep.name] && isVersionAffected(dep.version, knownVulnerablePackages[dep.name][0].affected_versions)) {
      dep.vulnerabilities = knownVulnerablePackages[dep.name].map(vuln => ({
        severity: vuln.severity,
        description: vuln.description,
        affectedVersions: vuln.affected_versions,
        fixedInVersion: vuln.fixed_in_version,
        cveIds: vuln.cve_ids
      }));
      dep.isVulnerable = true;
    }
  } catch (error) {
    log.debug(`Error checking NuGet vulnerabilities for ${dep.name}`, { error });
  }
}

/**
 * Check for Cargo vulnerabilities
 */
async function checkCargoVulnerabilities(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // This is a simplified approach - a real implementation would use the RustSec Advisory Database
    // or a more comprehensive database
    
    // Use the RustSec advisory database API if available
    const { stdout } = await execAsync(`curl -s https://rustsec.org/api/v1/advisories/crates/${dep.name}.json`);
    
    try {
      const advisories = JSON.parse(stdout);
      
      if (advisories && advisories.advisories && advisories.advisories.length > 0) {
        const vulns = [];
        
        for (const advisory of advisories.advisories) {
          if (isVersionAffected(dep.version, advisory.affected_versions)) {
            vulns.push({
              severity: mapRustSecSeverity(advisory.severity),
              description: advisory.title,
              affectedVersions: advisory.affected_versions,
              fixedInVersion: advisory.patched_versions?.[0],
              cveIds: advisory.aliases?.filter((a: string) => a.startsWith('CVE-')) || [],
              url: advisory.url
            });
          }
        }
        
        if (vulns.length > 0) {
          dep.vulnerabilities = vulns;
          dep.isVulnerable = true;
        }
      }
    } catch (jsonError) {
      log.warn(`Error parsing RustSec API output for ${dep.name}`, { error: jsonError });
    }
  } catch (error) {
    log.debug(`Error checking Cargo vulnerabilities for ${dep.name}`, { error });
  }
}

/**
 * Map RustSec severity to standard severity
 */
function mapRustSecSeverity(severity: string): 'low' | 'medium' | 'high' | 'critical' {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
    case 'moderate':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return 'medium';
  }
}

/**
 * Check dependency license
 */
async function checkDependencyLicense(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Get the license information based on package manager
    await getLicenseInfo(dep, config);
    
    if (!dep.license) {
      // If license information could not be determined, flag as a license issue
      dep.isLicenseIssue = true;
      dep.licenseIssue = {
        license: 'unknown',
        reason: 'No license information found for this dependency.'
      };
      return;
    }
    
    // Check against allowlist/blocklist if configured
    if (config.licenses) {
      // Check if the license is in the blocklist
      if (config.licenses.blocklist && config.licenses.blocklist.length > 0) {
        for (const blockedLicense of config.licenses.blocklist) {
          if (licenseMatches(dep.license, blockedLicense)) {
            dep.isLicenseIssue = true;
            dep.licenseIssue = {
              license: dep.license,
              reason: `License '${dep.license}' is in the blocked licenses list.`
            };
            return;
          }
        }
      }
      
      // Check if allowlist is configured and license is not in it
      if (config.licenses.allowlist && config.licenses.allowlist.length > 0) {
        let inAllowlist = false;
        
        for (const allowedLicense of config.licenses.allowlist) {
          if (licenseMatches(dep.license, allowedLicense)) {
            inAllowlist = true;
            break;
          }
        }
        
        if (!inAllowlist) {
          dep.isLicenseIssue = true;
          dep.licenseIssue = {
            license: dep.license,
            reason: `License '${dep.license}' is not in the allowed licenses list.`
          };
        }
      }
    }
  } catch (error) {
    log.warn(`Error checking license for dependency ${dep.name}`, { error });
  }
}

/**
 * Get license information for a dependency
 */
async function getLicenseInfo(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use different approaches based on package manager
    switch (dep.packageManager) {
      case 'npm':
      case 'yarn':
      case 'pnpm':
        await getNpmLicense(dep, config);
        break;
      case 'pip':
      case 'pipenv':
      case 'poetry':
        await getPythonLicense(dep, config);
        break;
      case 'maven':
      case 'gradle':
        await getMavenLicense(dep, config);
        break;
      case 'composer':
        await getComposerLicense(dep, config);
        break;
      case 'nuget':
        await getNuGetLicense(dep, config);
        break;
      case 'cargo':
        await getCargoLicense(dep, config);
        break;
      case 'go':
        await getGoLicense(dep, config);
        break;
      case 'gem':
        await getRubyGemsLicense(dep, config);
        break;
      case 'cocoapods':
        await getCocoaPodsLicense(dep, config);
        break;
      case 'swift':
        await getSwiftLicense(dep, config);
        break;
    }
  } catch (error) {
    log.warn(`Error getting license info for ${dep.name}`, { error });
  }
}

/**
 * Get license for NPM package
 */
async function getNpmLicense(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use npm view to get license information
    const { stdout } = await execAsync(`npm view ${dep.name}@${dep.version} license --json`);
    
    try {
      const licenseInfo = JSON.parse(stdout.trim());
      
      if (typeof licenseInfo === 'string') {
        dep.license = licenseInfo;
      } else if (licenseInfo && licenseInfo.type) {
        dep.license = licenseInfo.type;
      }
    } catch (jsonError) {
      // Handle non-JSON output (sometimes npm returns plain text)
      if (stdout.trim() && stdout.trim() !== 'undefined') {
        dep.license = stdout.trim();
      }
    }
  } catch (error) {
    log.debug(`Error getting NPM license for ${dep.name}`, { error });
  }
}

/**
 * Get license for Python package
 */
async function getPythonLicense(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use PyPI API to get license information
    const { stdout } = await execAsync(`curl -s https://pypi.org/pypi/${dep.name}/json`);
    
    try {
      const packageInfo = JSON.parse(stdout);
      
      if (packageInfo.info) {
        // PyPI stores license information in different fields
        dep.license = packageInfo.info.license || packageInfo.info.classifiers.find((c: string) => c.startsWith('License ::'))?.replace('License :: ', '') || 'unknown';
      }
    } catch (jsonError) {
      log.warn(`Error parsing PyPI API output for ${dep.name}`, { error: jsonError });
    }
  } catch (error) {
    log.debug(`Error getting Python license for ${dep.name}`, { error });
  }
}

/**
 * Get license for Maven package
 */
async function getMavenLicense(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Extract groupId and artifactId
    const [groupId, artifactId] = dep.name.split(':');
    
    if (!groupId || !artifactId) {
      return;
    }
    
    // Use Maven Central API to get license information
    const { stdout } = await execAsync(`curl -s "https://search.maven.org/solrsearch/select?q=g:%22${groupId}%22+AND+a:%22${artifactId}%22&rows=1&wt=json"`);
    
    try {
      const searchResult = JSON.parse(stdout);
      
      if (searchResult.response && searchResult.response.docs && searchResult.response.docs.length > 0) {
        // Maven Central stores license information in the license field
        const doc = searchResult.response.docs[0];
        
        if (doc.licenseUrl && doc.licenseUrl.length > 0) {
          // Try to determine license from URL
          const licenseUrl = doc.licenseUrl[0];
          
          if (licenseUrl.includes('apache.org/licenses')) {
            dep.license = 'Apache-2.0';
          } else if (licenseUrl.includes('opensource.org/licenses/MIT')) {
            dep.license = 'MIT';
          } else if (licenseUrl.includes('gnu.org/licenses/gpl')) {
            dep.license = 'GPL';
          } else if (licenseUrl.includes('gnu.org/licenses/lgpl')) {
            dep.license = 'LGPL';
          } else if (licenseUrl.includes('opensource.org/licenses/BSD')) {
            dep.license = 'BSD';
          } else if (licenseUrl.includes('mozilla.org/MPL')) {
            dep.license = 'MPL';
          } else {
            dep.license = licenseUrl; // Use URL as fallback
          }
        } else if (doc.license && doc.license.length > 0) {
          dep.license = doc.license[0];
        } else {
          dep.license = 'unknown';
        }
      }
    } catch (jsonError) {
      log.warn(`Error parsing Maven Central API output for ${dep.name}`, { error: jsonError });
    }
  } catch (error) {
    log.debug(`Error getting Maven license for ${dep.name}`, { error });
  }
}

/**
 * Get license for Composer package
 */
async function getComposerLicense(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use Packagist API to get license information
    const { stdout } = await execAsync(`curl -s https://repo.packagist.org/p2/${dep.name}.json`);
    
    try {
      const packageInfo = JSON.parse(stdout);
      
      if (packageInfo.packages && packageInfo.packages[dep.name]) {
        // Find the specific version if available
        const versions = packageInfo.packages[dep.name];
        
        if (versions[dep.version]) {
          dep.license = versions[dep.version].license?.[0] || 'unknown';
        } else {
          // Use the latest version's license as fallback
          const latestVersion = Object.keys(versions).sort().pop();
          if (latestVersion) {
            dep.license = versions[latestVersion].license?.[0] || 'unknown';
          }
        }
      }
    } catch (jsonError) {
      log.warn(`Error parsing Packagist API output for ${dep.name}`, { error: jsonError });
    }
  } catch (error) {
    log.debug(`Error getting Composer license for ${dep.name}`, { error });
  }
}

/**
 * Get license for NuGet package
 */
async function getNuGetLicense(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use NuGet API to get license information
    const { stdout } = await execAsync(`curl -s "https://api-v2v3search-0.nuget.org/query?q=PackageId:${dep.name}&prerelease=false"`);
    
    try {
      const searchResult = JSON.parse(stdout);
      
      if (searchResult.data && searchResult.data.length > 0) {
        // Find exact match for the package
        const pkg = searchResult.data.find((p: any) => p.id.toLowerCase() === dep.name.toLowerCase());
        
        if (pkg) {
          // NuGet stores license information in licenseUrl or license
          if (pkg.license) {
            dep.license = pkg.license;
          } else if (pkg.licenseUrl) {
            // Try to determine license from URL
            if (pkg.licenseUrl.includes('apache.org/licenses')) {
              dep.license = 'Apache-2.0';
            } else if (pkg.licenseUrl.includes('opensource.org/licenses/MIT')) {
              dep.license = 'MIT';
            } else if (pkg.licenseUrl.includes('gnu.org/licenses/gpl')) {
              dep.license = 'GPL';
            } else if (pkg.licenseUrl.includes('gnu.org/licenses/lgpl')) {
              dep.license = 'LGPL';
            } else if (pkg.licenseUrl.includes('opensource.org/licenses/BSD')) {
              dep.license = 'BSD';
            } else if (pkg.licenseUrl.includes('mozilla.org/MPL')) {
              dep.license = 'MPL';
            } else {
              dep.license = pkg.licenseUrl; // Use URL as fallback
            }
          } else if (pkg.licenseExpression) {
            dep.license = pkg.licenseExpression;
          } else {
            dep.license = 'unknown';
          }
        }
      }
    } catch (jsonError) {
      log.warn(`Error parsing NuGet API output for ${dep.name}`, { error: jsonError });
    }
  } catch (error) {
    log.debug(`Error getting NuGet license for ${dep.name}`, { error });
  }
}

/**
 * Get license for Cargo package
 */
async function getCargoLicense(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use crates.io API to get license information
    const { stdout } = await execAsync(`curl -s https://crates.io/api/v1/crates/${dep.name}`);
    
    try {
      const crateInfo = JSON.parse(stdout);
      
      if (crateInfo.crate) {
        // Cargo stores license information in the license field
        dep.license = crateInfo.crate.license || 'unknown';
      }
    } catch (jsonError) {
      log.warn(`Error parsing crates.io API output for ${dep.name}`, { error: jsonError });
    }
  } catch (error) {
    log.debug(`Error getting Cargo license for ${dep.name}`, { error });
  }
}

/**
 * Get license for Go module
 */
async function getGoLicense(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // This is a simplified approach - a real implementation would need to
    // fetch the module source and look for LICENSE files
    
    // Try to determine license from GitHub
    if (dep.name.includes('github.com/')) {
      try {
        const repoPath = dep.name.replace('github.com/', '');
        const { stdout } = await execAsync(`curl -s https://api.github.com/repos/${repoPath}/license`);
        
        try {
          const licenseInfo = JSON.parse(stdout);
          
          if (licenseInfo.license && licenseInfo.license.spdx_id) {
            dep.license = licenseInfo.license.spdx_id;
          } else if (licenseInfo.license && licenseInfo.license.key) {
            dep.license = licenseInfo.license.key.toUpperCase();
          }
        } catch (jsonError) {
          log.debug(`Error parsing GitHub API output for ${dep.name}`, { error: jsonError });
        }
      } catch (githubError) {
        log.debug(`Error getting GitHub license for ${dep.name}`, { error: githubError });
      }
    }
    
    // Set to unknown if not determined
    if (!dep.license) {
      dep.license = 'unknown';
    }
  } catch (error) {
    log.debug(`Error getting Go license for ${dep.name}`, { error });
  }
}

/**
 * Get license for RubyGems package
 */
async function getRubyGemsLicense(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use RubyGems API to get license information
    const { stdout } = await execAsync(`curl -s https://rubygems.org/api/v1/gems/${dep.name}.json`);
    
    try {
      const gemInfo = JSON.parse(stdout);
      
      // RubyGems stores license information in the licenses array or license field
      if (gemInfo.licenses && gemInfo.licenses.length > 0) {
        dep.license = gemInfo.licenses.join(', ');
      } else {
        dep.license = gemInfo.license || 'unknown';
      }
    } catch (jsonError) {
      log.warn(`Error parsing RubyGems API output for ${dep.name}`, { error: jsonError });
    }
  } catch (error) {
    log.debug(`Error getting RubyGems license for ${dep.name}`, { error });
  }
}

/**
 * Get license for CocoaPods package
 */
async function getCocoaPodsLicense(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Use CocoaPods API to get license information
    const { stdout } = await execAsync(`curl -s https://trunk.cocoapods.org/api/v1/pods/${dep.name}`);
    
    try {
      const podInfo = JSON.parse(stdout);
      
      if (podInfo.pod && podInfo.pod.license) {
        // CocoaPods stores license information in the license field
        // which can be a string or an object
        if (typeof podInfo.pod.license === 'string') {
          dep.license = podInfo.pod.license;
        } else if (podInfo.pod.license.type) {
          dep.license = podInfo.pod.license.type;
        }
      }
    } catch (jsonError) {
      log.warn(`Error parsing CocoaPods API output for ${dep.name}`, { error: jsonError });
    }
  } catch (error) {
    log.debug(`Error getting CocoaPods license for ${dep.name}`, { error });
  }
}

/**
 * Get license for Swift package
 */
async function getSwiftLicense(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // For Swift packages, we have less standardized means to check
    // For GitHub repositories, we can use the GitHub API
    if (dep.name.includes('/') && !dep.name.startsWith('http')) {
      // Extract owner and repo
      const parts = dep.name.split('/');
      if (parts.length >= 2) {
        const owner = parts[parts.length - 2];
        const repo = parts[parts.length - 1];
        
        try {
          const { stdout } = await execAsync(`curl -s https://api.github.com/repos/${owner}/${repo}/license`);
          
          try {
            const licenseInfo = JSON.parse(stdout);
            
            if (licenseInfo.license && licenseInfo.license.spdx_id) {
              dep.license = licenseInfo.license.spdx_id;
            } else if (licenseInfo.license && licenseInfo.license.key) {
              dep.license = licenseInfo.license.key.toUpperCase();
            }
          } catch (jsonError) {
            log.debug(`Error parsing GitHub API output for ${dep.name}`, { error: jsonError });
          }
        } catch (githubError) {
          log.debug(`Error getting GitHub license for ${dep.name}`, { error: githubError });
        }
      }
    }
    
    // Set to unknown if not determined
    if (!dep.license) {
      dep.license = 'unknown';
    }
  } catch (error) {
    log.debug(`Error getting Swift license for ${dep.name}`, { error });
  }
}

/**
 * Check if license matches a pattern
 */
function licenseMatches(license: string, pattern: string): boolean {
  // Normalize licenses for comparison
  const normalizedLicense = license.toLowerCase().trim();
  const normalizedPattern = pattern.toLowerCase().trim();
  
  // Exact match
  if (normalizedLicense === normalizedPattern) {
    return true;
  }
  
  // Wildcard match
  if (normalizedPattern.includes('*')) {
    const regexPattern = normalizedPattern.replace(/\*/g, '.*');
    return new RegExp(`^${regexPattern}$`).test(normalizedLicense);
  }
  
  // License family match (e.g., 'MIT' should match 'MIT License')
  if (normalizedLicense.includes(normalizedPattern)) {
    return true;
  }
  
  // SPDX license expressions
  // For AND and OR expressions, this is a simplified approach
  // A complete solution would use a proper SPDX expression parser
  if (normalizedLicense.includes(' AND ') || normalizedLicense.includes(' OR ')) {
    const parts = normalizedLicense
      .replace(' AND ', ' ')
      .replace(' OR ', ' ')
      .split(' ');
    
    for (const part of parts) {
      if (licenseMatches(part, pattern)) {
        return true;
      }
    }
  }
  
  return false;
}

/**
 * Check if dependency is maintained
 */
async function checkIfDependencyMaintained(
  dep: DependencyInfo,
  config: DependencyScannerConfig
): Promise<void> {
  try {
    // Consider a dependency not maintained if it hasn't been updated in a long time
    if (dep.lastPublishDate) {
      const now = new Date();
      const ageInDays = (now.getTime() - dep.lastPublishDate.getTime()) / (1000 * 60 * 60 * 24);
      
      const maxAge = config.maxUpdateAge || 365; // Default to 1 year
      
      if (ageInDays > maxAge) {
        dep.isNotMaintained = true;
      }
    }
    
    // If no publish date information is available, check for other signs of lack of maintenance
    if (!dep.lastPublishDate && dep.isOutdated && dep.latestVersion) {
      // If the package is significantly behind the latest version, it might not be maintained
      try {
        const currentParts = dep.version.split('.');
        const latestParts = dep.latestVersion.split('.');
        
        if (currentParts.length > 0 && latestParts.length > 0) {
          const currentMajor = parseInt(currentParts[0], 10);
          const latestMajor = parseInt(latestParts[0], 10);
          
          // If multiple major versions behind, flag as potentially not maintained
          if (latestMajor - currentMajor >= 2) {
            dep.isNotMaintained = true;
          }
        }
      } catch (parseError) {
        // Ignore version parsing errors
      }
    }
  } catch (error) {
    log.warn(`Error checking if dependency ${dep.name} is maintained`, { error });
  }
}

/**
 * Check if a version is affected by a specified range
 */
function isVersionAffected(version: string, affectedVersions: string): boolean {
  if (version === 'unknown' || version === 'local') {
    return true; // Assume unknown or local versions are affected
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
    const ranges = affectedVersions.split(',');
    return ranges.some(range => isVersionAffected(version, range.trim()));
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
  
  // Then consider license issues
  if (dep.isLicenseIssue) {
    // License issues are at least medium risk
    if (riskLevel === 'low') riskLevel = 'medium';
    
    // If license issue is combined with vulnerabilities, raise to high
    if (dep.vulnerabilities && dep.vulnerabilities.length > 0 && riskLevel === 'medium') {
      riskLevel = 'high';
    }
  }
  
  // Then consider maintenance status
  if (dep.isNotMaintained) {
    // Unmaintained packages are at least medium risk
    if (riskLevel === 'low') riskLevel = 'medium';
    
    // If unmaintained package has vulnerabilities, raise to high
    if (dep.vulnerabilities && dep.vulnerabilities.length > 0 && riskLevel === 'medium') {
      riskLevel = 'high';
    }
    
    // If unmaintained package has license issues, raise to high
    if (dep.isLicenseIssue && riskLevel === 'medium') {
      riskLevel = 'high';
    }
  }
  
  // Consider how outdated the dependency is
  if (dep.isOutdated && dep.version && dep.latestVersion) {
    try {
      // Check if it's a major version behind
      if (dep.upgradeBreaking) {
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
      // If can't parse, default to medium for outdated dependencies
      if (riskLevel === 'low') riskLevel = 'medium';
    }
  }
  
  // Consider whether the dependency is unused
  if (dep.isUnused) {
    // Unused dependencies are at least medium risk because they add unnecessary bloat and attack surface
    if (riskLevel === 'low') riskLevel = 'medium';
    
    // If unused dependency has vulnerabilities, maintain vulnerability severity
    // If unused dependency has license issues, raise to high
    if (dep.isLicenseIssue && riskLevel === 'medium') {
      riskLevel = 'high';
    }
  }
  
  return riskLevel;
}

/**
 * Generate tags for a dependency issue
 */
function generateTags(dep: DependencyInfo): string[] {
  const tags: string[] = [dep.packageManager];
  
  // Add tag for dependency type
  tags.push(`type:${dep.type}`);
  
  // Add tags based on issue type
  if (dep.isOutdated) {
    tags.push('outdated');
    
    if (dep.upgradeBreaking) {
      tags.push('breaking-update');
    } else {
      tags.push('non-breaking-update');
    }
  }
  
  if (dep.isVulnerable) {
    tags.push('vulnerable');
    
    // Add highest severity level
    if (dep.vulnerabilities && dep.vulnerabilities.length > 0) {
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
  }
  
  if (dep.isLicenseIssue) {
    tags.push('license-issue');
    
    if (dep.license) {
      tags.push(`license:${dep.license.toLowerCase().replace(/\s/g, '-')}`);
    } else {
      tags.push('license:unknown');
    }
  }
  
  if (dep.isNotMaintained) {
    tags.push('not-maintained');
  }
  
  if (dep.isUnused) {
    tags.push('unused');
  }
  
  if (dep.isDeprecated) {
    tags.push('deprecated');
  }
  
  if (dep.duplicates) {
    tags.push('duplicate');
  }
  
  return tags;
}

/**
 * Generate a recommendation for a dependency issue
 */
function generateRecommendation(dep: DependencyInfo): string {
  const recommendations: string[] = [];
  
  // Handle vulnerable dependencies with highest priority
  if (dep.isVulnerable && dep.vulnerabilities && dep.vulnerabilities.length > 0) {
    recommendations.push(
      `Found ${dep.vulnerabilities.length} ${dep.vulnerabilities.length === 1 ? 'vulnerability' : 'vulnerabilities'} in ${dep.name}@${dep.version}.`
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
  
  // Handle license issues
  if (dep.isLicenseIssue && dep.licenseIssue) {
    // Only add this header if not already covered by vulnerabilities
    if (recommendations.length === 0) {
      recommendations.push(
        `Found license issue with ${dep.name}@${dep.version}: ${dep.licenseIssue.reason}`
      );
    } else {
      recommendations.push(
        `Additionally, there is a license issue: ${dep.licenseIssue.reason}`
      );
    }
    
    recommendations.push(
      `Review the license compliance requirements for this dependency.`
    );
  }
  
  // Handle unmaintained dependencies
  if (dep.isNotMaintained) {
    // Only add this header if not already covered by other issues
    if (recommendations.length === 0) {
      recommendations.push(
        `${dep.name}@${dep.version} appears to be unmaintained or abandoned.`
      );
    } else {
      recommendations.push(
        `Additionally, this dependency appears to be unmaintained or abandoned.`
      );
    }
    
    if (dep.lastPublishDate) {
      recommendations.push(
        `Last update was on ${dep.lastPublishDate.toISOString().split('T')[0]}, which is more than ${config.maxUpdateAge || 365} days ago.`
      );
    }
    
    recommendations.push(
      `Consider finding an alternative, actively maintained package.`
    );
  }
  
  // Handle unused dependencies
  if (dep.isUnused) {
    // Only add this if not already covered by other issues
    if (recommendations.length === 0) {
      recommendations.push(
        `${dep.name}@${dep.version} appears to be unused in the codebase.`
      );
    } else {
      recommendations.push(
        `Additionally, this dependency appears to be unused in the codebase.`
      );
    }
    
    recommendations.push(
      `Remove this dependency to reduce package size and potential security issues.`
    );
  }
  
  // Handle outdated dependencies
  if (dep.isOutdated && dep.latestVersion) {
    // Only add this if not already covered by vulnerabilities, license issues, or maintenance issues
    if (recommendations.length === 0) {
      recommendations.push(
        `${dep.name}@${dep.version} is outdated. Latest version is ${dep.latestVersion}.`
      );
      
      // Check if it's a breaking update
      if (dep.upgradeBreaking) {
        recommendations.push(
          `This is a major version update which may include breaking changes. Review the changelog before updating.`
        );
      } else {
        recommendations.push(
          `Update to the latest version to receive bug fixes, performance improvements, and new features.`
        );
      }
    } else if (!recommendations.some(r => r.includes('Update to the latest version'))) {
      // Add update recommendation if not already present
      recommendations.push(
        `Update to ${dep.latestVersion} to receive the latest improvements and fixes.`
      );
    }
  }
  
  // Add additional information if available
  if (recommendations.length > 0 && (dep.homepageUrl || dep.repositoryUrl)) {
    recommendations.push('');
    recommendations.push('Additional information:');
    
    if (dep.homepageUrl) {
      recommendations.push(`- Homepage: ${dep.homepageUrl}`);
    }
    
    if (dep.repositoryUrl) {
      recommendations.push(`- Repository: ${dep.repositoryUrl}`);
    }
  }
  
  // If no specific recommendations were made, add generic advice
  if (recommendations.length === 0) {
    recommendations.push(
      `Review ${dep.name}@${dep.version} for potential updates or replacements as part of regular dependency maintenance.`
    );
  }
  
  return recommendations.join('\n');
}
