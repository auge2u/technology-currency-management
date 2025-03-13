import * as fs from 'fs';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import axios from 'axios';
import { OutdatedDependency } from '../types/scanning';
import { log } from '../utils/logging';

const execAsync = promisify(exec);

/**
 * Scanner to detect outdated dependencies across the tech stack
 */
export async function scanDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  try {
    log.info('Starting dependency scanning');
    
    const results: OutdatedDependency[] = [];
    
    // Scan for different types of dependencies based on package managers
    const npmResults = await scanNpmDependencies(rootDir);
    const pythonResults = await scanPythonDependencies(rootDir);
    const mavenResults = await scanMavenDependencies(rootDir);
    const gradleResults = await scanGradleDependencies(rootDir);
    const composerResults = await scanPhpComposerDependencies(rootDir);
    const dotnetResults = await scanDotnetDependencies(rootDir);
    const rubyResults = await scanRubyDependencies(rootDir);
    const goResults = await scanGoDependencies(rootDir);
    const rustResults = await scanRustDependencies(rootDir);
    
    results.push(
      ...npmResults,
      ...pythonResults,
      ...mavenResults,
      ...gradleResults,
      ...composerResults,
      ...dotnetResults,
      ...rubyResults,
      ...goResults,
      ...rustResults
    );
    
    log.info(`Dependency scanning completed. Found ${results.length} outdated dependencies`);
    
    return results;
  } catch (error) {
    log.error('Error during dependency scanning', { error });
    return [];
  }
}

/**
 * Scan for outdated npm dependencies (JavaScript/TypeScript)
 */
async function scanNpmDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  try {
    log.info('Scanning for NPM dependencies');
    
    // Find all package.json files (excluding node_modules)
    const { stdout } = await execAsync(`find ${rootDir} -name "package.json" -not -path "*/node_modules/*" -not -path "*/dist/*" -not -path "*/build/*"`);
    const packageJsonFiles = stdout.trim().split('\n').filter(Boolean);
    
    if (packageJsonFiles.length === 0) {
      log.info('No NPM projects found');
      return [];
    }
    
    log.info(`Found ${packageJsonFiles.length} NPM projects`);
    
    const results: OutdatedDependency[] = [];
    
    for (const filePath of packageJsonFiles) {
      try {
        log.debug(`Processing package.json at ${filePath}`);
        const content = fs.readFileSync(filePath, 'utf8');
        const packageJson = JSON.parse(content);
        const projectDir = path.dirname(filePath);
        
        // Process regular dependencies
        if (packageJson.dependencies) {
          await processNpmDependencies(packageJson.dependencies, 'production', projectDir, filePath, results);
        }
        
        // Process dev dependencies
        if (packageJson.devDependencies) {
          await processNpmDependencies(packageJson.devDependencies, 'development', projectDir, filePath, results);
        }
      } catch (fileError) {
        log.warn(`Error processing package.json at ${filePath}`, { error: fileError });
      }
    }
    
    return results;
  } catch (error) {
    log.error('Error scanning NPM dependencies', { error });
    return [];
  }
}

/**
 * Process npm dependencies and check for outdated versions
 */
async function processNpmDependencies(
  dependencies: Record<string, string>,
  type: 'production' | 'development',
  projectDir: string,
  filePath: string,
  results: OutdatedDependency[]
): Promise<void> {
  for (const [name, version] of Object.entries(dependencies)) {
    try {
      // Skip package references that are not version strings (e.g., git URLs, file:, link:)
      if (!version.match(/^[\^~><=]?\d/) && !version.match(/^\*$/)) {
        continue;
      }
      
      // Clean up version string (remove ^, ~, etc.)
      const currentVersion = version.replace(/^[\^~><=]/, '');
      
      // Check latest version from npm registry
      const latestVersion = await getLatestNpmVersion(name);
      
      if (latestVersion && compareVersions(currentVersion, latestVersion) < 0) {
        // Determine severity based on version difference
        const severity = determineDependencySeverity(currentVersion, latestVersion);
        
        // Add to results
        results.push({
          id: `npm-${name}-${filePath}`,
          name,
          currentVersion,
          latestVersion,
          packageManager: 'npm',
          dependencyType: type,
          path: filePath,
          severity,
          remediationSteps: `Update the version in package.json to "${name}": "^${latestVersion}" and run npm install`,
          detectedAt: new Date()
        });
      }
    } catch (depError) {
      log.warn(`Error checking NPM package ${name}`, { error: depError });
    }
  }
}

/**
 * Get the latest version of an npm package
 */
async function getLatestNpmVersion(packageName: string): Promise<string | null> {
  try {
    const response = await axios.get(`https://registry.npmjs.org/${packageName}`);
    return response.data['dist-tags']?.latest || null;
  } catch (error) {
    log.warn(`Error fetching NPM package info for ${packageName}`, { error });
    return null;
  }
}

/**
 * Scan for outdated Python dependencies
 */
async function scanPythonDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  try {
    log.info('Scanning for Python dependencies');
    
    // Find all requirements.txt, setup.py, and Pipfile files
    const { stdout } = await execAsync(
      `find ${rootDir} -name "requirements.txt" -o -name "setup.py" -o -name "Pipfile" -not -path "*/venv/*" -not -path "*/.env/*"`
    );
    const pythonFiles = stdout.trim().split('\n').filter(Boolean);
    
    if (pythonFiles.length === 0) {
      log.info('No Python projects found');
      return [];
    }
    
    log.info(`Found ${pythonFiles.length} Python dependency files`);
    
    const results: OutdatedDependency[] = [];
    
    for (const filePath of pythonFiles) {
      try {
        log.debug(`Processing Python dependency file at ${filePath}`);
        const content = fs.readFileSync(filePath, 'utf8');
        const filename = path.basename(filePath);
        
        if (filename === 'requirements.txt') {
          await processPythonRequirements(content, filePath, results);
        } else if (filename === 'setup.py') {
          await processPythonSetupPy(content, filePath, results);
        } else if (filename === 'Pipfile') {
          await processPythonPipfile(content, filePath, results);
        }
      } catch (fileError) {
        log.warn(`Error processing Python dependency file at ${filePath}`, { error: fileError });
      }
    }
    
    return results;
  } catch (error) {
    log.error('Error scanning Python dependencies', { error });
    return [];
  }
}

/**
 * Process Python requirements.txt file
 */
async function processPythonRequirements(
  content: string,
  filePath: string,
  results: OutdatedDependency[]
): Promise<void> {
  // Parse requirements.txt line by line
  const lines = content.split('\n');
  
  for (const line of lines) {
    // Skip comments and empty lines
    if (line.trim().startsWith('#') || !line.trim()) {
      continue;
    }
    
    try {
      // Basic parsing - this would need to be more sophisticated in a real-world implementation
      const match = line.match(/^([\w-\.]+)(?:[=<>~!]=|@|\s)([\w\.]+)/);
      
      if (match) {
        const [, name, version] = match;
        
        // Check latest version from PyPI
        const latestVersion = await getLatestPythonVersion(name);
        
        if (latestVersion && compareVersions(version, latestVersion) < 0) {
          // Determine severity based on version difference
          const severity = determineDependencySeverity(version, latestVersion);
          
          // Add to results
          results.push({
            id: `python-${name}-${filePath}`,
            name,
            currentVersion: version,
            latestVersion,
            packageManager: 'pip',
            dependencyType: 'production',
            path: filePath,
            severity,
            remediationSteps: `Update the version in requirements.txt to ${name}==${latestVersion} and run pip install -r requirements.txt`,
            detectedAt: new Date()
          });
        }
      }
    } catch (lineError) {
      log.warn(`Error processing Python requirement: ${line}`, { error: lineError });
    }
  }
}

/**
 * Process Python setup.py file
 */
async function processPythonSetupPy(
  content: string,
  filePath: string,
  results: OutdatedDependency[]
): Promise<void> {
  // This would require more sophisticated parsing in a real implementation
  // For now, we'll use a simple regex approach to extract install_requires
  
  const installRequiresMatch = content.match(/install_requires\s*=\s*\[([^\]]+)\]/);
  
  if (installRequiresMatch) {
    const requiresContent = installRequiresMatch[1];
    
    // Extract package names and versions using regex - this is simplified
    const packageMatches = requiresContent.match(/['"]([\w-\.]+)(?:[=<>~!]=|>=|<=)([\w\.]+)['"](?:,|\s)/g);
    
    if (packageMatches) {
      for (const packageMatch of packageMatches) {
        const detailedMatch = packageMatch.match(/['"]([\w-\.]+)(?:[=<>~!]=|>=|<=)([\w\.]+)/);
        
        if (detailedMatch) {
          const [, name, version] = detailedMatch;
          
          // Check latest version from PyPI
          const latestVersion = await getLatestPythonVersion(name);
          
          if (latestVersion && compareVersions(version, latestVersion) < 0) {
            // Determine severity based on version difference
            const severity = determineDependencySeverity(version, latestVersion);
            
            // Add to results
            results.push({
              id: `python-${name}-${filePath}`,
              name,
              currentVersion: version,
              latestVersion,
              packageManager: 'pip',
              dependencyType: 'production',
              path: filePath,
              severity,
              remediationSteps: `Update the version in setup.py to ${name}>=${latestVersion} and reinstall the package`,
              detectedAt: new Date()
            });
          }
        }
      }
    }
  }
}

/**
 * Process Python Pipfile
 */
async function processPythonPipfile(
  content: string,
  filePath: string,
  results: OutdatedDependency[]
): Promise<void> {
  // Simple Pipfile parsing - would need more robust implementation in reality
  const packages = content.match(/\[packages\](\r|\n)[^\[]*/);
  const devPackages = content.match(/\[dev-packages\](\r|\n)[^\[]*/);
  
  if (packages) {
    await processPipfileSection(packages[0], 'production', filePath, results);
  }
  
  if (devPackages) {
    await processPipfileSection(devPackages[0], 'development', filePath, results);
  }
}

/**
 * Process a section of a Pipfile
 */
async function processPipfileSection(
  section: string,
  type: 'production' | 'development',
  filePath: string,
  results: OutdatedDependency[]
): Promise<void> {
  // Extract package definitions using regex
  const packageMatches = section.match(/([\w-\.]+)\s*=\s*"([^"]*)"(\r|\n)/g);
  
  if (packageMatches) {
    for (const packageMatch of packageMatches) {
      const detailedMatch = packageMatch.match(/([\w-\.]+)\s*=\s*"([^"]*)"/); 
      
      if (detailedMatch) {
        const [, name, versionSpec] = detailedMatch;
        
        // Parse version from spec (e.g., "==1.0.0", ">=1.0.0,<2.0.0")
        const versionMatch = versionSpec.match(/[=<>~!]=([\w\.]+)/);
        
        if (versionMatch) {
          const version = versionMatch[1];
          
          // Check latest version from PyPI
          const latestVersion = await getLatestPythonVersion(name);
          
          if (latestVersion && compareVersions(version, latestVersion) < 0) {
            // Determine severity based on version difference
            const severity = determineDependencySeverity(version, latestVersion);
            
            // Add to results
            results.push({
              id: `python-${name}-${filePath}`,
              name,
              currentVersion: version,
              latestVersion,
              packageManager: 'pipenv',
              dependencyType: type,
              path: filePath,
              severity,
              remediationSteps: `Update the version in Pipfile to ${name} = "==${latestVersion}" and run pipenv update ${name}`,
              detectedAt: new Date()
            });
          }
        }
      }
    }
  }
}

/**
 * Get the latest version of a Python package from PyPI
 */
async function getLatestPythonVersion(packageName: string): Promise<string | null> {
  try {
    const response = await axios.get(`https://pypi.org/pypi/${packageName}/json`);
    return response.data.info.version || null;
  } catch (error) {
    log.warn(`Error fetching PyPI package info for ${packageName}`, { error });
    return null;
  }
}

/**
 * Scan for outdated Maven dependencies (Java)
 */
async function scanMavenDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  // Implementation would scan pom.xml files
  return [];
}

/**
 * Scan for outdated Gradle dependencies (Java)
 */
async function scanGradleDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  // Implementation would scan build.gradle or build.gradle.kts files
  return [];
}

/**
 * Scan for outdated PHP Composer dependencies
 */
async function scanPhpComposerDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  // Implementation would scan composer.json files
  return [];
}

/**
 * Scan for outdated .NET dependencies
 */
async function scanDotnetDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  // Implementation would scan .csproj, .fsproj, .vbproj files
  return [];
}

/**
 * Scan for outdated Ruby dependencies
 */
async function scanRubyDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  // Implementation would scan Gemfile files
  return [];
}

/**
 * Scan for outdated Go dependencies
 */
async function scanGoDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  // Implementation would scan go.mod files
  return [];
}

/**
 * Scan for outdated Rust dependencies
 */
async function scanRustDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  // Implementation would scan Cargo.toml files
  return [];
}

/**
 * Compare two version strings
 * Returns:
 * - Negative if version1 is older than version2
 * - 0 if versions are equal
 * - Positive if version1 is newer than version2
 */
function compareVersions(version1: string, version2: string): number {
  const parts1 = version1.split('.').map(part => {
    const num = parseInt(part.replace(/[^0-9]+/g, ''), 10);
    return isNaN(num) ? 0 : num;
  });
  
  const parts2 = version2.split('.').map(part => {
    const num = parseInt(part.replace(/[^0-9]+/g, ''), 10);
    return isNaN(num) ? 0 : num;
  });
  
  const maxLength = Math.max(parts1.length, parts2.length);
  
  for (let i = 0; i < maxLength; i++) {
    const part1 = i < parts1.length ? parts1[i] : 0;
    const part2 = i < parts2.length ? parts2[i] : 0;
    
    if (part1 !== part2) {
      return part1 - part2;
    }
  }
  
  return 0;
}

/**
 * Determine dependency severity based on version difference
 */
function determineDependencySeverity(
  currentVersion: string,
  latestVersion: string
): 'low' | 'medium' | 'high' | 'critical' {
  // Parse versions to get major.minor.patch parts
  const current = currentVersion.split('.').map(Number);
  const latest = latestVersion.split('.').map(Number);
  
  // Calculate major version difference
  const majorDiff = (latest[0] || 0) - (current[0] || 0);
  
  if (majorDiff >= 2) return 'critical'; // Two or more major versions behind
  if (majorDiff === 1) return 'high';    // One major version behind
  
  // Calculate minor version difference if same major version
  if (majorDiff === 0) {
    const minorDiff = (latest[1] || 0) - (current[1] || 0);
    if (minorDiff >= 5) return 'high';     // Five or more minor versions behind
    if (minorDiff >= 2) return 'medium';   // Two to four minor versions behind
  }
  
  return 'low'; // Otherwise low severity
}
