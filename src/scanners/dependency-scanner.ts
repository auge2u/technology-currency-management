import * as fs from 'fs';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as semver from 'semver';
import axios from 'axios';
import { OutdatedDependency } from '../types/scanning';
import { log } from '../utils/logging';

const execAsync = promisify(exec);

/**
 * Scanner to detect outdated dependencies across different package managers
 */
export async function scanDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  try {
    log.info(`Starting dependency scanning in ${rootDir}`);
    
    const results: OutdatedDependency[] = [];
    
    // Scan for different types of dependencies
    const npmResults = await scanNpmDependencies(rootDir);
    const pythonResults = await scanPythonDependencies(rootDir);
    const javaResults = await scanJavaDependencies(rootDir);
    const rubyResults = await scanRubyDependencies(rootDir);
    const dotnetResults = await scanDotNetDependencies(rootDir);
    const goResults = await scanGoDependencies(rootDir);
    const rustResults = await scanRustDependencies(rootDir);
    
    results.push(
      ...npmResults,
      ...pythonResults,
      ...javaResults,
      ...rubyResults,
      ...dotnetResults,
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
 * Scan for outdated NPM dependencies
 */
async function scanNpmDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  try {
    log.info('Scanning NPM dependencies');
    
    // Find all package.json files (excluding node_modules)
    const { stdout } = await execAsync(`find ${rootDir} -name "package.json" -not -path "*/node_modules/*" -not -path "*/dist/*" -not -path "*/build/*"`);
    const packageJsonFiles = stdout.trim().split('\n').filter(Boolean);
    
    if (packageJsonFiles.length === 0) {
      log.info('No NPM projects found');
      return [];
    }
    
    const results: OutdatedDependency[] = [];
    
    for (const filePath of packageJsonFiles) {
      try {
        log.info(`Processing NPM dependencies in ${filePath}`);
        const content = fs.readFileSync(filePath, 'utf8');
        const packageJson = JSON.parse(content);
        const projectName = packageJson.name || path.basename(path.dirname(filePath));
        
        const allDependencies = {
          ...packageJson.dependencies,
          ...packageJson.devDependencies
        };
        
        for (const [name, versionSpec] of Object.entries(allDependencies)) {
          // Skip packages with non-standard version specs (like Git URLs)
          if (typeof versionSpec !== 'string' || versionSpec.includes(':') || versionSpec.includes('/')) {
            continue;
          }
          
          // Clean up version string (remove ^, ~, etc.)
          const currentVersion = versionSpec.replace(/^[\^~><=]/, '');
          
          try {
            // Check if there's a newer version available
            const latestVersion = await getLatestNpmVersion(name);
            
            if (latestVersion && semver.valid(currentVersion) && semver.valid(latestVersion)) {
              // Calculate version difference
              const diff = semver.diff(currentVersion, latestVersion);
              const behind = getVersionsBehind(currentVersion, latestVersion);
              
              if (diff) {
                const severity = getSeverityForVersionDiff(diff, behind);
                
                // Determine if we should notify based on version difference
                const dependency: OutdatedDependency = {
                  id: `npm-${name}-${projectName}`,
                  name,
                  packageManager: 'npm',
                  currentVersion,
                  latestVersion,
                  versionsBehind: behind,
                  releaseDate: null, // Would require additional API calls to get this
                  severity,
                  path: filePath,
                  isDirectDependency: true,
                  remediationSteps: `Update ${name} to version ${latestVersion} in ${path.basename(filePath)}`,
                  detectedAt: new Date()
                };
                
                results.push(dependency);
              }
            }
          } catch (packageError) {
            log.warn(`Error checking latest version for ${name}`, { error: packageError });
          }
        }
      } catch (fileError) {
        log.warn(`Error processing ${filePath}`, { error: fileError });
      }
    }
    
    return results;
  } catch (error) {
    log.error('Error scanning NPM dependencies', { error });
    return [];
  }
}

/**
 * Get the latest version of an NPM package
 */
async function getLatestNpmVersion(packageName: string): Promise<string | null> {
  try {
    const response = await axios.get(`https://registry.npmjs.org/${packageName}`);
    return response.data['dist-tags']?.latest || null;
  } catch (error) {
    log.warn(`Failed to fetch latest version for ${packageName}`, { error });
    return null;
  }
}

/**
 * Calculate the difference between two semver versions
 */
function getVersionsBehind(current: string, latest: string): {
  major: number;
  minor: number;
  patch: number;
} {
  const currentParts = semver.parse(current);
  const latestParts = semver.parse(latest);
  
  if (!currentParts || !latestParts) {
    return { major: 0, minor: 0, patch: 0 };
  }
  
  // Calculate versions behind for each segment
  let majorBehind = Math.max(0, latestParts.major - currentParts.major);
  let minorBehind = 0;
  let patchBehind = 0;
  
  if (majorBehind === 0) {
    minorBehind = Math.max(0, latestParts.minor - currentParts.minor);
    
    if (minorBehind === 0) {
      patchBehind = Math.max(0, latestParts.patch - currentParts.patch);
    }
  }
  
  return {
    major: majorBehind,
    minor: minorBehind,
    patch: patchBehind
  };
}

/**
 * Determine severity based on version difference and count
 */
function getSeverityForVersionDiff(
  diff: string,
  behind: { major: number; minor: number; patch: number }
): 'low' | 'medium' | 'high' | 'critical' {
  // Major version differences
  if (diff === 'major') {
    if (behind.major >= 3) return 'critical';
    if (behind.major >= 2) return 'high';
    return 'medium';
  }
  
  // Minor version differences
  if (diff === 'minor') {
    if (behind.minor >= 10) return 'high';
    if (behind.minor >= 5) return 'medium';
    return 'low';
  }
  
  // Patch version differences
  if (diff === 'patch') {
    if (behind.patch >= 20) return 'medium';
    if (behind.patch >= 10) return 'low';
    return 'low';
  }
  
  // Default
  return 'low';
}

/**
 * Scan for outdated Python dependencies
 */
async function scanPythonDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  try {
    log.info('Scanning Python dependencies');
    
    // Find all requirements.txt files
    const { stdout: requirementsStdout } = await execAsync(`find ${rootDir} -name "requirements.txt" -not -path "*/venv/*" -not -path "*/.env/*"`);
    const requirementsFiles = requirementsStdout.trim().split('\n').filter(Boolean);
    
    // Find all Pipfile files
    const { stdout: pipfileStdout } = await execAsync(`find ${rootDir} -name "Pipfile" -not -path "*/venv/*" -not -path "*/.env/*"`);
    const pipfileFiles = pipfileStdout.trim().split('\n').filter(Boolean);
    
    // Find all pyproject.toml files
    const { stdout: pyprojectStdout } = await execAsync(`find ${rootDir} -name "pyproject.toml" -not -path "*/venv/*" -not -path "*/.env/*"`);
    const pyprojectFiles = pyprojectStdout.trim().split('\n').filter(Boolean);
    
    if (requirementsFiles.length === 0 && pipfileFiles.length === 0 && pyprojectFiles.length === 0) {
      log.info('No Python projects found');
      return [];
    }
    
    const results: OutdatedDependency[] = [];
    
    // Process requirements.txt files
    for (const filePath of requirementsFiles) {
      try {
        log.info(`Processing Python dependencies in ${filePath}`);
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n');
        
        for (const line of lines) {
          // Skip comments and empty lines
          if (line.trim().startsWith('#') || !line.trim()) continue;
          
          // Parse package name and version
          // This regex matches patterns like 'package==1.0.0', 'package>=1.0.0', etc.
          const match = line.match(/^([\w-\.]+)(\s*[=<>!~]+\s*[\w\.]+)?/);
          
          if (match) {
            const name = match[1];
            let currentVersion = 'unknown';
            
            // Extract version if present
            if (match[2]) {
              const versionMatch = match[2].match(/[=<>!~]+\s*([\w\.]+)/);
              if (versionMatch) {
                currentVersion = versionMatch[1];
              }
            }
            
            // Skip packages without a specific version
            if (currentVersion === 'unknown') {
              continue;
            }
            
            try {
              // Check if there's a newer version available
              const latestVersion = await getLatestPypiVersion(name);
              
              if (latestVersion && currentVersion !== 'unknown') {
                // Try to parse as semver
                const currentSemver = parsePythonVersionToSemver(currentVersion);
                const latestSemver = parsePythonVersionToSemver(latestVersion);
                
                if (currentSemver && latestSemver && semver.lt(currentSemver, latestSemver)) {
                  // Calculate version difference
                  const diff = semver.diff(currentSemver, latestSemver);
                  const behind = getVersionsBehind(currentSemver, latestSemver);
                  
                  if (diff) {
                    const severity = getSeverityForVersionDiff(diff, behind);
                    
                    const dependency: OutdatedDependency = {
                      id: `pip-${name}-${path.basename(path.dirname(filePath))}`,
                      name,
                      packageManager: 'pip',
                      currentVersion,
                      latestVersion,
                      versionsBehind: behind,
                      releaseDate: null,
                      severity,
                      path: filePath,
                      isDirectDependency: true,
                      remediationSteps: `Update ${name} to version ${latestVersion} in ${path.basename(filePath)}`,
                      detectedAt: new Date()
                    };
                    
                    results.push(dependency);
                  }
                }
              }
            } catch (packageError) {
              log.warn(`Error checking latest version for Python package ${name}`, { error: packageError });
            }
          }
        }
      } catch (fileError) {
        log.warn(`Error processing ${filePath}`, { error: fileError });
      }
    }
    
    // Process Pipfile and pyproject.toml files
    // In a real implementation, we would parse these files and check for outdated dependencies
    // For brevity, we'll skip the implementation details here
    
    return results;
  } catch (error) {
    log.error('Error scanning Python dependencies', { error });
    return [];
  }
}

/**
 * Get the latest version of a PyPI package
 */
async function getLatestPypiVersion(packageName: string): Promise<string | null> {
  try {
    const response = await axios.get(`https://pypi.org/pypi/${packageName}/json`);
    return response.data.info.version || null;
  } catch (error) {
    log.warn(`Failed to fetch latest version for Python package ${packageName}`, { error });
    return null;
  }
}

/**
 * Parse Python version string to semver format
 */
function parsePythonVersionToSemver(version: string): string | null {
  // Handle simple versions like '1.0.0'
  if (semver.valid(version)) {
    return version;
  }
  
  // Try to handle versions like '1.0', '1.0.0a1', etc.
  const match = version.match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[a-zA-Z]+\d*)?$/);
  
  if (match) {
    const major = match[1] || '0';
    const minor = match[2] || '0';
    const patch = match[3] || '0';
    
    // Construct a valid semver string
    const semverVersion = `${major}.${minor}.${patch}`;
    
    if (semver.valid(semverVersion)) {
      return semverVersion;
    }
  }
  
  return null;
}

/**
 * Scan for outdated Java dependencies (Maven/Gradle)
 */
async function scanJavaDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  // Implementation for scanning Java dependencies would go here
  // This would involve parsing pom.xml or build.gradle files and
  // comparing with latest versions from Maven Central
  return [];
}

/**
 * Scan for outdated Ruby dependencies (Gemfile)
 */
async function scanRubyDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  // Implementation for scanning Ruby dependencies would go here
  // This would involve parsing Gemfile/Gemfile.lock files and
  // comparing with latest versions from RubyGems
  return [];
}

/**
 * Scan for outdated .NET dependencies
 */
async function scanDotNetDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  // Implementation for scanning .NET dependencies would go here
  // This would involve parsing .csproj files and comparing with
  // latest versions from NuGet
  return [];
}

/**
 * Scan for outdated Go dependencies
 */
async function scanGoDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  // Implementation for scanning Go dependencies would go here
  // This would involve parsing go.mod files and comparing with
  // latest versions from Go modules proxy
  return [];
}

/**
 * Scan for outdated Rust dependencies
 */
async function scanRustDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  // Implementation for scanning Rust dependencies would go here
  // This would involve parsing Cargo.toml files and comparing with
  // latest versions from crates.io
  return [];
}
