import path from 'path';
import fs from 'fs/promises';
import { glob } from 'glob';
import semver from 'semver';
import axios from 'axios';
import { log } from '../../utils/logging';
import { OutdatedDependency } from '../../types/scanning';
import { createScanResult, updateScanResult } from '../services/scan-result-service';
import { getRepositoryInfo } from '../services/repository-service';
import { notifyOutdatedDependencies } from '../services/notification-service';

// Interfaces for dependency files
interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  name?: string;
  version?: string;
}

interface RequirementsTxt {
  dependencies: Array<{ name: string; version: string; line: number }>;
}

interface GemFile {
  dependencies: Array<{ name: string; version: string; line: number }>;
}

interface ComposerJson {
  require?: Record<string, string>;
  "require-dev"?: Record<string, string>;
  name?: string;
  version?: string;
}

/**
 * Runs a dependency scan to find outdated dependencies
 */
export async function runDependencyScan(repoPath?: string): Promise<OutdatedDependency[]> {
  try {
    log.info('Starting dependency scan', { repoPath });
    
    // Create a new scan result record
    const scanId = await createScanResult('dependency');
    
    // Get repository info if path is provided
    let repoInfo = null;
    if (repoPath) {
      repoInfo = await getRepositoryInfo(repoPath);
    }
    
    // Scan for all dependency files
    const dependencyFiles = await findDependencyFiles(repoPath || '.');
    log.info(`Found ${dependencyFiles.length} dependency files`);
    
    // Find outdated dependencies
    const outdatedDependencies = await findOutdatedDependencies(repoPath || '.', dependencyFiles);
    
    // Update scan result with findings
    await updateScanResult(scanId, {
      completedAt: new Date(),
      findings: outdatedDependencies.length,
      scanStatus: 'completed',
      repository: repoInfo
    });
    
    // Send notifications if there are findings
    if (outdatedDependencies.length > 0) {
      await notifyOutdatedDependencies(outdatedDependencies);
    }
    
    log.info(`Dependency scan completed with ${outdatedDependencies.length} findings`);
    return outdatedDependencies;
    
  } catch (error) {
    log.error('Error during dependency scan', { error });
    throw error;
  }
}

/**
 * Finds all dependency management files in a repository
 */
async function findDependencyFiles(repoPath: string): Promise<string[]> {
  const patterns = [
    // Node.js
    '**/package.json',
    // Python
    '**/requirements.txt',
    '**/Pipfile',
    '**/pyproject.toml',
    // Ruby
    '**/Gemfile',
    // PHP
    '**/composer.json',
    // Java
    '**/pom.xml',
    '**/build.gradle',
    // .NET
    '**/*.csproj',
    '**/packages.config',
    // Go
    '**/go.mod',
  ];
  
  const files: string[] = [];
  
  for (const pattern of patterns) {
    try {
      const found = await glob(path.join(repoPath, pattern), { nodir: true });
      files.push(...found);
    } catch (error) {
      log.warn(`Error finding files matching ${pattern}`, { error });
    }
  }
  
  return files;
}

/**
 * Finds outdated dependencies in all dependency files
 */
async function findOutdatedDependencies(
  repoPath: string,
  dependencyFiles: string[]
): Promise<OutdatedDependency[]> {
  const outdatedDependencies: OutdatedDependency[] = [];
  
  for (const filePath of dependencyFiles) {
    try {
      const ext = path.extname(filePath);
      const fileName = path.basename(filePath);
      
      // Process based on file type
      if (fileName === 'package.json') {
        const npmDeps = await findOutdatedNpmDependencies(filePath);
        outdatedDependencies.push(...npmDeps);
      } else if (fileName === 'requirements.txt') {
        const pythonDeps = await findOutdatedPythonDependencies(filePath);
        outdatedDependencies.push(...pythonDeps);
      } else if (fileName === 'Gemfile') {
        const rubyDeps = await findOutdatedRubyDependencies(filePath);
        outdatedDependencies.push(...rubyDeps);
      } else if (fileName === 'composer.json') {
        const phpDeps = await findOutdatedPhpDependencies(filePath);
        outdatedDependencies.push(...phpDeps);
      } else if (fileName === 'pom.xml' || fileName === 'build.gradle') {
        const javaDeps = await findOutdatedJavaDependencies(filePath);
        outdatedDependencies.push(...javaDeps);
      } else if (ext === '.csproj' || fileName === 'packages.config') {
        const dotnetDeps = await findOutdatedDotNetDependencies(filePath);
        outdatedDependencies.push(...dotnetDeps);
      } else if (fileName === 'go.mod') {
        const goDeps = await findOutdatedGoDependencies(filePath);
        outdatedDependencies.push(...goDeps);
      }
    } catch (error) {
      log.warn(`Error processing dependency file ${filePath}`, { error });
    }
  }
  
  return outdatedDependencies;
}

/**
 * Finds outdated npm dependencies in package.json
 */
async function findOutdatedNpmDependencies(filePath: string): Promise<OutdatedDependency[]> {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    const packageJson: PackageJson = JSON.parse(content);
    
    const outdatedDeps: OutdatedDependency[] = [];
    const depTypes = [
      { name: 'dependencies', obj: packageJson.dependencies },
      { name: 'devDependencies', obj: packageJson.devDependencies },
      { name: 'peerDependencies', obj: packageJson.peerDependencies }
    ];
    
    for (const { name: depType, obj } of depTypes) {
      if (!obj) continue;
      
      for (const [depName, versionRange] of Object.entries(obj)) {
        try {
          // Clean version range (remove ^ or ~ if present)
          const currentVersion = versionRange.replace(/[~^]/g, '');
          
          // Check for deprecated versions or known vulnerabilities
          // Get the latest version of the package from npm registry
          const { data } = await axios.get(`https://registry.npmjs.org/${depName}`);
          
          if (data && data['dist-tags'] && data['dist-tags'].latest) {
            const latestVersion = data['dist-tags'].latest;
            
            // Check if deprecated
            const isDeprecated = data.versions && 
              data.versions[currentVersion] && 
              data.versions[currentVersion].deprecated;
              
            // Check if outdated by 2 or more minor versions
            const isMajorOutdated = semver.major(latestVersion) > semver.major(currentVersion);
            const isMinorOutdated = semver.major(latestVersion) === semver.major(currentVersion) && 
                                  semver.minor(latestVersion) >= semver.minor(currentVersion) + 2;
                                  
            if (isDeprecated || isMajorOutdated || isMinorOutdated) {
              // Calculate severity based on how outdated it is
              let severity: 'low' | 'medium' | 'high' | 'critical' = 'low';
              
              if (isDeprecated) {
                severity = 'critical';
              } else if (isMajorOutdated) {
                severity = semver.major(latestVersion) - semver.major(currentVersion) > 1 ? 'high' : 'medium';
              } else if (isMinorOutdated) {
                severity = 'low';
              }
              
              // Create outdated dependency record
              outdatedDeps.push({
                name: depName,
                currentVersion,
                latestVersion,
                packageManager: 'npm',
                dependencyType: depType,
                filePath,
                isDeprecated: !!isDeprecated,
                severity,
                remediationSteps: `Update to version ${latestVersion} by running 'npm install ${depName}@latest'`,
                detectedAt: new Date(),
                releaseDate: data.time && data.time[latestVersion] ? new Date(data.time[latestVersion]) : undefined
              });
            }
          }
        } catch (depError) {
          log.warn(`Error checking npm dependency ${depName}`, { error: depError });
        }
      }
    }
    
    return outdatedDeps;
  } catch (error) {
    log.error(`Error analyzing package.json at ${filePath}`, { error });
    return [];
  }
}

/**
 * Parse Python requirements.txt file
 */
async function parseRequirementsTxt(filePath: string): Promise<RequirementsTxt> {
  const content = await fs.readFile(filePath, 'utf-8');
  const lines = content.split('\n');
  
  const dependencies: Array<{ name: string; version: string; line: number }> = [];
  
  lines.forEach((line, index) => {
    // Skip comments and empty lines
    if (line.trim().startsWith('#') || !line.trim()) return;
    
    // Match package specifications like package==1.0.0, package>=1.0.0
    const match = line.match(/^([a-zA-Z0-9_.-]+)([=<>~!]+)([a-zA-Z0-9_.-]+)/);
    if (match) {
      dependencies.push({
        name: match[1].trim(),
        version: match[3].trim(),
        line: index + 1
      });
    }
  });
  
  return { dependencies };
}

/**
 * Finds outdated Python dependencies in requirements.txt
 */
async function findOutdatedPythonDependencies(filePath: string): Promise<OutdatedDependency[]> {
  try {
    const requirmentsTxt = await parseRequirementsTxt(filePath);
    const outdatedDeps: OutdatedDependency[] = [];
    
    for (const dep of requirmentsTxt.dependencies) {
      try {
        // Check PyPI for latest version
        const { data } = await axios.get(`https://pypi.org/pypi/${dep.name}/json`);
        
        if (data && data.info && data.info.version) {
          const latestVersion = data.info.version;
          
          // Compare versions
          if (semver.valid(dep.version) && semver.valid(latestVersion) && semver.lt(dep.version, latestVersion)) {
            outdatedDeps.push({
              name: dep.name,
              currentVersion: dep.version,
              latestVersion,
              packageManager: 'pip',
              dependencyType: 'dependencies',
              filePath,
              isDeprecated: false, // PyPI doesn't have clear deprecation info
              severity: semver.major(latestVersion) > semver.major(dep.version) ? 'high' : 'medium',
              remediationSteps: `Update to version ${latestVersion} by running 'pip install --upgrade ${dep.name}'`,
              detectedAt: new Date(),
              releaseDate: data.releases && data.releases[latestVersion] && data.releases[latestVersion][0].upload_time 
                ? new Date(data.releases[latestVersion][0].upload_time) 
                : undefined
            });
          }
        }
      } catch (depError) {
        log.warn(`Error checking Python dependency ${dep.name}`, { error: depError });
      }
    }
    
    return outdatedDeps;
  } catch (error) {
    log.error(`Error analyzing requirements.txt at ${filePath}`, { error });
    return [];
  }
}

/**
 * Placeholder for finding outdated Ruby dependencies
 */
async function findOutdatedRubyDependencies(filePath: string): Promise<OutdatedDependency[]> {
  // In a real implementation, this would parse the Gemfile and check RubyGems for updates
  log.info(`Ruby dependency scanning for ${filePath} not fully implemented`);
  return [];
}

/**
 * Placeholder for finding outdated PHP dependencies
 */
async function findOutdatedPhpDependencies(filePath: string): Promise<OutdatedDependency[]> {
  // In a real implementation, this would parse composer.json and check Packagist for updates
  log.info(`PHP dependency scanning for ${filePath} not fully implemented`);
  return [];
}

/**
 * Placeholder for finding outdated Java dependencies
 */
async function findOutdatedJavaDependencies(filePath: string): Promise<OutdatedDependency[]> {
  // In a real implementation, this would parse pom.xml/build.gradle and check Maven Central for updates
  log.info(`Java dependency scanning for ${filePath} not fully implemented`);
  return [];
}

/**
 * Placeholder for finding outdated .NET dependencies
 */
async function findOutdatedDotNetDependencies(filePath: string): Promise<OutdatedDependency[]> {
  // In a real implementation, this would parse .csproj/packages.config and check NuGet for updates
  log.info(`.NET dependency scanning for ${filePath} not fully implemented`);
  return [];
}

/**
 * Placeholder for finding outdated Go dependencies
 */
async function findOutdatedGoDependencies(filePath: string): Promise<OutdatedDependency[]> {
  // In a real implementation, this would parse go.mod and check for updates
  log.info(`Go dependency scanning for ${filePath} not fully implemented`);
  return [];
}
