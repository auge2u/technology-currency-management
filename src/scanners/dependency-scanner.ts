import { exec } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import axios from 'axios';
import { log } from '../utils/logging';
import { OutdatedDependency } from '../types/scanning';

const execAsync = promisify(exec);

/**
 * Scanner for detecting outdated dependencies across different package managers
 */
export async function scanDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  try {
    log.info('Starting dependency scanning');
    
    const results: OutdatedDependency[] = [];
    
    // Scan different types of dependency files
    const npmResults = await scanNpmDependencies(rootDir);
    const pythonResults = await scanPythonDependencies(rootDir);
    const rubyResults = await scanRubyDependencies(rootDir);
    const goResults = await scanGoDependencies(rootDir);
    
    results.push(...npmResults, ...pythonResults, ...rubyResults, ...goResults);
    
    log.info(`Dependency scanning completed. Found ${results.length} outdated dependencies`);
    
    return results;
  } catch (error) {
    log.error('Error during dependency scanning', { error });
    return [];
  }
}

/**
 * Calculate severity based on version difference and package importance
 */
function calculateSeverity(currentVersion: string, latestVersion: string, isSecurityCritical = false): 'low' | 'medium' | 'high' | 'critical' {
  // Parse versions (simple semver parsing)
  const current = parseSemVer(currentVersion);
  const latest = parseSemVer(latestVersion);
  
  if (!current || !latest) {
    return isSecurityCritical ? 'high' : 'medium';
  }
  
  // Critical for security-critical packages with any update
  if (isSecurityCritical && (latest.major > current.major || latest.minor > current.minor || latest.patch > current.patch)) {
    return 'critical';
  }
  
  // Major version difference
  if (latest.major > current.major) {
    const majorDiff = latest.major - current.major;
    return majorDiff >= 2 ? 'high' : 'medium';
  }
  
  // Minor version difference
  if (latest.minor > current.minor) {
    const minorDiff = latest.minor - current.minor;
    return minorDiff >= 5 ? 'medium' : 'low';
  }
  
  // Patch version difference
  return latest.patch - current.patch >= 10 ? 'medium' : 'low';
}

/**
 * Parse semantic version string
 */
function parseSemVer(version: string): { major: number; minor: number; patch: number } | null {
  const match = version.match(/^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (!match) return null;
  
  return {
    major: parseInt(match[1] || '0', 10),
    minor: parseInt(match[2] || '0', 10),
    patch: parseInt(match[3] || '0', 10)
  };
}

/**
 * Determine update type based on semantic versioning
 */
function getUpdateType(currentVersion: string, latestVersion: string): 'patch' | 'minor' | 'major' | 'unknown' {
  const current = parseSemVer(currentVersion);
  const latest = parseSemVer(latestVersion);
  
  if (!current || !latest) {
    return 'unknown';
  }
  
  if (latest.major > current.major) {
    return 'major';
  }
  
  if (latest.minor > current.minor) {
    return 'minor';
  }
  
  if (latest.patch > current.patch) {
    return 'patch';
  }
  
  return 'unknown';
}

/**
 * Scan NPM dependencies in package.json files
 */
async function scanNpmDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  try {
    // Find all package.json files
    const { stdout } = await execAsync(`find ${rootDir} -name "package.json" -not -path "*/node_modules/*" -type f`);
    const packageJsonFiles = stdout.trim().split('\n').filter(Boolean);
    
    const results: OutdatedDependency[] = [];
    
    for (const filePath of packageJsonFiles) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const packageJson = JSON.parse(content);
        
        const dependencies = { 
          ...packageJson.dependencies || {}, 
          ...packageJson.devDependencies || {} 
        };
        
        for (const [packageName, versionSpec] of Object.entries(dependencies)) {
          try {
            // Clean version spec (remove ^, ~, etc.)
            const currentVersion = (versionSpec as string).replace(/^[\^~>=<]+/, '');
            
            // Get latest version from npm registry
            const latestVersion = await getLatestNpmVersion(packageName);
            
            if (currentVersion !== latestVersion) {
              const isSecurityCritical = securityCriticalPackages.includes(packageName);
              const updateType = getUpdateType(currentVersion, latestVersion);
              const severity = calculateSeverity(currentVersion, latestVersion, isSecurityCritical);
              const versionsBehind = estimateVersionsBehind(currentVersion, latestVersion);
              const hasSecurityIssues = await checkForKnownVulnerabilities(packageName, currentVersion);
              
              results.push({
                id: `npm-${packageName}-${filePath}`,
                packageName,
                currentVersion,
                latestVersion,
                updateType,
                filePath,
                versionsBehind,
                severity: hasSecurityIssues ? 'critical' : severity,
                hasSecurityIssues,
                updateSteps: `Update in ${path.basename(filePath)} by changing "${packageName}": "${versionSpec}" to "${packageName}": "^${latestVersion}" and running npm install`,
                detectedAt: new Date()
              });
            }
          } catch (packageError) {
            log.warn(`Error processing npm package ${packageName}`, { error: packageError });
          }
        }
      } catch (fileError) {
        log.warn(`Error processing package.json at ${filePath}`, { error: fileError });
      }
    }
    
    return results;
  } catch (error) {
    log.error('Error scanning npm dependencies', { error });
    return [];
  }
}

/**
 * Get the latest version of an npm package
 */
async function getLatestNpmVersion(packageName: string): Promise<string> {
  try {
    const response = await axios.get(`https://registry.npmjs.org/${packageName}`);
    return response.data['dist-tags'].latest;
  } catch (error) {
    log.warn(`Error fetching latest version for npm package ${packageName}`, { error });
    throw error;
  }
}

/**
 * Scan Python dependencies in requirements.txt files
 */
async function scanPythonDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  try {
    // Find all requirements.txt files
    const { stdout } = await execAsync(`find ${rootDir} -name "requirements.txt" -type f`);
    const requirementsFiles = stdout.trim().split('\n').filter(Boolean);
    
    const results: OutdatedDependency[] = [];
    
    for (const filePath of requirementsFiles) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n');
        
        for (const line of lines) {
          // Skip comments and empty lines
          if (line.trim().startsWith('#') || !line.trim()) {
            continue;
          }
          
          // Parse package name and version
          // Examples: package==1.0.0, package>=1.0.0, package~=1.0.0
          const match = line.match(/^([\w-]+)(?:[=<>~]+)([\d.]+)/);
          if (match) {
            const packageName = match[1];
            const currentVersion = match[2];
            
            try {
              // Get latest version from PyPI
              const latestVersion = await getLatestPythonVersion(packageName);
              
              if (currentVersion !== latestVersion) {
                const isSecurityCritical = securityCriticalPackages.includes(packageName);
                const updateType = getUpdateType(currentVersion, latestVersion);
                const severity = calculateSeverity(currentVersion, latestVersion, isSecurityCritical);
                const versionsBehind = estimateVersionsBehind(currentVersion, latestVersion);
                const hasSecurityIssues = await checkForKnownVulnerabilities(packageName, currentVersion, 'python');
                
                results.push({
                  id: `python-${packageName}-${filePath}`,
                  packageName,
                  currentVersion,
                  latestVersion,
                  updateType,
                  filePath,
                  versionsBehind,
                  severity: hasSecurityIssues ? 'critical' : severity,
                  hasSecurityIssues,
                  updateSteps: `Update in ${path.basename(filePath)} by changing ${line} to ${packageName}==${latestVersion} and running pip install -r ${path.basename(filePath)}`,
                  detectedAt: new Date()
                });
              }
            } catch (packageError) {
              log.warn(`Error processing Python package ${packageName}`, { error: packageError });
            }
          }
        }
      } catch (fileError) {
        log.warn(`Error processing requirements.txt at ${filePath}`, { error: fileError });
      }
    }
    
    return results;
  } catch (error) {
    log.error('Error scanning Python dependencies', { error });
    return [];
  }
}

/**
 * Get the latest version of a Python package
 */
async function getLatestPythonVersion(packageName: string): Promise<string> {
  try {
    const response = await axios.get(`https://pypi.org/pypi/${packageName}/json`);
    return response.data.info.version;
  } catch (error) {
    log.warn(`Error fetching latest version for Python package ${packageName}`, { error });
    throw error;
  }
}

/**
 * Scan Ruby dependencies in Gemfiles
 */
async function scanRubyDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  // Implementation would be similar to npm and python scanners
  // For brevity, returning empty array
  return [];
}

/**
 * Scan Go dependencies in go.mod files
 */
async function scanGoDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  // Implementation would be similar to npm and python scanners
  // For brevity, returning empty array
  return [];
}

/**
 * Check if a package has known vulnerabilities
 * This is a simplified implementation
 */
async function checkForKnownVulnerabilities(
  packageName: string, 
  version: string, 
  ecosystem: 'npm' | 'python' | 'ruby' | 'go' = 'npm'
): Promise<boolean> {
  try {
    // In a real implementation, this would query a vulnerability database
    // like Snyk, GitHub Advisory Database, or OSV
    
    // For the example, we'll just check against a hardcoded list
    const key = `${ecosystem}:${packageName}@${version}`;
    return mockVulnerabilities.has(key);
  } catch (error) {
    log.warn(`Error checking vulnerabilities for ${packageName}@${version}`, { error });
    return false;
  }
}

/**
 * Estimate how many versions behind latest
 */
function estimateVersionsBehind(currentVersion: string, latestVersion: string): number {
  const current = parseSemVer(currentVersion);
  const latest = parseSemVer(latestVersion);
  
  if (!current || !latest) {
    return 1;
  }
  
  const majorDiff = Math.max(0, latest.major - current.major);
  const minorDiff = Math.max(0, latest.minor - current.minor);
  const patchDiff = Math.max(0, latest.patch - current.patch);
  
  // Simplified estimate
  return majorDiff * 100 + minorDiff * 10 + patchDiff;
}

// Security-critical packages that should have higher severity ratings
const securityCriticalPackages = [
  // JavaScript/NPM
  'crypto-js', 'jsonwebtoken', 'bcrypt', 'helmet', 'passport', 'dotenv',
  'express', 'koa', 'hapi', 'axios', 'request', 'node-fetch', 'lodash',
  
  // Python
  'django', 'flask', 'requests', 'cryptography', 'pyjwt', 'sqlalchemy',
  'werkzeug', 'tornado', 'twisted', 'paramiko', 'pyyaml', 'pillow',
  
  // Ruby
  'rails', 'sinatra', 'devise', 'bcrypt', 'jwt',
  
  // Go
  'golang.org/x/crypto', 'github.com/gorilla/csrf'
];

// Mock vulnerability database (in a real implementation, this would be a service)
const mockVulnerabilities = new Set([
  'npm:lodash@4.17.15',
  'npm:axios@0.18.0',
  'npm:express@4.16.1',
  'npm:react@16.8.6',
  'python:django@2.2.4',
  'python:flask@1.0.2',
  'python:requests@2.22.0',
  'python:pyyaml@5.1.1'
]);
