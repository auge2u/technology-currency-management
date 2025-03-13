import * as fs from 'fs';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import axios from 'axios';
import { SecurityVulnerability } from '../types/scanning';
import { log } from '../utils/logging';

const execAsync = promisify(exec);

/**
 * Scanner to detect security vulnerabilities in dependencies and technologies
 */
export async function scanSecurityVulnerabilities(rootDir: string): Promise<SecurityVulnerability[]> {
  try {
    log.info('Starting security vulnerability scanning');
    
    const results: SecurityVulnerability[] = [];
    
    // Scan for different types of security vulnerabilities
    const npmResults = await scanNpmVulnerabilities(rootDir);
    const pythonResults = await scanPythonVulnerabilities(rootDir);
    const containerResults = await scanContainerVulnerabilities(rootDir);
    const gitSecretsResults = await scanGitSecrets(rootDir);
    
    results.push(
      ...npmResults,
      ...pythonResults,
      ...containerResults,
      ...gitSecretsResults
    );
    
    log.info(`Security vulnerability scanning completed. Found ${results.length} vulnerabilities`);
    
    return results;
  } catch (error) {
    log.error('Error during security vulnerability scanning', { error });
    return [];
  }
}

/**
 * Scan for NPM package vulnerabilities
 */
async function scanNpmVulnerabilities(rootDir: string): Promise<SecurityVulnerability[]> {
  try {
    log.info('Scanning NPM packages for vulnerabilities');
    
    // Find all package.json files (excluding node_modules)
    const { stdout } = await execAsync(`find ${rootDir} -name "package.json" -not -path "*/node_modules/*" -not -path "*/dist/*" -not -path "*/build/*"`);
    const packageJsonFiles = stdout.trim().split('\n').filter(Boolean);
    
    if (packageJsonFiles.length === 0) {
      log.info('No NPM projects found');
      return [];
    }
    
    const results: SecurityVulnerability[] = [];
    
    for (const filePath of packageJsonFiles) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const packageJson = JSON.parse(content);
        const allDependencies = {
          ...packageJson.dependencies,
          ...packageJson.devDependencies
        };
        
        for (const [name, version] of Object.entries(allDependencies)) {
          if (typeof version !== 'string') continue;
          
          // Clean up version string (remove ^, ~, etc.)
          const cleanVersion = version.replace(/^[\^~><=]/, '');
          
          // Check for known vulnerabilities
          const vulnerabilities = await checkNpmPackageVulnerabilities(name, cleanVersion);
          
          for (const vuln of vulnerabilities) {
            results.push({
              id: `npm-${name}-${vuln.id}-${path.dirname(filePath)}`,
              packageName: name,
              packageVersion: cleanVersion,
              vulnerabilityId: vuln.id,
              title: vuln.title,
              description: vuln.description,
              cvss: vuln.cvss,
              severity: vuln.severity,
              fixedInVersion: vuln.fixedInVersion,
              path: filePath,
              remediationSteps: `Update ${name} to version ${vuln.fixedInVersion} or later`,
              references: vuln.references,
              detectedAt: new Date()
            });
          }
        }
      } catch (fileError) {
        log.warn(`Error processing security for package.json at ${filePath}`, { error: fileError });
      }
    }
    
    return results;
  } catch (error) {
    log.error('Error scanning NPM vulnerabilities', { error });
    return [];
  }
}

/**
 * Check NPM package for known vulnerabilities
 */
async function checkNpmPackageVulnerabilities(
  packageName: string,
  version: string
): Promise<Array<{
  id: string;
  title: string;
  description: string;
  cvss: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  fixedInVersion: string;
  references: string[];
}>> {
  // In a real implementation, this would query a vulnerability database
  // For simulation, we'll use a mock database
  return new Promise(resolve => {
    setTimeout(() => {
      // Mock vulnerability database
      const knownVulnerabilities: Record<string, Array<{
        id: string;
        title: string;
        description: string;
        cvss: number;
        severity: 'low' | 'medium' | 'high' | 'critical';
        affectedVersions: string;
        fixedInVersion: string;
        references: string[];
      }>> = {
        'lodash': [
          {
            id: 'CVE-2021-23337',
            title: 'Prototype Pollution in lodash',
            description: 'Lodash versions prior to 4.17.21 are vulnerable to prototype pollution.',
            cvss: 7.4,
            severity: 'high',
            affectedVersions: '<4.17.21',
            fixedInVersion: '4.17.21',
            references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-23337']
          }
        ],
        'axios': [
          {
            id: 'CVE-2023-45857',
            title: 'Header Injection in Axios',
            description: 'Axios before 1.6.0 allows CRLF injection if user controlled data is passed to the auth option.',
            cvss: 9.1,
            severity: 'critical',
            affectedVersions: '<1.6.0',
            fixedInVersion: '1.6.0',
            references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-45857']
          }
        ],
        'express': [
          {
            id: 'CVE-2022-24999',
            title: 'Header Injection Vulnerability',
            description: 'Express through 4.17.3 allows Request Splitting.',
            cvss: 8.1,
            severity: 'high',
            affectedVersions: '<=4.17.3',
            fixedInVersion: '4.18.0',
            references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-24999']
          }
        ]
      };
      
      // Check if package has known vulnerabilities
      const packageVulns = knownVulnerabilities[packageName] || [];
      
      // Filter vulnerabilities that affect the current version
      const affectingVulns = packageVulns.filter(vuln => {
        return isVersionAffected(version, vuln.affectedVersions);
      });
      
      resolve(affectingVulns);
    }, 100);
  });
}

/**
 * Check if a version is affected by vulnerability
 */
function isVersionAffected(version: string, affectedVersionsSpec: string): boolean {
  // For simplicity, we're only handling '<X.Y.Z' format
  if (affectedVersionsSpec.startsWith('<')) {
    const maxVersion = affectedVersionsSpec.substring(1);
    return compareVersions(version, maxVersion) < 0;
  }
  
  // For simplicity, we're only handling '<=X.Y.Z' format
  if (affectedVersionsSpec.startsWith('<=')) {
    const maxVersion = affectedVersionsSpec.substring(2);
    return compareVersions(version, maxVersion) <= 0;
  }
  
  return false;
}

/**
 * Compare two version strings
 * Returns: Negative if version1 < version2, 0 if equal, Positive if version1 > version2
 */
function compareVersions(version1: string, version2: string): number {
  const parts1 = version1.split('.').map(Number);
  const parts2 = version2.split('.').map(Number);
  
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
 * Scan for Python package vulnerabilities
 */
async function scanPythonVulnerabilities(rootDir: string): Promise<SecurityVulnerability[]> {
  // Implementation for scanning Python vulnerabilities
  return [];
}

/**
 * Scan for vulnerabilities in container images and Dockerfiles
 */
async function scanContainerVulnerabilities(rootDir: string): Promise<SecurityVulnerability[]> {
  // Implementation for scanning container vulnerabilities
  return [];
}

/**
 * Scan for secrets accidentally committed to Git
 */
async function scanGitSecrets(rootDir: string): Promise<SecurityVulnerability[]> {
  // Implementation for scanning git secrets
  return [];
}
