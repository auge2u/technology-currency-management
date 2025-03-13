import { exec } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import axios from 'axios';
import { log } from '../utils/logging';
import { SecurityVulnerability } from '../types/scanning';

const execAsync = promisify(exec);

/**
 * Scanner for detecting security vulnerabilities in dependencies
 */
export async function scanSecurityVulnerabilities(rootDir: string): Promise<SecurityVulnerability[]> {
  try {
    log.info('Starting security vulnerability scanning');
    
    const results: SecurityVulnerability[] = [];
    
    // Run different security scans
    const npmResults = await scanNpmSecurityVulnerabilities(rootDir);
    const pythonResults = await scanPythonSecurityVulnerabilities(rootDir);
    const dockerResults = await scanDockerSecurityVulnerabilities(rootDir);
    const generalResults = await scanGeneralSecurityIssues(rootDir);
    
    results.push(...npmResults, ...pythonResults, ...dockerResults, ...generalResults);
    
    log.info(`Security vulnerability scanning completed. Found ${results.length} vulnerabilities`);
    
    return results;
  } catch (error) {
    log.error('Error during security vulnerability scanning', { error });
    return [];
  }
}

/**
 * Scan for NPM security vulnerabilities using data from security advisories
 */
async function scanNpmSecurityVulnerabilities(rootDir: string): Promise<SecurityVulnerability[]> {
  try {
    // Find all package.json files
    const { stdout } = await execAsync(`find ${rootDir} -name "package.json" -not -path "*/node_modules/*" -type f`);
    const packageJsonFiles = stdout.trim().split('\n').filter(Boolean);
    
    const results: SecurityVulnerability[] = [];
    
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
            
            // Query mock vulnerability database (in a real implementation, this would query a real database)
            const vulnerabilities = await queryVulnerabilityDatabase('npm', packageName, currentVersion);
            
            for (const vuln of vulnerabilities) {
              results.push({
                id: `npm-${packageName}-${vuln.cveId || 'no-cve'}-${filePath}`,
                cveId: vuln.cveId,
                packageName,
                affectedVersions: vuln.affectedVersions,
                severity: vuln.severity,
                description: vuln.description,
                infoUrl: vuln.infoUrl,
                patchedVersions: vuln.patchedVersions,
                filePath,
                remediationSteps: `Update ${packageName} to version ${vuln.patchedVersions} or later.`,
                publishedDate: vuln.publishedDate,
                detectedAt: new Date()
              });
            }
          } catch (packageError) {
            log.warn(`Error processing npm package ${packageName} for security`, { error: packageError });
          }
        }
      } catch (fileError) {
        log.warn(`Error processing package.json at ${filePath} for security`, { error: fileError });
      }
    }
    
    return results;
  } catch (error) {
    log.error('Error scanning npm dependencies for security vulnerabilities', { error });
    return [];
  }
}

/**
 * Scan for Python security vulnerabilities
 */
async function scanPythonSecurityVulnerabilities(rootDir: string): Promise<SecurityVulnerability[]> {
  try {
    // Find all requirements.txt files
    const { stdout } = await execAsync(`find ${rootDir} -name "requirements.txt" -type f`);
    const requirementsFiles = stdout.trim().split('\n').filter(Boolean);
    
    const results: SecurityVulnerability[] = [];
    
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
          const match = line.match(/^([\w-]+)(?:[=<>~]+)([\d.]+)/);
          if (match) {
            const packageName = match[1];
            const currentVersion = match[2];
            
            try {
              // Query vulnerability database
              const vulnerabilities = await queryVulnerabilityDatabase('python', packageName, currentVersion);
              
              for (const vuln of vulnerabilities) {
                results.push({
                  id: `python-${packageName}-${vuln.cveId || 'no-cve'}-${filePath}`,
                  cveId: vuln.cveId,
                  packageName,
                  affectedVersions: vuln.affectedVersions,
                  severity: vuln.severity,
                  description: vuln.description,
                  infoUrl: vuln.infoUrl,
                  patchedVersions: vuln.patchedVersions,
                  filePath,
                  remediationSteps: `Update ${packageName} to version ${vuln.patchedVersions} or later.`,
                  publishedDate: vuln.publishedDate,
                  detectedAt: new Date()
                });
              }
            } catch (packageError) {
              log.warn(`Error processing Python package ${packageName} for security`, { error: packageError });
            }
          }
        }
      } catch (fileError) {
        log.warn(`Error processing requirements.txt at ${filePath} for security`, { error: fileError });
      }
    }
    
    return results;
  } catch (error) {
    log.error('Error scanning Python dependencies for security vulnerabilities', { error });
    return [];
  }
}

/**
 * Scan Docker images for security vulnerabilities
 */
async function scanDockerSecurityVulnerabilities(rootDir: string): Promise<SecurityVulnerability[]> {
  try {
    // Find all Dockerfile files
    const { stdout } = await execAsync(`find ${rootDir} -name "Dockerfile" -type f`);
    const dockerfiles = stdout.trim().split('\n').filter(Boolean);
    
    const results: SecurityVulnerability[] = [];
    
    for (const filePath of dockerfiles) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n');
        
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          
          // Match FROM statements to detect base images
          const match = line.match(/^FROM\s+([\w\/\.-]+)(?::([\w\.-]+))?/);
          if (match) {
            const imageName = match[1];
            const imageTag = match[2] || 'latest';
            
            try {
              // Query vulnerability database for this Docker image
              const vulnerabilities = await queryVulnerabilityDatabase('docker', imageName, imageTag);
              
              for (const vuln of vulnerabilities) {
                results.push({
                  id: `docker-${imageName}-${vuln.cveId || 'no-cve'}-${filePath}`,
                  cveId: vuln.cveId,
                  packageName: `${imageName}:${imageTag}`,
                  affectedVersions: vuln.affectedVersions,
                  severity: vuln.severity,
                  description: vuln.description,
                  infoUrl: vuln.infoUrl,
                  patchedVersions: vuln.patchedVersions,
                  filePath,
                  remediationSteps: `Update Docker base image to ${imageName}:${vuln.patchedVersions} or later.`,
                  publishedDate: vuln.publishedDate,
                  detectedAt: new Date()
                });
              }
              
              // Look for other security issues in Dockerfiles
              if (imageTag === 'latest') {
                results.push({
                  id: `docker-latest-tag-${imageName}-${filePath}`,
                  packageName: `${imageName}:latest`,
                  affectedVersions: 'latest',
                  severity: 'medium',
                  description: 'Using the "latest" tag for Docker images can lead to unexpected changes and breaks',
                  patchedVersions: 'specific version tag',
                  filePath,
                  remediationSteps: 'Use a specific version tag instead of "latest" to ensure reproducibility',
                  detectedAt: new Date()
                });
              }
            } catch (imageError) {
              log.warn(`Error processing Docker image ${imageName}:${imageTag} for security`, { error: imageError });
            }
          }
          
          // Check for running as root
          if (!content.includes('USER ') && (content.includes('ENTRYPOINT ') || content.includes('CMD '))) {
            results.push({
              id: `docker-running-as-root-${filePath}`,
              packageName: 'dockerfile',
              affectedVersions: 'all',
              severity: 'medium',
              description: 'Docker container is running as root, which is a security risk',
              patchedVersions: 'N/A',
              filePath,
              remediationSteps: 'Add a USER instruction to run as a non-root user',
              detectedAt: new Date()
            });
          }
        }
      } catch (fileError) {
        log.warn(`Error processing Dockerfile at ${filePath} for security`, { error: fileError });
      }
    }
    
    return results;
  } catch (error) {
    log.error('Error scanning Docker images for security vulnerabilities', { error });
    return [];
  }
}

/**
 * Scan for general security issues in the codebase
 */
async function scanGeneralSecurityIssues(rootDir: string): Promise<SecurityVulnerability[]> {
  try {
    const results: SecurityVulnerability[] = [];
    
    // Find all source code files
    const extensions = [".js", ".ts", ".jsx", ".tsx", ".py", ".rb", ".java", ".go", ".php", ".cs"];
    let filePatterns = extensions.map(ext => `-name "*${ext}"`).join(' -o ');
    
    const { stdout } = await execAsync(`find ${rootDir} -type f \( ${filePatterns} \) -not -path "*/node_modules/*" -not -path "*/venv/*" -not -path "*/vendor/*"`);
    const sourceFiles = stdout.trim().split('\n').filter(Boolean);
    
    // Define security vulnerability patterns to check
    const patterns = [
      {
        regex: /password\s*=\s*["']\w+["']|api[_-]?key\s*=\s*["']\w+["']/i,
        id: 'hardcoded-secrets',
        severity: 'critical' as const,
        description: 'Hardcoded passwords or API keys found in source code',
        remediationSteps: 'Move sensitive values to environment variables or a secure vault solution'
      },
      {
        regex: /eval\s*\(|setTimeout\s*\(\s*["']|setInterval\s*\(\s*["']/,
        id: 'code-injection',
        severity: 'high' as const,
        description: 'Potential code injection vulnerability with eval() or setTimeout/setInterval with strings',
        remediationSteps: 'Avoid using eval() and pass functions (not strings) to setTimeout/setInterval'
      },
      {
        regex: /md5\s*\(|sha1\s*\(/i,
        id: 'weak-hashing',
        severity: 'high' as const,
        description: 'Using weak cryptographic hash functions (MD5, SHA1)',
        remediationSteps: 'Use stronger hashing algorithms like SHA-256 or bcrypt for passwords'
      },
      {
        regex: /SELECT\s+.+\s+FROM.+WHERE.+(['"]\s*\+|\$\{|\$\w+|\?)/i,
        id: 'sql-injection',
        severity: 'critical' as const,
        description: 'Potential SQL injection vulnerability with string concatenation in queries',
        remediationSteps: 'Use parameterized queries or an ORM instead of string concatenation'
      },
      {
        regex: /dangerouslySetInnerHTML|innerHTML\s*=/,
        id: 'xss',
        severity: 'high' as const,
        description: 'Potential XSS vulnerability with dangerouslySetInnerHTML or innerHTML',
        remediationSteps: 'Sanitize HTML content or use safer alternatives'
      }
    ];
    
    // Check each file for patterns
    for (const filePath of sourceFiles) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        
        for (const pattern of patterns) {
          if (pattern.regex.test(content)) {
            results.push({
              id: `general-${pattern.id}-${path.basename(filePath)}`,
              packageName: 'general-code-security',
              affectedVersions: 'all',
              severity: pattern.severity,
              description: pattern.description,
              patchedVersions: 'N/A',
              filePath,
              remediationSteps: pattern.remediationSteps,
              detectedAt: new Date()
            });
          }
        }
      } catch (fileError) {
        log.warn(`Error processing file ${filePath} for general security issues`, { error: fileError });
      }
    }
    
    return results;
  } catch (error) {
    log.error('Error scanning for general security issues', { error });
    return [];
  }
}

/**
 * Query vulnerability database for a specific package
 * This is a mock implementation - in a real tool this would connect to
 * actual vulnerability databases like Snyk, OSV, or GitHub Advisory Database
 */
async function queryVulnerabilityDatabase(
  ecosystem: 'npm' | 'python' | 'docker' | 'ruby' | 'go',
  packageName: string,
  version: string
): Promise<Array<{
  cveId?: string;
  affectedVersions: string;
  patchedVersions: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  infoUrl?: string;
  publishedDate?: Date;
}>> {
  // Simulate an API call to a vulnerability database
  // This is a mock implementation with hardcoded vulnerabilities
  
  // In a real implementation, you would call an actual API like:
  // - https://api.snyk.io/v1/...
  // - https://api.osv.dev/v1/...
  // - https://api.github.com/graphql (GitHub Security Advisories)
  // - https://nvd.nist.gov/vuln/data-feeds
  
  return new Promise((resolve) => {
    // Simulate network delay
    setTimeout(() => {
      const key = `${ecosystem}:${packageName}@${version}`;
      
      // Some mock vulnerabilities for demonstration
      const vulnerabilities: Record<string, Array<{
        cveId?: string;
        affectedVersions: string;
        patchedVersions: string;
        severity: 'low' | 'medium' | 'high' | 'critical';
        description: string;
        infoUrl?: string;
        publishedDate?: Date;
      }>> = {
        'npm:lodash@4.17.15': [
          {
            cveId: 'CVE-2020-8203',
            affectedVersions: '<4.17.19',
            patchedVersions: '4.17.19',
            severity: 'high',
            description: 'Prototype Pollution in lodash via set method allows for modification of Object prototype properties',
            infoUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2020-8203',
            publishedDate: new Date('2020-07-15')
          }
        ],
        'npm:axios@0.18.0': [
          {
            cveId: 'CVE-2019-10742',
            affectedVersions: '<0.18.1',
            patchedVersions: '0.18.1',
            severity: 'medium',
            description: 'Axios up to and including 0.18.0 allows attackers to cause a denial of service (SSRF) by exploiting the way Axios follows redirects',
            infoUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2019-10742',
            publishedDate: new Date('2019-04-15')
          }
        ],
        'npm:express@4.16.1': [
          {
            cveId: 'CVE-2022-24999',
            affectedVersions: '<4.17.3',
            patchedVersions: '4.17.3',
            severity: 'high',
            description: 'Express.js allows for header injection via CRLF sequences in input, potentially allowing for HTTP response splitting attacks',
            infoUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2022-24999',
            publishedDate: new Date('2022-02-18')
          }
        ],
        'python:django@2.2.4': [
          {
            cveId: 'CVE-2019-19844',
            affectedVersions: '>=2.2,<2.2.9',
            patchedVersions: '2.2.9',
            severity: 'high',
            description: 'Account hijack vulnerability in Django through improper handling of email case sensitivity',
            infoUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2019-19844',
            publishedDate: new Date('2019-12-18')
          }
        ],
        'python:flask@1.0.2': [
          {
            cveId: 'CVE-2019-1010083',
            affectedVersions: '<1.0.3',
            patchedVersions: '1.0.3',
            severity: 'high',
            description: 'The Pallets Project Flask before 1.0.3 is affected by a Cross-site Scripting (XSS) vulnerability in the default cookie serializer',
            infoUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2019-1010083',
            publishedDate: new Date('2019-07-17')
          }
        ],
        'docker:nginx:1.16': [
          {
            cveId: 'CVE-2019-9511',
            affectedVersions: '<1.17.3',
            patchedVersions: '1.17.3',
            severity: 'high',
            description: 'HTTP/2 implementation in NGINX before 1.17.3 is vulnerable to excessive CPU consumption due to HTTP/2 implementation allowing flood of empty frames',
            infoUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2019-9511',
            publishedDate: new Date('2019-08-13')
          }
        ],
        'docker:node:10': [
          {
            cveId: 'CVE-2019-15604',
            affectedVersions: '10.x < 10.16.3',
            patchedVersions: '10.16.3',
            severity: 'high',
            description: 'HTTP header parsing in Node.js before 10.16.3 is vulnerable to denial of service attacks',
            infoUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2019-15604',
            publishedDate: new Date('2019-09-06')
          }
        ]
      };
      
      resolve(vulnerabilities[key] || []);
    }, 100);
  });
}
