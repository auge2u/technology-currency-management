import { exec } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import axios from 'axios';
import { log } from '../utils/logging';
import { SecurityVulnerability } from '../types/scanning';
import { getRemediation } from '../utils/remediation-helper';

const execAsync = promisify(exec);

// Optional API keys for different security services
const SNYK_API_KEY = process.env.SNYK_API_KEY;
const SONATYPE_API_KEY = process.env.SONATYPE_API_KEY;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

/**
 * Scans for security vulnerabilities in the codebase
 */
export async function scanSecurityVulnerabilities(rootDir: string): Promise<SecurityVulnerability[]> {
  try {
    log.info('Starting security vulnerability scanning');
    
    const results: SecurityVulnerability[] = [];
    
    // Scan using different strategies in parallel
    const [npmResults, owasp, githubResults] = await Promise.all([
      scanNpmVulnerabilities(rootDir),
      scanWithOwaspDependencyCheck(rootDir),
      scanWithGithubAdvisories(rootDir)
    ]);
    
    // Merge all results, removing duplicates
    const allVulnerabilities = [...npmResults, ...owasp, ...githubResults];
    const deduplicatedResults = deduplicateVulnerabilities(allVulnerabilities);
    
    results.push(...deduplicatedResults);
    
    log.info(`Security scanning completed. Found ${results.length} vulnerabilities`);
    
    return results;
  } catch (error) {
    log.error('Error during security vulnerability scanning', { error });
    return [];
  }
}

/**
 * Scan NPM packages for vulnerabilities using npm audit
 */
async function scanNpmVulnerabilities(rootDir: string): Promise<SecurityVulnerability[]> {
  try {
    log.info('Scanning NPM packages for vulnerabilities');
    const results: SecurityVulnerability[] = [];
    
    // Find all package.json files
    const packageFiles = await findFiles(rootDir, 'package.json');
    log.debug(`Found ${packageFiles.length} package.json files`);
    
    for (const packageFile of packageFiles) {
      try {
        // Skip node_modules directories
        if (packageFile.includes('node_modules')) {
          continue;
        }
        
        const packageDir = path.dirname(packageFile);
        
        // Run npm audit --json in the package directory
        const { stdout } = await execAsync('npm audit --json', { cwd: packageDir })
          .catch(error => {
            // npm audit returns non-zero exit code when vulnerabilities are found
            // so we need to capture the output from the error
            if (error && error.stdout) {
              return { stdout: error.stdout };
            }
            throw error;
          });
        
        // Parse the audit output
        const auditResult = JSON.parse(stdout);
        
        // Extract vulnerabilities
        const vulnerabilities = auditResult.vulnerabilities || {};
        
        for (const [packageName, details] of Object.entries<any>(vulnerabilities)) {
          if (details.via) {
            for (const viaItem of Array.isArray(details.via) ? details.via : [details.via]) {
              // Skip items that are just strings (dependency paths)
              if (typeof viaItem === 'string') continue;
              
              const cveIds = [];
              if (viaItem.url && viaItem.url.includes('cve-')) {
                const cveMatch = viaItem.url.match(/CVE-\d+-\d+/i);
                if (cveMatch) {
                  cveIds.push(cveMatch[0]);
                }
              }
              
              const references = [viaItem.url].filter(Boolean);
              
              // Get remediation steps
              const fixedIn = details.fixAvailable ? 
                (typeof details.fixAvailable === 'object' ? details.fixAvailable.version : 'available') : 
                undefined;
              
              const remediationSteps = getRemediation({
                type: 'vulnerability',
                packageName,
                currentVersion: details.version,
                fixedIn,
                url: viaItem.url
              });
              
              // Map npm severity to our severity scale
              const severityMap: Record<string, any> = {
                'low': 'low',
                'moderate': 'medium',
                'high': 'high',
                'critical': 'critical'
              };
              
              results.push({
                id: `npm-${packageName}-${viaItem.source || 'unknown'}`,
                packageName,
                version: details.version,
                title: viaItem.title || `Vulnerability in ${packageName}`,
                description: viaItem.overview || viaItem.desc || `Security vulnerability in ${packageName}`,
                cve: cveIds,
                cvss: viaItem.cvss?.score,
                fixedIn,
                exploitAvailable: viaItem.exploitAvailable || false,
                severity: severityMap[details.severity] || 'medium',
                publicationDate: viaItem.publishedAt ? new Date(viaItem.publishedAt) : undefined,
                remediationSteps,
                references,
                detectedAt: new Date()
              });
            }
          }
        }
      } catch (packageError) {
        log.warn(`Error scanning ${packageFile} for vulnerabilities`, { error: packageError });
      }
    }
    
    log.info(`Found ${results.length} NPM vulnerabilities`);
    return results;
  } catch (error) {
    log.error('Error scanning NPM packages for vulnerabilities', { error });
    return [];
  }
}

/**
 * Scan with OWASP Dependency Check tool
 */
async function scanWithOwaspDependencyCheck(rootDir: string): Promise<SecurityVulnerability[]> {
  try {
    log.info('Scanning with OWASP Dependency Check');
    const results: SecurityVulnerability[] = [];
    
    // Check if OWASP Dependency Check is installed
    try {
      await execAsync('dependency-check --version');
      
      // Create a temporary directory for reports
      const tmpDir = path.join(rootDir, 'tmp-dependency-check');
      fs.mkdirSync(tmpDir, { recursive: true });
      
      // Run dependency check
      const reportFile = path.join(tmpDir, 'dependency-check-report.json');
      
      await execAsync(
        `dependency-check --project "Project Scan" --out ${reportFile} --scan ${rootDir} --format JSON`,
        { maxBuffer: 10 * 1024 * 1024 } // Increase buffer size for large outputs
      );
      
      // Parse the report
      if (fs.existsSync(reportFile)) {
        const reportContent = fs.readFileSync(reportFile, 'utf8');
        const report = JSON.parse(reportContent);
        
        // Extract vulnerabilities
        if (report.dependencies) {
          for (const dependency of report.dependencies) {
            if (dependency.vulnerabilities && dependency.vulnerabilities.length > 0) {
              for (const vuln of dependency.vulnerabilities) {
                const cves = vuln.references
                  .filter((ref: any) => ref.source === 'NVD')
                  .map((ref: any) => ref.name);
                
                const references = vuln.references.map((ref: any) => ref.url).filter(Boolean);
                
                // Map CVSS severity to our severity scale
                let severity: any = 'medium';
                if (vuln.cvssv3 && vuln.cvssv3.baseScore) {
                  const score = vuln.cvssv3.baseScore;
                  if (score >= 9.0) severity = 'critical';
                  else if (score >= 7.0) severity = 'high';
                  else if (score >= 4.0) severity = 'medium';
                  else severity = 'low';
                }
                
                const remediationSteps = getRemediation({
                  type: 'vulnerability',
                  packageName: dependency.name,
                  description: vuln.description,
                  cveId: cves[0]
                });
                
                results.push({
                  id: `owasp-${dependency.name}-${vuln.name}`,
                  packageName: dependency.name,
                  version: dependency.version,
                  title: vuln.name,
                  description: vuln.description,
                  cve: cves,
                  cvss: vuln.cvssv3 ? vuln.cvssv3.baseScore : undefined,
                  exploitAvailable: false, // OWASP doesn't provide this info
                  severity,
                  remediationSteps,
                  references,
                  detectedAt: new Date()
                });
              }
            }
          }
        }
        
        // Clean up temp directory
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    } catch (error) {
      log.warn('OWASP Dependency Check not available or error running it', { error });
    }
    
    log.info(`Found ${results.length} vulnerabilities with OWASP Dependency Check`);
    return results;
  } catch (error) {
    log.error('Error scanning with OWASP Dependency Check', { error });
    return [];
  }
}

/**
 * Scan for vulnerabilities using GitHub Security Advisories
 */
async function scanWithGithubAdvisories(rootDir: string): Promise<SecurityVulnerability[]> {
  try {
    // Skip if no GitHub token is provided
    if (!GITHUB_TOKEN) {
      log.info('Skipping GitHub Advisories scan (no GitHub token provided)');
      return [];
    }
    
    log.info('Scanning with GitHub Security Advisories');
    const results: SecurityVulnerability[] = [];
    
    // Find all dependency files
    const packageFiles = await findFiles(rootDir, 'package.json');
    const requirementsFiles = await findFiles(rootDir, 'requirements.txt');
    const gemfiles = await findFiles(rootDir, 'Gemfile');
    const composerFiles = await findFiles(rootDir, 'composer.json');
    
    // Collect all dependencies
    const allDependencies: Map<string, { name: string, version: string, ecosystem: string }> = new Map();
    
    // Process package.json files
    for (const file of packageFiles) {
      try {
        if (file.includes('node_modules')) continue;
        
        const packageJson = JSON.parse(fs.readFileSync(file, 'utf8'));
        const allDeps = {
          ...packageJson.dependencies || {},
          ...packageJson.devDependencies || {},
        };
        
        for (const [name, versionConstraint] of Object.entries<string>(allDeps)) {
          if (
            versionConstraint.includes('github:') ||
            versionConstraint.includes('git+') ||
            versionConstraint.startsWith('file:')
          ) {
            continue;
          }
          
          const cleanVersion = versionConstraint.replace(/^[\^~]/, '');
          allDependencies.set(`npm:${name}`, {
            name,
            version: cleanVersion,
            ecosystem: 'npm'
          });
        }
      } catch (error) {
        log.warn(`Error processing ${file} for GitHub Advisories`, { error });
      }
    }
    
    // Process requirements.txt files
    for (const file of requirementsFiles) {
      try {
        const content = fs.readFileSync(file, 'utf8');
        const lines = content
          .split('\n')
          .map(line => line.trim())
          .filter(line => line && !line.startsWith('#'));
        
        for (const line of lines) {
          const match = line.match(/^([\w-]+)(?:[=<>!~]+(\d+\.\d+\.\d+))?.*$/);
          if (match) {
            const [, name, version] = match;
            if (name) {
              allDependencies.set(`pip:${name}`, {
                name,
                version: version || 'unknown',
                ecosystem: 'pip'
              });
            }
          }
        }
      } catch (error) {
        log.warn(`Error processing ${file} for GitHub Advisories`, { error });
      }
    }
    
    // Get vulnerabilities from GitHub API
    const ecosystemToGitHub: Record<string, string> = {
      'npm': 'NPM',
      'pip': 'PIP',
      'maven': 'MAVEN',
      'composer': 'COMPOSER',
      'gem': 'RUBYGEMS'
    };
    
    for (const [, dep] of allDependencies) {
      try {
        const githubEcosystem = ecosystemToGitHub[dep.ecosystem];
        if (!githubEcosystem) continue;
        
        const response = await axios.post(
          'https://api.github.com/graphql',
          {
            query: `
              query {
                securityVulnerabilities(ecosystem: ${githubEcosystem}, package: "${dep.name}", first: 100) {
                  nodes {
                    vulnerableVersionRange
                    package {
                      name
                    }
                    advisory {
                      id
                      summary
                      description
                      publishedAt
                      severity
                      references {
                        url
                      }
                      identifiers {
                        type
                        value
                      }
                      cvss {
                        score
                      }
                    }
                  }
                }
              }
            `
          },
          {
            headers: {
              'Authorization': `Bearer ${GITHUB_TOKEN}`,
              'Content-Type': 'application/json'
            }
          }
        );
        
        const vulnerabilities = response.data.data?.securityVulnerabilities?.nodes || [];
        
        for (const vuln of vulnerabilities) {
          // Check if the current version is in the vulnerable range
          // This is a simplified check - in a real implementation you'd need a semantic version range check
          if (isVersionInRange(dep.version, vuln.vulnerableVersionRange)) {
            const advisory = vuln.advisory;
            
            // Extract CVE IDs
            const cves = advisory.identifiers
              .filter((id: any) => id.type === 'CVE')
              .map((id: any) => id.value);
            
            // Extract references
            const references = advisory.references.map((ref: any) => ref.url).filter(Boolean);
            
            // Map GitHub severity to our severity scale
            const severityMap: Record<string, any> = {
              'LOW': 'low',
              'MODERATE': 'medium',
              'HIGH': 'high',
              'CRITICAL': 'critical'
            };
            
            const remediationSteps = getRemediation({
              type: 'vulnerability',
              packageName: dep.name,
              currentVersion: dep.version,
              description: advisory.description,
              cveId: cves[0]
            });
            
            results.push({
              id: `github-${advisory.id}`,
              packageName: dep.name,
              version: dep.version,
              title: advisory.summary,
              description: advisory.description,
              cve: cves,
              cvss: advisory.cvss?.score,
              exploitAvailable: false,  // GitHub doesn't provide this info
              severity: severityMap[advisory.severity] || 'medium',
              publicationDate: advisory.publishedAt ? new Date(advisory.publishedAt) : undefined,
              remediationSteps,
              references,
              detectedAt: new Date()
            });
          }
        }
      } catch (error) {
        log.warn(`Error checking GitHub Advisories for ${dep.name}`, { error });
      }
    }
    
    log.info(`Found ${results.length} vulnerabilities with GitHub Security Advisories`);
    return results;
  } catch (error) {
    log.error('Error scanning with GitHub Security Advisories', { error });
    return [];
  }
}

/**
 * Check if a version is in a vulnerable version range
 * This is a simplified check for demonstration purposes
 */
function isVersionInRange(version: string, range: string): boolean {
  // Basic implementation - this would need a proper semver range check in production
  if (range.includes(version)) return true;
  
  // Handle common patterns
  if (range.includes('*')) {
    const prefix = range.split('*')[0];
    return version.startsWith(prefix);
  }
  
  if (range.includes('<=')) {
    const maxVersion = range.split('<=')[1].trim();
    return compareVersions(version, maxVersion) <= 0;
  }
  
  if (range.includes('<')) {
    const maxVersion = range.split('<')[1].trim();
    return compareVersions(version, maxVersion) < 0;
  }
  
  if (range.includes('>=')) {
    const minVersion = range.split('>=')[1].trim();
    return compareVersions(version, minVersion) >= 0;
  }
  
  if (range.includes('>')) {
    const minVersion = range.split('>')[1].trim();
    return compareVersions(version, minVersion) > 0;
  }
  
  return false;
}

/**
 * Compare two version strings
 * Returns: -1 if a < b, 0 if a == b, 1 if a > b
 */
function compareVersions(a: string, b: string): number {
  if (a === 'unknown' || b === 'unknown') return 0;
  
  const partsA = a.split('.').map(Number);
  const partsB = b.split('.').map(Number);
  
  for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
    const partA = i < partsA.length ? partsA[i] : 0;
    const partB = i < partsB.length ? partsB[i] : 0;
    
    if (partA < partB) return -1;
    if (partA > partB) return 1;
  }
  
  return 0;
}

/**
 * Deduplicate vulnerabilities based on package name, version, and CVE
 */
function deduplicateVulnerabilities(vulnerabilities: SecurityVulnerability[]): SecurityVulnerability[] {
  const uniqueVulnerabilities = new Map<string, SecurityVulnerability>();
  
  for (const vuln of vulnerabilities) {
    // Create a unique key based on package name, version, and CVE
    const cveKey = vuln.cve.length > 0 ? vuln.cve[0] : 'unknown';
    const key = `${vuln.packageName}:${vuln.version}:${cveKey}`;
    
    // Keep the vulnerability with the most information
    if (!uniqueVulnerabilities.has(key) || hasMoreInfo(vuln, uniqueVulnerabilities.get(key)!)) {
      uniqueVulnerabilities.set(key, vuln);
    }
  }
  
  return Array.from(uniqueVulnerabilities.values());
}

/**
 * Determines if vulnerability a has more information than vulnerability b
 */
function hasMoreInfo(a: SecurityVulnerability, b: SecurityVulnerability): boolean {
  // Count the number of defined properties as a simple heuristic
  const countDefinedProps = (obj: any) => 
    Object.entries(obj).filter(([_, v]) => v !== undefined && v !== null).length;
  
  return countDefinedProps(a) > countDefinedProps(b);
}

/**
 * Find files with a specific name recursively
 */
async function findFiles(rootDir: string, fileName: string): Promise<string[]> {
  try {
    const { stdout } = await execAsync(`find ${rootDir} -name "${fileName}" -type f`);
    return stdout.trim().split('\n').filter(Boolean);
  } catch (error) {
    log.error(`Error finding ${fileName} files`, { error });
    return [];
  }
}
