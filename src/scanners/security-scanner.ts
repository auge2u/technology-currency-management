import * as fs from 'fs';
import * as path from 'path';
import axios from 'axios';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as semver from 'semver';
import { SecurityVulnerability } from '../types/scanning';
import { log } from '../utils/logging';

const execAsync = promisify(exec);

/**
 * Configuration for security scanning
 */
export interface SecurityScannerConfig {
  // API keys for vulnerability databases
  snykApiKey?: string;
  sonatypeApiKey?: string;
  ossIndexUsername?: string;
  ossIndexPassword?: string;
  githubToken?: string;
  
  // Sources to check for vulnerabilities
  vulnerabilitySources: Array<'snyk' | 'osv' | 'github' | 'ossindex' | 'npmAudit' | 'sonatype'>;
  
  // CVSS severity threshold for reporting
  minSeverity: number;
  
  // Whether to include dev dependencies
  includeDevDependencies: boolean;
  
  // Whether to check for dependencies transitively
  checkTransitiveDependencies: boolean;
  
  // Cache TTL in minutes
  cacheTtlMinutes: number;
  
  // Cache directory
  cacheDir: string;
  
  // Ignored vulnerabilities (by ID)
  ignoredVulnerabilities: string[];
  
  // Ignored packages
  ignoredPackages: string[];
  
  // Custom vulnerability data sources
  customDataSources?: Array<{
    name: string;
    url: string;
    headers?: Record<string, string>;
    mapping: Record<string, string>; // how to map external data to our format
  }>;
}

/**
 * Run a security scan on the specified directory
 */
export async function scanForSecurityVulnerabilities(
  rootDir: string,
  config: SecurityScannerConfig
): Promise<SecurityVulnerability[]> {
  try {
    log.info(`Starting security vulnerability scanning in ${rootDir}`);
    
    const results: SecurityVulnerability[] = [];
    
    // Find dependencies in the project
    const npmDependencies = await findNpmDependencies(rootDir, config.includeDevDependencies);
    const pipDependencies = await findPipDependencies(rootDir);
    
    // Check for vulnerabilities in NPM dependencies
    if (npmDependencies.length > 0) {
      log.info(`Checking ${npmDependencies.length} NPM packages for vulnerabilities`);
      
      // Check with npm audit if enabled
      if (config.vulnerabilitySources.includes('npmAudit')) {
        const npmAuditResults = await runNpmAudit(rootDir);
        results.push(...npmAuditResults);
      }
      
      // Check with Snyk if enabled
      if (config.vulnerabilitySources.includes('snyk') && config.snykApiKey) {
        const snykResults = await checkSnykVulnerabilities(npmDependencies, config.snykApiKey);
        results.push(...snykResults);
      }
      
      // Check with OSV if enabled
      if (config.vulnerabilitySources.includes('osv')) {
        const osvResults = await checkOSVVulnerabilities(npmDependencies, 'npm');
        results.push(...osvResults);
      }
      
      // Check with GitHub Advisory Database if enabled
      if (config.vulnerabilitySources.includes('github')) {
        const githubResults = await checkGitHubAdvisories(npmDependencies, 'NPM', config.githubToken);
        results.push(...githubResults);
      }
    }
    
    // Check for vulnerabilities in Python dependencies
    if (pipDependencies.length > 0) {
      log.info(`Checking ${pipDependencies.length} Python packages for vulnerabilities`);
      
      // Check with OSV if enabled
      if (config.vulnerabilitySources.includes('osv')) {
        const osvResults = await checkOSVVulnerabilities(pipDependencies, 'PyPI');
        results.push(...osvResults);
      }
      
      // Check with GitHub Advisory Database if enabled
      if (config.vulnerabilitySources.includes('github')) {
        const githubResults = await checkGitHubAdvisories(pipDependencies, 'PIP', config.githubToken);
        results.push(...githubResults);
      }
    }
    
    // Filter results by minimum severity
    const filteredResults = results.filter(
      v => v.cvss >= config.minSeverity && 
      !config.ignoredVulnerabilities.includes(v.vulnerabilityId) &&
      !config.ignoredPackages.includes(v.packageName)
    );
    
    // Deduplicate results by vulnerability ID
    const dedupedResults: SecurityVulnerability[] = [];
    const seenVulnIds = new Set<string>();
    
    for (const result of filteredResults) {
      if (!seenVulnIds.has(result.vulnerabilityId)) {
        seenVulnIds.add(result.vulnerabilityId);
        dedupedResults.push(result);
      }
    }
    
    log.info(`Security scanning completed. Found ${dedupedResults.length} unique vulnerabilities`);
    return dedupedResults;
  } catch (error) {
    log.error('Error during security vulnerability scanning', { error });
    return [];
  }
}

/**
 * Find NPM dependencies in the project
 */
async function findNpmDependencies(
  rootDir: string,
  includeDevDependencies: boolean
): Promise<Array<{ name: string; version: string; path: string }>> {
  try {
    // Find all package.json files (excluding node_modules)
    const { stdout } = await execAsync(`find ${rootDir} -name "package.json" -not -path "*/node_modules/*" -not -path "*/dist/*" -not -path "*/build/*"`);
    const packageJsonFiles = stdout.trim().split('\n').filter(Boolean);
    
    if (packageJsonFiles.length === 0) {
      return [];
    }
    
    const dependencies: Array<{ name: string; version: string; path: string }> = [];
    
    for (const filePath of packageJsonFiles) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const packageJson = JSON.parse(content);
        
        // Process regular dependencies
        if (packageJson.dependencies) {
          for (const [name, version] of Object.entries(packageJson.dependencies)) {
            if (typeof version === 'string') {
              dependencies.push({
                name,
                version: version.replace(/^[\^~><=]/, ''), // Remove version prefixes
                path: filePath
              });
            }
          }
        }
        
        // Process dev dependencies if requested
        if (includeDevDependencies && packageJson.devDependencies) {
          for (const [name, version] of Object.entries(packageJson.devDependencies)) {
            if (typeof version === 'string') {
              dependencies.push({
                name,
                version: version.replace(/^[\^~><=]/, ''), // Remove version prefixes
                path: filePath
              });
            }
          }
        }
      } catch (fileError) {
        log.warn(`Error processing ${filePath}`, { error: fileError });
      }
    }
    
    return dependencies;
  } catch (error) {
    log.error('Error finding NPM dependencies', { error });
    return [];
  }
}

/**
 * Find Python dependencies in the project
 */
async function findPipDependencies(rootDir: string): Promise<Array<{ name: string; version: string; path: string }>> {
  try {
    // Find all requirements.txt files
    const { stdout } = await execAsync(`find ${rootDir} -name "requirements.txt" -not -path "*/venv/*" -not -path "*/.env/*"`);
    const requirementsFiles = stdout.trim().split('\n').filter(Boolean);
    
    if (requirementsFiles.length === 0) {
      return [];
    }
    
    const dependencies: Array<{ name: string; version: string; path: string }> = [];
    
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
          const match = line.match(/^([\w-\.]+)(?:[=<>!~]+([\w\.]+))?/);
          
          if (match) {
            const name = match[1];
            const version = match[2] || 'unknown';
            
            // Skip packages without a specific version
            if (version !== 'unknown') {
              dependencies.push({
                name,
                version,
                path: filePath
              });
            }
          }
        }
      } catch (fileError) {
        log.warn(`Error processing ${filePath}`, { error: fileError });
      }
    }
    
    return dependencies;
  } catch (error) {
    log.error('Error finding Python dependencies', { error });
    return [];
  }
}

/**
 * Run npm audit to find vulnerabilities
 */
async function runNpmAudit(rootDir: string): Promise<SecurityVulnerability[]> {
  try {
    log.info('Running npm audit');
    
    // Find all package.json directories
    const { stdout } = await execAsync(`find ${rootDir} -name "package.json" -not -path "*/node_modules/*" -not -path "*/dist/*" -not -path "*/build/*"`);
    const packageJsonFiles = stdout.trim().split('\n').filter(Boolean);
    
    if (packageJsonFiles.length === 0) {
      return [];
    }
    
    const results: SecurityVulnerability[] = [];
    
    for (const filePath of packageJsonFiles) {
      const packageDir = path.dirname(filePath);
      
      try {
        log.info(`Running npm audit in ${packageDir}`);
        
        // Run npm audit with JSON output
        const { stdout: auditOutput } = await execAsync('npm audit --json', { cwd: packageDir });
        const auditData = JSON.parse(auditOutput);
        
        // Process vulnerabilities from npm audit
        if (auditData.vulnerabilities) {
          for (const [name, vulnData] of Object.entries(auditData.vulnerabilities)) {
            const vulnInfo = vulnData as any; // Type assertion for easier access
            
            // Skip informational advisories
            if (vulnInfo.severity === 'info') {
              continue;
            }
            
            const severity = mapNpmSeverityToCVSS(vulnInfo.severity);
            
            if (vulnInfo.via && Array.isArray(vulnInfo.via)) {
              // Process each vulnerability source
              for (const via of vulnInfo.via) {
                if (typeof via === 'object') {
                  // Process detailed vulnerability info
                  const vulnerability: SecurityVulnerability = {
                    id: `npm-${name}-${via.source || 'unknown'}-${via.name || 'unknown'}`,
                    vulnerabilityId: via.source || `npm-audit-${name}`,
                    packageName: name,
                    packageVersion: vulnInfo.version || 'unknown',
                    title: via.title || `Security vulnerability in ${name}`,
                    description: via.url || 'No description available',
                    cvss: severity,
                    fixedInVersion: vulnInfo.fixAvailable?.version || 'No fix available',
                    path: filePath,
                    remediationSteps: buildNpmRemediationSteps(name, vulnInfo),
                    references: [via.url].filter(Boolean) as string[],
                    severity: mapCVSSToSeverity(severity),
                    detectedAt: new Date()
                  };
                  
                  results.push(vulnerability);
                }
              }
            }
          }
        }
      } catch (auditError) {
        // npm audit may fail if there are issues with the package.json
        // We'll just log this and continue with other packages
        log.warn(`Error running npm audit in ${packageDir}`, { error: auditError });
      }
    }
    
    return results;
  } catch (error) {
    log.error('Error running npm audit', { error });
    return [];
  }
}

/**
 * Map npm severity level to CVSS score
 */
function mapNpmSeverityToCVSS(severity: string): number {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 9.0;
    case 'high':
      return 7.5;
    case 'moderate':
      return 5.0;
    case 'low':
      return 3.0;
    default:
      return 0.0;
  }
}

/**
 * Map CVSS score to severity level
 */
function mapCVSSToSeverity(cvss: number): 'low' | 'medium' | 'high' | 'critical' {
  if (cvss >= 9.0) return 'critical';
  if (cvss >= 7.0) return 'high';
  if (cvss >= 4.0) return 'medium';
  return 'low';
}

/**
 * Build remediation steps for npm vulnerabilities
 */
function buildNpmRemediationSteps(packageName: string, vulnInfo: any): string {
  const steps = [];
  
  if (vulnInfo.fixAvailable) {
    if (vulnInfo.fixAvailable.name === packageName) {
      steps.push(`Update ${packageName} to version ${vulnInfo.fixAvailable.version} or later.`);
      steps.push(`Run: npm update ${packageName} --depth=0`);
    } else {
      steps.push(`This is a vulnerability in a dependency of ${packageName}.`);
      steps.push(`Update ${vulnInfo.fixAvailable.name} to version ${vulnInfo.fixAvailable.version} or later.`);
    }
  } else {
    steps.push(`No direct fix is available for ${packageName}.`);
    steps.push('Consider the following options:');
    steps.push('1. Check if there is a newer version of the package that fixes the vulnerability.');
    steps.push('2. Look for alternative packages that provide similar functionality.');
    steps.push('3. Evaluate if the vulnerability is exploitable in your specific use case.');
  }
  
  return steps.join('\n');
}

/**
 * Check vulnerabilities using Snyk API
 */
async function checkSnykVulnerabilities(
  dependencies: Array<{ name: string; version: string; path: string }>,
  snykApiKey: string
): Promise<SecurityVulnerability[]> {
  try {
    log.info('Checking vulnerabilities with Snyk');
    
    const results: SecurityVulnerability[] = [];
    const baseUrl = 'https://snyk.io/api/v1';
    
    for (const { name, version, path: filePath } of dependencies) {
      try {
        // Call Snyk API to test the package
        const response = await axios.post(
          `${baseUrl}/test/npm/${encodeURIComponent(name)}/${encodeURIComponent(version)}`,
          {},
          {
            headers: {
              'Authorization': `token ${snykApiKey}`,
              'Content-Type': 'application/json'
            }
          }
        );
        
        // Process vulnerabilities from Snyk response
        if (response.data.issues && response.data.issues.vulnerabilities) {
          for (const vuln of response.data.issues.vulnerabilities) {
            const vulnerability: SecurityVulnerability = {
              id: `snyk-${name}-${vuln.id}`,
              vulnerabilityId: vuln.id,
              packageName: name,
              packageVersion: version,
              title: vuln.title,
              description: vuln.description || 'No description available',
              cvss: vuln.cvssScore || mapNpmSeverityToCVSS(vuln.severity),
              fixedInVersion: vuln.fixedIn[0] || 'No fix available',
              path: filePath,
              remediationSteps: buildSnykRemediationSteps(name, vuln),
              references: [
                vuln.url,
                ...vuln.references?.map((ref: any) => ref.url) || []
              ].filter(Boolean) as string[],
              severity: mapCVSSToSeverity(vuln.cvssScore || mapNpmSeverityToCVSS(vuln.severity)),
              detectedAt: new Date()
            };
            
            results.push(vulnerability);
          }
        }
      } catch (packageError) {
        log.warn(`Error checking ${name}@${version} with Snyk`, { error: packageError });
      }
    }
    
    return results;
  } catch (error) {
    log.error('Error checking vulnerabilities with Snyk', { error });
    return [];
  }
}

/**
 * Build remediation steps for Snyk vulnerabilities
 */
function buildSnykRemediationSteps(packageName: string, vulnInfo: any): string {
  const steps = [];
  
  steps.push(`Vulnerability: ${vulnInfo.title}`);
  
  if (vulnInfo.fixedIn && vulnInfo.fixedIn.length > 0) {
    steps.push(`Update ${packageName} to version ${vulnInfo.fixedIn[0]} or later.`);
    steps.push(`Run: npm update ${packageName} --depth=0`);
    
    if (vulnInfo.from && vulnInfo.from.length > 1) {
      // It's a transitive dependency
      steps.push('');
      steps.push('This is a vulnerability in a dependency chain:');
      steps.push(vulnInfo.from.join(' > '));
      steps.push('');
      steps.push('You may need to upgrade the direct dependency that requires this package.');
    }
  } else {
    steps.push('No fixed version is available yet.');
    steps.push('Consider:');
    steps.push('1. Looking for alternative packages');
    steps.push('2. Implementing additional security controls');
    steps.push('3. Assessing if the vulnerability is exploitable in your context');
  }
  
  if (vulnInfo.patches && vulnInfo.patches.length > 0) {
    steps.push('');
    steps.push('Snyk can patch this vulnerability, run:');
    steps.push('npm install -g snyk');
    steps.push('snyk protect');
  }
  
  return steps.join('\n');
}

/**
 * Check vulnerabilities in the OSV database
 */
async function checkOSVVulnerabilities(
  dependencies: Array<{ name: string; version: string; path: string }>,
  ecosystem: string
): Promise<SecurityVulnerability[]> {
  try {
    log.info(`Checking vulnerabilities with OSV for ${ecosystem}`);
    
    const results: SecurityVulnerability[] = [];
    const baseUrl = 'https://api.osv.dev/v1/query';
    
    // OSV API allows batch queries, but we'll limit batch size
    const batchSize = 50;
    for (let i = 0; i < dependencies.length; i += batchSize) {
      const batch = dependencies.slice(i, i + batchSize);
      
      try {
        // Prepare OSV query for batch
        const osvQuery = {
          package: {
            ecosystem
          },
          version: '',
          query: batch.map(dep => ({
            package: {
              name: dep.name,
              ecosystem
            },
            version: dep.version
          }))
        };
        
        // Call OSV API
        const response = await axios.post(baseUrl, osvQuery);
        
        // Process vulnerabilities from OSV response
        if (response.data.vulns) {
          for (const vuln of response.data.vulns) {
            // Find matching dependency for this vulnerability
            const affectedPackages = vuln.affected.filter((a: any) => 
              a.package.name && batch.some(dep => dep.name === a.package.name)
            );
            
            for (const affected of affectedPackages) {
              const dep = batch.find(d => d.name === affected.package.name);
              
              if (dep) {
                // Check if the version is affected
                const isVersionAffected = affected.ranges.some((range: any) => {
                  if (range.type === 'SEMVER') {
                    return range.events.some((event: any) => {
                      if (event.introduced === '0') {
                        return event.fixed ? semver.lt(dep.version, event.fixed) : true;
                      }
                      if (event.introduced && event.fixed) {
                        return semver.gte(dep.version, event.introduced) && 
                               semver.lt(dep.version, event.fixed);
                      }
                      if (event.introduced) {
                        return semver.gte(dep.version, event.introduced);
                      }
                      return false;
                    });
                  }
                  return false;
                });
                
                if (isVersionAffected) {
                  // Find fixed version if available
                  let fixedVersions: string[] = [];
                  affected.ranges.forEach((range: any) => {
                    if (range.type === 'SEMVER') {
                      range.events.forEach((event: any) => {
                        if (event.fixed) {
                          fixedVersions.push(event.fixed);
                        }
                      });
                    }
                  });
                  
                  // Sort fixed versions to recommend the lowest valid one
                  fixedVersions.sort((a, b) => {
                    if (semver.valid(a) && semver.valid(b)) {
                      return semver.compare(a, b);
                    }
                    return 0;
                  });
                  
                  // Try to get CVSS from the database entry
                  let cvss = 5.0; // Default medium severity
                  if (vuln.database_specific && vuln.database_specific.severity) {
                    cvss = mapSeverityToCVSS(vuln.database_specific.severity);
                  }
                  
                  const vulnerability: SecurityVulnerability = {
                    id: `osv-${dep.name}-${vuln.id}`,
                    vulnerabilityId: vuln.id,
                    packageName: dep.name,
                    packageVersion: dep.version,
                    title: vuln.summary || `Security vulnerability in ${dep.name}`,
                    description: vuln.details || 'No details available',
                    cvss,
                    fixedInVersion: fixedVersions[0] || 'No fix available',
                    path: dep.path,
                    remediationSteps: buildOSVRemediationSteps(dep.name, fixedVersions, vuln),
                    references: vuln.references?.map((ref: any) => ref.url) || [],
                    severity: mapCVSSToSeverity(cvss),
                    detectedAt: new Date()
                  };
                  
                  results.push(vulnerability);
                }
              }
            }
          }
        }
      } catch (batchError) {
        log.warn('Error checking batch with OSV', { error: batchError, batch: batch.map(d => `${d.name}@${d.version}`) });
      }
    }
    
    return results;
  } catch (error) {
    log.error('Error checking vulnerabilities with OSV', { error });
    return [];
  }
}

/**
 * Map severity string to CVSS score
 */
function mapSeverityToCVSS(severity: string): number {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 9.5;
    case 'high':
      return 8.0;
    case 'medium':
    case 'moderate':
      return 5.5;
    case 'low':
      return 3.5;
    default:
      return 5.0; // Default to medium
  }
}

/**
 * Build remediation steps for OSV vulnerabilities
 */
function buildOSVRemediationSteps(packageName: string, fixedVersions: string[], vulnInfo: any): string {
  const steps = [];
  
  steps.push(`Vulnerability: ${vulnInfo.summary || vulnInfo.id}`);
  
  if (fixedVersions.length > 0) {
    steps.push(`Update ${packageName} to version ${fixedVersions[0]} or later.`);
    steps.push(`Run: npm update ${packageName} --depth=0`);
  } else {
    steps.push('No fixed version is available yet.');
    steps.push('Consider:');
    steps.push('1. Looking for alternative packages');
    steps.push('2. Implementing additional security controls');
    steps.push('3. Assessing if the vulnerability is exploitable in your context');
  }
  
  if (vulnInfo.references && vulnInfo.references.length > 0) {
    steps.push('');
    steps.push('References:');
    vulnInfo.references.forEach((ref: any) => {
      if (ref.url) {
        steps.push(`- ${ref.url}`);
      }
    });
  }
  
  return steps.join('\n');
}

/**
 * Check vulnerabilities in GitHub Advisory Database
 */
async function checkGitHubAdvisories(
  dependencies: Array<{ name: string; version: string; path: string }>,
  ecosystem: string,
  githubToken?: string
): Promise<SecurityVulnerability[]> {
  try {
    log.info(`Checking vulnerabilities with GitHub Advisories for ${ecosystem}`);
    
    const results: SecurityVulnerability[] = [];
    const baseUrl = 'https://api.github.com/graphql';
    
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    
    if (githubToken) {
      headers['Authorization'] = `bearer ${githubToken}`;
    }
    
    // Process dependencies in smaller batches to avoid hitting rate limits
    const batchSize = 10;
    for (let i = 0; i < dependencies.length; i += batchSize) {
      const batch = dependencies.slice(i, i + batchSize);
      
      for (const { name, version, path: filePath } of batch) {
        try {
          // Construct GraphQL query for GitHub Security Advisories
          const query = `
            query {
              securityVulnerabilities(ecosystem: ${ecosystem}, package: "${name}", first: 100) {
                edges {
                  node {
                    advisory {
                      id
                      summary
                      description
                      severity
                      references {
                        url
                      }
                      publishedAt
                      updatedAt
                    }
                    vulnerableVersionRange
                    firstPatchedVersion {
                      identifier
                    }
                  }
                }
              }
            }
          `;
          
          // Call GitHub GraphQL API
          const response = await axios.post(
            baseUrl,
            { query },
            { headers }
          );
          
          // Process vulnerabilities from GitHub response
          if (response.data.data?.securityVulnerabilities?.edges) {
            for (const edge of response.data.data.securityVulnerabilities.edges) {
              const vuln = edge.node;
              const advisory = vuln.advisory;
              
              // Check if the current version is vulnerable
              const vulnerableRange = vuln.vulnerableVersionRange;
              const isVulnerable = isVersionInRange(version, vulnerableRange);
              
              if (isVulnerable) {
                const fixedVersion = vuln.firstPatchedVersion?.identifier || 'No fix available';
                const cvss = mapSeverityToCVSS(advisory.severity);
                
                const vulnerability: SecurityVulnerability = {
                  id: `github-${name}-${advisory.id}`,
                  vulnerabilityId: advisory.id,
                  packageName: name,
                  packageVersion: version,
                  title: advisory.summary || `Security vulnerability in ${name}`,
                  description: advisory.description || 'No description available',
                  cvss,
                  fixedInVersion: fixedVersion,
                  path: filePath,
                  remediationSteps: buildGitHubRemediationSteps(name, fixedVersion, advisory),
                  references: advisory.references?.map((ref: any) => ref.url) || [],
                  severity: mapCVSSToSeverity(cvss),
                  detectedAt: new Date()
                };
                
                results.push(vulnerability);
              }
            }
          }
        } catch (packageError) {
          log.warn(`Error checking ${name}@${version} with GitHub Advisories`, { error: packageError });
        }
      }
    }
    
    return results;
  } catch (error) {
    log.error('Error checking vulnerabilities with GitHub Advisories', { error });
    return [];
  }
}

/**
 * Check if a version is in the vulnerable range
 */
function isVersionInRange(version: string, range: string): boolean {
  try {
    // GitHub uses ranges like "< 1.0.0" or ">= 1.0.0, < 2.0.0"
    // We need to convert these to semver ranges
    const semverRange = range
      .replace(/[\[\]()]/g, '')
      .split(',')
      .map(part => part.trim())
      .join(' ');
    
    return semver.satisfies(version, semverRange);
  } catch (error) {
    // If there's an error parsing the range, we'll assume it's vulnerable to be safe
    return true;
  }
}

/**
 * Build remediation steps for GitHub vulnerabilities
 */
function buildGitHubRemediationSteps(packageName: string, fixedVersion: string, advisory: any): string {
  const steps = [];
  
  steps.push(`Vulnerability: ${advisory.summary}`);
  
  if (fixedVersion && fixedVersion !== 'No fix available') {
    steps.push(`Update ${packageName} to version ${fixedVersion} or later.`);
    steps.push(`Run: npm update ${packageName} --depth=0`);
  } else {
    steps.push('No fixed version is available yet.');
    steps.push('Consider:');
    steps.push('1. Looking for alternative packages');
    steps.push('2. Implementing additional security controls');
    steps.push('3. Assessing if the vulnerability is exploitable in your context');
  }
  
  if (advisory.references && advisory.references.length > 0) {
    steps.push('');
    steps.push('References:');
    advisory.references.forEach((ref: any) => {
      if (ref.url) {
        steps.push(`- ${ref.url}`);
      }
    });
  }
  
  return steps.join('\n');
}
