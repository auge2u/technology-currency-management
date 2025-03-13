import path from 'path';
import { exec } from 'child_process';
import util from 'util';
import axios from 'axios';
import { log } from '../../utils/logging';
import config from '../../config';
import { SecurityVulnerability } from '../../types/scanning';
import { createScanResult, updateScanResult } from '../services/scan-result-service';
import { getRepositoryInfo } from '../services/repository-service';
import { notifySecurityVulnerabilities } from '../services/notification-service';

// Promisify exec for async/await usage
const execAsync = util.promisify(exec);

/**
 * Runs a security vulnerability scan
 */
export async function runSecurityVulnerabilityScan(repoPath?: string): Promise<SecurityVulnerability[]> {
  try {
    log.info('Starting security vulnerability scan', { repoPath });
    
    // Create a new scan result record
    const scanId = await createScanResult('security');
    
    // Get repository info if path is provided
    let repoInfo = null;
    if (repoPath) {
      repoInfo = await getRepositoryInfo(repoPath);
    }
    
    // Determine which security scanners to use based on config
    const vulnerabilities: SecurityVulnerability[] = [];
    
    // Run Snyk scan if enabled
    if (config.security.snyk.enabled) {
      const snykResults = await runSnykScan(repoPath || '.');
      vulnerabilities.push(...snykResults);
    }
    
    // Run OWASP Dependency-Check if enabled
    if (config.security.owaspDependencyCheck.enabled) {
      const owaspResults = await runOwaspDependencyCheck(repoPath || '.');
      vulnerabilities.push(...owaspResults);
    }
    
    // Run custom vulnerability checks
    const customResults = await runCustomVulnerabilityChecks(repoPath || '.');
    vulnerabilities.push(...customResults);
    
    // Check OSV database for known vulnerabilities
    const osvResults = await checkOSVDatabase(repoPath || '.');
    vulnerabilities.push(...osvResults);
    
    // Update scan result with findings
    await updateScanResult(scanId, {
      completedAt: new Date(),
      findings: vulnerabilities.length,
      scanStatus: 'completed',
      repository: repoInfo
    });
    
    // Send notifications if there are critical vulnerabilities
    const criticalVulnerabilities = vulnerabilities.filter(v => v.severity === 'critical');
    if (criticalVulnerabilities.length > 0) {
      await notifySecurityVulnerabilities(criticalVulnerabilities);
    }
    
    log.info(`Security vulnerability scan completed with ${vulnerabilities.length} findings`);
    return vulnerabilities;
    
  } catch (error) {
    log.error('Error during security vulnerability scan', { error });
    throw error;
  }
}

/**
 * Runs a Snyk security scan
 */
async function runSnykScan(repoPath: string): Promise<SecurityVulnerability[]> {
  try {
    if (!config.security.snyk.apiToken) {
      log.warn('Snyk API token not configured, skipping Snyk scan');
      return [];
    }
    
    log.info('Running Snyk security scan');
    
    // In a real implementation, you would either:
    // 1. Use Snyk CLI via execAsync
    // 2. Use Snyk API via HTTP requests
    // For this example, we'll simulate the results
    
    try {
      // Check if Snyk CLI is installed
      await execAsync('snyk --version');
      
      // Run Snyk test and output as JSON
      const { stdout } = await execAsync(`snyk test --json`, { 
        cwd: repoPath,
        env: { ...process.env, SNYK_TOKEN: config.security.snyk.apiToken }
      });
      
      // Parse the JSON output
      const snykResult = JSON.parse(stdout);
      
      // Convert Snyk results to our vulnerability format
      return snykResult.vulnerabilities?.map(vuln => ({
        id: vuln.id,
        title: vuln.title,
        description: vuln.description || 'No description provided',
        packageName: vuln.packageName,
        version: vuln.version,
        fixedIn: vuln.fixedIn,
        severity: mapSnykSeverity(vuln.severity),
        cve: vuln.identifiers?.CVE || [],
        references: vuln.references || [],
        remediationSteps: vuln.fixedIn ? `Update to version ${vuln.fixedIn} or later` : 'No fix available yet',
        detectedAt: new Date(),
        scanTool: 'snyk',
        affectedFiles: [],
        exploitAvailable: vuln.exploit !== 'Not Defined'
      })) || [];
      
    } catch (execError) {
      log.error('Error executing Snyk CLI', { error: execError });
      return [];
    }
  } catch (error) {
    log.error('Error running Snyk scan', { error });
    return [];
  }
}

/**
 * Maps Snyk severity to our severity format
 */
function mapSnykSeverity(severity: string): 'low' | 'medium' | 'high' | 'critical' {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
    default:
      return 'low';
  }
}

/**
 * Runs OWASP Dependency-Check
 */
async function runOwaspDependencyCheck(repoPath: string): Promise<SecurityVulnerability[]> {
  try {
    log.info('Running OWASP Dependency-Check');
    
    // In a real implementation, you would run the OWASP Dependency-Check tool
    // For this example, we'll simulate the results
    
    try {
      // Check if Dependency-Check is installed
      const dcPath = config.security.owaspDependencyCheck.path || 'dependency-check.sh';
      await execAsync(`${dcPath} --version`);
      
      // Run Dependency-Check and output as JSON
      const outputDir = path.join(repoPath, 'dependency-check-report');
      const { stdout } = await execAsync(
        `${dcPath} --project "Tech Currency Scan" --scan "${repoPath}" --out "${outputDir}" --format JSON`, 
        { cwd: repoPath }
      );
      
      // In a real implementation, you would parse the JSON output file
      // For this example, we'll return an empty array
      return [];
      
    } catch (execError) {
      log.error('Error executing OWASP Dependency-Check', { error: execError });
      return [];
    }
  } catch (error) {
    log.error('Error running OWASP Dependency-Check', { error });
    return [];
  }
}

/**
 * Runs custom vulnerability checks
 */
async function runCustomVulnerabilityChecks(repoPath: string): Promise<SecurityVulnerability[]> {
  // In a real implementation, this would run custom checks for vulnerabilities
  // For this example, we'll return an empty array
  return [];
}

/**
 * Checks the OSV database for known vulnerabilities
 * See: https://osv.dev/
 */
async function checkOSVDatabase(repoPath: string): Promise<SecurityVulnerability[]> {
  try {
    log.info('Checking OSV database for known vulnerabilities');
    
    // In a real implementation, you would:
    // 1. Identify packages and versions in the project
    // 2. Check the OSV API for each package
    // For this example, we'll simulate with a few hardcoded packages
    
    const testPackages = [
      { name: 'lodash', version: '4.17.15', ecosystem: 'npm' },
      { name: 'log4j-core', version: '2.14.1', ecosystem: 'Maven' }
    ];
    
    const vulnerabilities: SecurityVulnerability[] = [];
    
    for (const pkg of testPackages) {
      try {
        // Query OSV API
        const response = await axios.post('https://api.osv.dev/v1/query', {
          package: {
            name: pkg.name,
            ecosystem: pkg.ecosystem
          },
          version: pkg.version
        });
        
        if (response.data.vulns && response.data.vulns.length > 0) {
          // Process each vulnerability
          for (const vuln of response.data.vulns) {
            vulnerabilities.push({
              id: vuln.id,
              title: `${pkg.name}@${pkg.version} - ${vuln.summary || 'Vulnerability'}`,
              description: vuln.details || 'No details provided',
              packageName: pkg.name,
              version: pkg.version,
              fixedIn: vuln.affected?.[0]?.ranges?.[0]?.fixed || 'Unknown',
              severity: mapOSVSeverity(vuln.severity?.[0]?.type, vuln.severity?.[0]?.score),
              cve: vuln.aliases || [],
              references: vuln.references?.map(ref => ref.url) || [],
              remediationSteps: 'Update to the latest version',
              detectedAt: new Date(),
              scanTool: 'osv',
              affectedFiles: [],
              exploitAvailable: false // OSV doesn't provide this info directly
            });
          }
        }
      } catch (pkgError) {
        log.warn(`Error checking OSV for ${pkg.name}@${pkg.version}`, { error: pkgError });
      }
    }
    
    return vulnerabilities;
  } catch (error) {
    log.error('Error checking OSV database', { error });
    return [];
  }
}

/**
 * Maps OSV severity to our severity format
 */
function mapOSVSeverity(type?: string, score?: number): 'low' | 'medium' | 'high' | 'critical' {
  if (!type || !score) return 'medium';
  
  // For CVSS v3
  if (type === 'CVSS_V3') {
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    return 'low';
  }
  
  // For CVSS v2
  if (type === 'CVSS_V2') {
    if (score >= 8.0) return 'critical';
    if (score >= 6.0) return 'high';
    if (score >= 3.0) return 'medium';
    return 'low';
  }
  
  return 'medium';
}
