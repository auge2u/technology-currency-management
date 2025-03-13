import * as fs from 'fs';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { scanDependencies } from './dependency-scanner';
import { scanSecurityVulnerabilities } from './security-scanner';
import { scanTechnologyPatterns } from './technology-scanner';
import { scanBrowserExtensions } from './browser-extension-scanner';
import { log } from '../utils/logging';
import {
  ScanConfig,
  ScanResult,
  OutdatedTechnology,
  OutdatedDependency,
  SecurityVulnerability,
  BrowserExtensionIssue
} from '../types/scanning';
import { NotificationService } from '../services/notification-service';
import { ReportGenerator } from '../services/report-generator';

/**
 * Main scanner class that orchestrates all technology currency scans
 */
export class TechnologyCurrencyScanner {
  private config: ScanConfig;
  private notificationService: NotificationService;
  private reportGenerator: ReportGenerator;
  
  constructor(config: ScanConfig) {
    this.config = this.validateAndNormalizeConfig(config);
    this.notificationService = new NotificationService();
    this.reportGenerator = new ReportGenerator();
    
    log.info('Technology Currency Scanner initialized with config', { config: this.config });
  }
  
  /**
   * Run all configured scans and return combined results
   */
  public async runScan(): Promise<ScanResult> {
    const startTime = new Date();
    log.info('Starting technology currency scan');
    
    try {
      // Initialize results object
      const scanResult: ScanResult = {
        scanId: uuidv4(),
        startTime,
        endTime: new Date(), // Will be updated at the end
        config: this.config,
        technologies: [],
        dependencies: [],
        vulnerabilities: [],
        browserExtensions: [],
        totalIssues: 0,
        issuesBySeverity: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0
        },
        issuesByType: {
          technology: 0,
          dependency: 0,
          security: 0,
          browserExtension: 0
        }
      };
      
      // Run selected scans based on config
      if (this.config.scanTypes.includes('technology')) {
        log.info('Running technology pattern scan');
        scanResult.technologies = await scanTechnologyPatterns(this.config.rootDir);
        scanResult.issuesByType.technology = scanResult.technologies.length;
        log.info(`Found ${scanResult.technologies.length} outdated technology patterns`);
      }
      
      if (this.config.scanTypes.includes('dependency')) {
        log.info('Running dependency scan');
        scanResult.dependencies = await scanDependencies(this.config.rootDir);
        scanResult.issuesByType.dependency = scanResult.dependencies.length;
        log.info(`Found ${scanResult.dependencies.length} outdated dependencies`);
      }
      
      if (this.config.scanTypes.includes('security')) {
        log.info('Running security vulnerability scan');
        scanResult.vulnerabilities = await scanSecurityVulnerabilities(this.config.rootDir);
        scanResult.issuesByType.security = scanResult.vulnerabilities.length;
        log.info(`Found ${scanResult.vulnerabilities.length} security vulnerabilities`);
      }
      
      if (this.config.scanTypes.includes('browser-extension')) {
        log.info('Running browser extension scan');
        // Path to organization's browser extension inventory, if available
        const extensionInventoryPath = path.join(this.config.rootDir, 'extension-inventory.json');
        scanResult.browserExtensions = await scanBrowserExtensions(
          fs.existsSync(extensionInventoryPath) ? extensionInventoryPath : undefined
        );
        scanResult.issuesByType.browserExtension = scanResult.browserExtensions.length;
        log.info(`Found ${scanResult.browserExtensions.length} problematic browser extensions`);
      }
      
      // Count total issues and by severity
      this.calculateScanMetrics(scanResult);
      
      // Filter results based on minimum severity
      this.filterResultsBySeverity(scanResult);
      
      // Update scan end time
      scanResult.endTime = new Date();
      
      // Generate report and send notifications for critical issues
      await this.processResults(scanResult);
      
      log.info('Technology currency scan completed successfully', {
        scanId: scanResult.scanId,
        duration: scanResult.endTime.getTime() - scanResult.startTime.getTime(),
        totalIssues: scanResult.totalIssues
      });
      
      return scanResult;
      
    } catch (error) {
      log.error('Error during technology currency scan', { error });
      throw error;
    }
  }
  
  /**
   * Run scans and save results to a file
   */
  public async runAndSave(outputPath?: string): Promise<string> {
    const results = await this.runScan();
    
    // If no output path specified, create one based on date and scan ID
    const filePath = outputPath || path.join(
      this.config.rootDir,
      'scan-results',
      `scan-${results.scanId}-${this.formatDate(results.endTime)}.json`
    );
    
    // Ensure directory exists
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    // Write results to file
    fs.writeFileSync(filePath, JSON.stringify(results, null, 2));
    log.info(`Scan results saved to ${filePath}`);
    
    return filePath;
  }
  
  /**
   * Process scan results, generate reports and notifications
   */
  private async processResults(scanResult: ScanResult): Promise<void> {    
    // Generate comprehensive reports
    const reportPath = await this.reportGenerator.generateReport(scanResult);
    log.info(`Report generated at ${reportPath}`);
    
    // Send notifications about critical findings
    if (scanResult.issuesBySeverity.critical > 0) {
      await this.notificationService.sendCriticalAlert(scanResult);
    }
    
    if (scanResult.issuesBySeverity.high > 0) {
      await this.notificationService.sendHighPriorityAlert(scanResult);
    }
    
    if (scanResult.totalIssues > 0) {
      await this.notificationService.sendSummaryNotification(scanResult);
    }
  }
  
  /**
   * Calculate metrics from scan results
   */
  private calculateScanMetrics(scanResult: ScanResult): void {
    // Count issues by severity
    const countSeverity = (severity: 'critical' | 'high' | 'medium' | 'low', items: Array<{ severity: string }>): number => {
      return items.filter(item => item.severity === severity).length;
    };
    
    // Technologies
    scanResult.issuesBySeverity.critical += countSeverity('critical', scanResult.technologies);
    scanResult.issuesBySeverity.high += countSeverity('high', scanResult.technologies);
    scanResult.issuesBySeverity.medium += countSeverity('medium', scanResult.technologies);
    scanResult.issuesBySeverity.low += countSeverity('low', scanResult.technologies);
    
    // Dependencies
    scanResult.issuesBySeverity.critical += countSeverity('critical', scanResult.dependencies);
    scanResult.issuesBySeverity.high += countSeverity('high', scanResult.dependencies);
    scanResult.issuesBySeverity.medium += countSeverity('medium', scanResult.dependencies);
    scanResult.issuesBySeverity.low += countSeverity('low', scanResult.dependencies);
    
    // Security vulnerabilities
    scanResult.issuesBySeverity.critical += countSeverity('critical', scanResult.vulnerabilities);
    scanResult.issuesBySeverity.high += countSeverity('high', scanResult.vulnerabilities);
    scanResult.issuesBySeverity.medium += countSeverity('medium', scanResult.vulnerabilities);
    scanResult.issuesBySeverity.low += countSeverity('low', scanResult.vulnerabilities);
    
    // Browser extensions
    scanResult.issuesBySeverity.critical += countSeverity('critical', scanResult.browserExtensions);
    scanResult.issuesBySeverity.high += countSeverity('high', scanResult.browserExtensions);
    scanResult.issuesBySeverity.medium += countSeverity('medium', scanResult.browserExtensions);
    scanResult.issuesBySeverity.low += countSeverity('low', scanResult.browserExtensions);
    
    // Calculate total
    scanResult.totalIssues = 
      scanResult.technologies.length +
      scanResult.dependencies.length +
      scanResult.vulnerabilities.length +
      scanResult.browserExtensions.length;
  }
  
  /**
   * Filter results based on minimum severity level from config
   */
  private filterResultsBySeverity(scanResult: ScanResult): void {
    const severitiesToKeep = this.getSeveritiesToKeep(this.config.minSeverity);
    
    scanResult.technologies = scanResult.technologies
      .filter(item => severitiesToKeep.includes(item.severity));
      
    scanResult.dependencies = scanResult.dependencies
      .filter(item => severitiesToKeep.includes(item.severity));
      
    scanResult.vulnerabilities = scanResult.vulnerabilities
      .filter(item => severitiesToKeep.includes(item.severity));
      
    scanResult.browserExtensions = scanResult.browserExtensions
      .filter(item => severitiesToKeep.includes(item.severity));
      
    // Recalculate metrics after filtering
    scanResult.issuesBySeverity = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    };
    
    scanResult.issuesByType = {
      technology: scanResult.technologies.length,
      dependency: scanResult.dependencies.length,
      security: scanResult.vulnerabilities.length,
      browserExtension: scanResult.browserExtensions.length
    };
    
    this.calculateScanMetrics(scanResult);
  }
  
  /**
   * Get array of severities to keep based on minimum severity
   */
  private getSeveritiesToKeep(minSeverity: 'low' | 'medium' | 'high' | 'critical'): Array<string> {
    const allSeverities = ['critical', 'high', 'medium', 'low'];
    const minIndex = allSeverities.indexOf(minSeverity);
    return allSeverities.slice(0, minIndex + 1);
  }
  
  /**
   * Format date as YYYY-MM-DD
   */
  private formatDate(date: Date): string {
    return date.toISOString().split('T')[0];
  }
  
  /**
   * Validate and set default values for scan configuration
   */
  private validateAndNormalizeConfig(config: ScanConfig): ScanConfig {
    // Check for required fields
    if (!config.rootDir) {
      throw new Error('Root directory is required in scan configuration');
    }
    
    // Normalize paths
    const rootDir = path.resolve(config.rootDir);
    
    // Set defaults for optional fields
    return {
      rootDir,
      includeNodeModules: config.includeNodeModules ?? false,
      includeDevDependencies: config.includeDevDependencies ?? true,
      maxDepth: config.maxDepth || Infinity,
      includePatterns: config.includePatterns || ['*'],
      excludePatterns: config.excludePatterns || ['**/node_modules/**', '**/dist/**', '**/build/**', '**/.git/**'],
      minSeverity: config.minSeverity || 'low',
      scanTypes: config.scanTypes || ['technology', 'dependency', 'security', 'browser-extension']
    };
  }
}

/**
 * Create a scanner with default configuration
 */
export function createDefaultScanner(rootDir: string): TechnologyCurrencyScanner {
  const defaultConfig: ScanConfig = {
    rootDir,
    includeNodeModules: false,
    includeDevDependencies: true,
    includePatterns: ['*'],
    excludePatterns: ['**/node_modules/**', '**/dist/**', '**/build/**', '**/.git/**'],
    minSeverity: 'low',
    scanTypes: ['technology', 'dependency', 'security', 'browser-extension']
  };
  
  return new TechnologyCurrencyScanner(defaultConfig);
}
