import * as fs from 'fs';
import * as path from 'path';
import glob from 'glob';
import { CodePatternIssue, DeprecationPattern } from '../types/scanning';
import { getLanguagePatterns, getFrameworkPatterns } from './pattern-libraries';
import { isBinaryFile, filterBySeverity } from '../utils/scanner-utils';
import { log } from '../utils/logging';

/**
 * Configuration for code pattern scanning
 */
export interface CodePatternScannerConfig {
  // Source code directories to scan
  directories: string[];
  
  // File patterns to include (glob patterns)
  filePatterns: string[];
  
  // File patterns to exclude (glob patterns)
  excludePatterns: string[];
  
  // Custom patterns to check for
  customPatterns?: DeprecationPattern[];
  
  // Whether to check for deprecated language features
  checkDeprecatedLanguageFeatures: boolean;
  
  // Whether to check for deprecated framework patterns
  checkDeprecatedFrameworkPatterns: boolean;
  
  // Frameworks to check
  frameworks: Array<'react' | 'angular' | 'vue' | 'jquery' | 'dotnet' | 'django' | 'flask' | 'laravel' | 'spring'>;
  
  // Language-specific checks
  languages: Array<'javascript' | 'typescript' | 'python' | 'java' | 'csharp' | 'php' | 'ruby' | 'go'>;
  
  // Severity threshold (only report issues at or above this severity)
  severityThreshold: 'low' | 'medium' | 'high' | 'critical';
  
  // Max files to scan (0 for unlimited)
  maxFiles: number;
  
  // Whether to use AST-based scanning for JavaScript/TypeScript
  useAstScanning: boolean;
  
  // Maximum file size to scan in KB (0 for unlimited)
  maxFileSizeKb: number;
}

/**
 * Scan code for deprecated patterns
 */
export async function scanCodePatterns(
  config: CodePatternScannerConfig
): Promise<CodePatternIssue[]> {
  try {
    log.info('Starting code pattern scanner');
    
    // Get all relevant files
    const filesToScan = await getFilesToScan(config);
    log.info(`Found ${filesToScan.length} files to scan`);
    
    // Apply max files limit if configured
    const limitedFiles = config.maxFiles > 0 ? filesToScan.slice(0, config.maxFiles) : filesToScan;
    
    // Get all patterns to check for
    const patterns = getAllPatterns(config);
    log.info(`Checking for ${patterns.length} deprecated patterns`);
    
    // Scan each file
    const issues: CodePatternIssue[] = [];
    
    for (const file of limitedFiles) {
      try {
        log.debug(`Scanning ${file}`);
        
        // Check file size if configured
        if (config.maxFileSizeKb > 0) {
          const stats = fs.statSync(file);
          const fileSizeKb = stats.size / 1024;
          if (fileSizeKb > config.maxFileSizeKb) {
            log.debug(`Skipping ${file} - exceeds max file size (${fileSizeKb.toFixed(2)} KB)`);
            continue;
          }
        }
        
        const fileContent = fs.readFileSync(file, 'utf8');
        
        // Skip binary files
        if (isBinaryFile(fileContent)) {
          log.debug(`Skipping binary file ${file}`);
          continue;
        }
        
        const fileIssues = scanFile(file, fileContent, patterns, config);
        issues.push(...fileIssues);
      } catch (fileError) {
        log.warn(`Error scanning file ${file}`, { error: fileError });
      }
    }
    
    // Filter by severity threshold
    const filteredIssues = filterBySeverity(issues, config.severityThreshold);
    
    log.info(`Completed code pattern scanning. Found ${filteredIssues.length} issues`);
    return filteredIssues;
  } catch (error) {
    log.error('Error during code pattern scanning', { error });
    return [];
  }
}

/**
 * Get files to scan based on configuration
 */
async function getFilesToScan(config: CodePatternScannerConfig): Promise<string[]> {
  const allFiles: string[] = [];
  
  for (const dir of config.directories) {
    if (!fs.existsSync(dir)) {
      log.warn(`Directory not found: ${dir}`);
      continue;
    }
    
    for (const pattern of config.filePatterns) {
      const globPattern = path.join(dir, pattern);
      const files = glob.sync(globPattern, { ignore: config.excludePatterns });
      allFiles.push(...files);
    }
  }
  
  return [...new Set(allFiles)]; // Remove duplicates
}

/**
 * Get all patterns to check for based on configuration
 */
function getAllPatterns(config: CodePatternScannerConfig): DeprecationPattern[] {
  const patterns: DeprecationPattern[] = [];
  
  // Add custom patterns if defined
  if (config.customPatterns && config.customPatterns.length > 0) {
    patterns.push(...config.customPatterns);
  }
  
  // Add language-specific patterns
  if (config.checkDeprecatedLanguageFeatures) {
    for (const language of config.languages) {
      patterns.push(...getLanguagePatterns(language));
    }
  }
  
  // Add framework-specific patterns
  if (config.checkDeprecatedFrameworkPatterns) {
    for (const framework of config.frameworks) {
      patterns.push(...getFrameworkPatterns(framework));
    }
  }
  
  return patterns;
}

/**
 * Scan an individual file for deprecated patterns
 */
function scanFile(
  filePath: string, 
  content: string, 
  patterns: DeprecationPattern[], 
  config: CodePatternScannerConfig
): CodePatternIssue[] {
  const issues: CodePatternIssue[] = [];
  const extension = path.extname(filePath).toLowerCase();
  
  // For each pattern, check if it applies to this file type and scan for it
  for (const pattern of patterns) {
    if (pattern.fileTypes.some(type => type === '*' || extension === `.${type}`)) {
      const patternIssues = scanForPattern(filePath, content, pattern);
      issues.push(...patternIssues);
    }
  }
  
  // For JavaScript/TypeScript files, also do AST-based scanning if enabled
  if (config.useAstScanning && (
    extension === '.js' || 
    extension === '.jsx' || 
    extension === '.ts' || 
    extension === '.tsx'
  )) {
    try {
      // AST scanning is handled by a separate module to keep this file manageable
      const { scanJavaScriptAST } = require('./javascript-ast-scanner');
      const astIssues = scanJavaScriptAST(filePath, content, patterns);
      issues.push(...astIssues);
    } catch (astError) {
      log.warn(`Error during AST scanning of ${filePath}`, { error: astError });
    }
  }
  
  return issues;
}

/**
 * Scan for a specific pattern in a file
 */
function scanForPattern(filePath: string, content: string, pattern: DeprecationPattern): CodePatternIssue[] {
  const issues: CodePatternIssue[] = [];
  
  if (pattern.regex) {
    const regex = new RegExp(pattern.regex, 'g');
    const lines = content.split('\n');
    
    let lineNumber = 1;
    for (const line of lines) {
      let match: RegExpExecArray | null;
      
      while ((match = regex.exec(line)) !== null) {
        // Check exclusion regex if it exists
        if (pattern.exclusionRegex && new RegExp(pattern.exclusionRegex).test(line)) {
          continue;
        }
        
        const issue: CodePatternIssue = {
          id: `${pattern.id}-${filePath.replace(/[^a-zA-Z0-9]/g, '-')}-${lineNumber}`,
          patternId: pattern.id,
          file: filePath,
          line: lineNumber,
          column: match.index !== undefined ? match.index + 1 : 0,
          snippet: line.trim(),
          match: match[0],
          message: pattern.message,
          description: pattern.description,
          remediation: pattern.remediation,
          documentationUrl: pattern.documentationUrl,
          severity: pattern.severity,
          technology: pattern.technology,
          detectedAt: new Date()
        };
        
        issues.push(issue);
      }
      
      lineNumber++;
    }
  }
  
  return issues;
}
