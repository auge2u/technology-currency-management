import path from 'path';
import fs from 'fs/promises';
import { glob } from 'glob';
import { log } from '../../utils/logging';
import config from '../../config';
import { TechnologyRule } from '../rules/technology-rules';
import { loadAllTechnologyRules } from '../rules/rule-loader';
import { OutdatedTechnology } from '../../types/scanning';
import { createScanResult, updateScanResult } from '../services/scan-result-service';
import { getRepositoryInfo } from '../services/repository-service';
import { notifyOutdatedTechnologies } from '../services/notification-service';

// Languages and frameworks to check for
interface LanguageDetector {
  name: string;
  filePatterns: string[];
  configFiles: string[];
  detectionFn?: (filePath: string, content: string) => Promise<boolean>;
}

/**
 * Detects languages and frameworks in a codebase
 */
const languageDetectors: LanguageDetector[] = [
  {
    name: 'JavaScript',
    filePatterns: ['**/*.js', '**/*.jsx', '**/*.mjs'],
    configFiles: ['package.json', '.eslintrc*', 'webpack.config.js', 'babel.config.js']
  },
  {
    name: 'TypeScript',
    filePatterns: ['**/*.ts', '**/*.tsx'],
    configFiles: ['tsconfig.json', 'tslint.json']
  },
  {
    name: 'Python',
    filePatterns: ['**/*.py'],
    configFiles: ['requirements.txt', 'setup.py', 'pyproject.toml', 'Pipfile']
  },
  {
    name: 'Java',
    filePatterns: ['**/*.java', '**/*.kt'],
    configFiles: ['pom.xml', 'build.gradle', 'build.gradle.kts', 'settings.gradle']
  },
  {
    name: 'Ruby',
    filePatterns: ['**/*.rb'],
    configFiles: ['Gemfile', '.ruby-version', 'config/application.rb']
  },
  {
    name: 'PHP',
    filePatterns: ['**/*.php'],
    configFiles: ['composer.json', 'composer.lock']
  },
  {
    name: 'Go',
    filePatterns: ['**/*.go'],
    configFiles: ['go.mod', 'go.sum']
  },
  {
    name: 'C#',
    filePatterns: ['**/*.cs'],
    configFiles: ['*.csproj', '*.sln', 'packages.config']
  },
  {
    name: 'C++',
    filePatterns: ['**/*.cpp', '**/*.cc', '**/*.h', '**/*.hpp'],
    configFiles: ['CMakeLists.txt', 'Makefile']
  },
  {
    name: 'Rust',
    filePatterns: ['**/*.rs'],
    configFiles: ['Cargo.toml', 'Cargo.lock']
  },
  // Frameworks
  {
    name: 'React',
    filePatterns: ['**/*.jsx', '**/*.tsx'],
    configFiles: [],
    detectionFn: async (filePath, content) => {
      return content.includes('import React') || content.includes('from \'react\'');
    }
  },
  {
    name: 'Angular',
    filePatterns: ['**/*.ts'],
    configFiles: ['angular.json'],
    detectionFn: async (filePath, content) => {
      return content.includes('@angular/core') || content.includes('@Component');
    }
  },
  {
    name: 'Vue',
    filePatterns: ['**/*.vue'],
    configFiles: ['vue.config.js'],
  },
  {
    name: 'Django',
    filePatterns: ['**/*.py'],
    configFiles: ['manage.py', 'settings.py'],
    detectionFn: async (filePath, content) => {
      return content.includes('django.') || content.includes('from django');
    }
  },
  {
    name: 'Spring',
    filePatterns: ['**/*.java'],
    configFiles: [],
    detectionFn: async (filePath, content) => {
      return content.includes('org.springframework') || content.includes('@SpringBootApplication');
    }
  },
];

/**
 * Runs a full scan of the codebase to detect outdated technologies
 */
export async function runCodebaseScan(repoPath?: string): Promise<OutdatedTechnology[]> {
  try {
    log.info('Starting codebase scan', { repoPath });
    
    // Create a new scan result record
    const scanId = await createScanResult('codebase');
    
    // Load all technology rules
    const rules = await loadAllTechnologyRules();
    log.debug(`Loaded ${rules.length} technology rules`);
    
    // Get repository info if path is provided
    let repoInfo = null;
    if (repoPath) {
      repoInfo = await getRepositoryInfo(repoPath);
    }
    
    // Detect technologies used in the codebase
    const detectedTechnologies = await detectTechnologies(repoPath || '.');
    log.info(`Detected technologies: ${detectedTechnologies.join(', ')}`);
    
    // Get rules for the detected technologies
    const relevantRules = rules.filter(rule => 
      detectedTechnologies.includes(rule.technology) || rule.technology === 'All'
    );
    
    // Scan the codebase with the relevant rules
    const outdatedTechnologies = await scanWithRules(repoPath || '.', relevantRules);
    
    // Update scan result with findings
    await updateScanResult(scanId, {
      completedAt: new Date(),
      findings: outdatedTechnologies.length,
      detectedTechnologies,
      scanStatus: 'completed',
      repository: repoInfo
    });
    
    // Send notifications if there are findings
    if (outdatedTechnologies.length > 0) {
      await notifyOutdatedTechnologies(outdatedTechnologies, 'codebase');
    }
    
    log.info(`Codebase scan completed with ${outdatedTechnologies.length} findings`);
    return outdatedTechnologies;
    
  } catch (error) {
    log.error('Error during codebase scan', { error });
    throw error;
  }
}

/**
 * Detects technologies used in a codebase
 */
async function detectTechnologies(repoPath: string): Promise<string[]> {
  const detectedTechnologies = new Set<string>();
  
  for (const detector of languageDetectors) {
    try {
      // Check for config files first (faster)
      for (const configFile of detector.configFiles) {
        const configPaths = await glob(path.join(repoPath, '**', configFile), { nodir: true });
        if (configPaths.length > 0) {
          detectedTechnologies.add(detector.name);
          break;
        }
      }
      
      // If not found by config, check file patterns
      if (!detectedTechnologies.has(detector.name)) {
        for (const pattern of detector.filePatterns) {
          const filePaths = await glob(path.join(repoPath, pattern), { nodir: true });
          
          if (filePaths.length > 0) {
            // If there's a detection function, use it for additional verification
            if (detector.detectionFn) {
              for (const filePath of filePaths.slice(0, 5)) { // Check up to 5 files
                const content = await fs.readFile(filePath, 'utf-8');
                const isDetected = await detector.detectionFn(filePath, content);
                if (isDetected) {
                  detectedTechnologies.add(detector.name);
                  break;
                }
              }
            } else {
              detectedTechnologies.add(detector.name);
              break;
            }
          }
        }
      }
    } catch (error) {
      log.warn(`Error detecting ${detector.name}`, { error });
    }
  }
  
  return Array.from(detectedTechnologies);
}

/**
 * Scans codebase with the provided rules
 */
async function scanWithRules(repoPath: string, rules: TechnologyRule[]): Promise<OutdatedTechnology[]> {
  const findings: OutdatedTechnology[] = [];
  
  for (const rule of rules) {
    try {
      log.debug(`Applying rule: ${rule.name}`);
      
      // Get files to scan based on rule's file patterns
      const filesToScan = await glob(path.join(repoPath, rule.filePattern || '**/*'), { nodir: true });
      
      // Apply content matcher if defined
      if (rule.contentPattern) {
        const regex = new RegExp(rule.contentPattern, 'g');
        
        for (const filePath of filesToScan) {
          try {
            const content = await fs.readFile(filePath, 'utf-8');
            const matches = content.match(regex);
            
            if (matches) {
              findings.push({
                technology: rule.technology,
                currentVersion: matches[0],
                recommendedVersion: rule.recommendedVersion,
                severity: rule.severity,
                filePath: path.relative(repoPath, filePath),
                lineNumber: getLineNumber(content, matches[0]),
                message: rule.message,
                ruleId: rule.id,
                remediationSteps: rule.remediationSteps,
                detectedAt: new Date(),
                type: 'codebase'
              });
            }
          } catch (fileError) {
            log.warn(`Error scanning file ${filePath}`, { error: fileError });
          }
        }
      }
      
      // Apply file name matcher if defined
      if (rule.fileNamePattern) {
        const regex = new RegExp(rule.fileNamePattern);
        
        for (const filePath of filesToScan) {
          if (regex.test(filePath)) {
            findings.push({
              technology: rule.technology,
              currentVersion: path.basename(filePath),
              recommendedVersion: rule.recommendedVersion,
              severity: rule.severity,
              filePath: path.relative(repoPath, filePath),
              message: rule.message,
              ruleId: rule.id,
              remediationSteps: rule.remediationSteps,
              detectedAt: new Date(),
              type: 'codebase'
            });
          }
        }
      }
      
    } catch (ruleError) {
      log.error(`Error applying rule ${rule.name}`, { error: ruleError });
    }
  }
  
  return findings;
}

/**
 * Gets the line number of a match in a string
 */
function getLineNumber(content: string, match: string): number {
  const index = content.indexOf(match);
  if (index === -1) return 0;
  
  return content.substring(0, index).split('\n').length;
}
