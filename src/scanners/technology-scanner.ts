import { exec } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { log } from '../utils/logging';
import { OutdatedTechnology } from '../types/scanning';

const execAsync = promisify(exec);

interface TechnologyRule {
  id: string;
  name: string;
  pattern: RegExp;
  filePattern: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  recommendation: string;
  documentationUrl?: string;
  recommendedVersion?: string;
}

/**
 * Scans for outdated technologies and patterns in the codebase
 */
export async function scanTechnologies(rootDir: string): Promise<OutdatedTechnology[]> {
  try {
    log.info('Starting technology scanning');
    
    const results: OutdatedTechnology[] = [];
    
    // Get the rule sets for different technologies
    const rules = [
      ...getJavaScriptRules(),
      ...getTypeScriptRules(),
      ...getReactRules(),
      ...getPythonRules(),
      ...getDockerRules()
    ];
    
    // Process each rule set
    for (const rule of rules) {
      try {
        log.debug(`Processing rule: ${rule.id} - ${rule.name}`);
        
        // Find files matching the pattern
        const files = await findFiles(rootDir, rule.filePattern);
        
        // For each file, search for pattern matches
        for (const file of files) {
          try {
            // Skip node_modules or vendor directories
            if (
              file.includes('node_modules') || 
              file.includes('/vendor/') ||
              file.includes('/dist/') ||
              file.includes('/build/')
            ) {
              continue;
            }
            
            const content = fs.readFileSync(file, 'utf8');
            const lines = content.split('\n');
            
            for (let i = 0; i < lines.length; i++) {
              const line = lines[i];
              
              if (rule.pattern.test(line)) {
                // Get some context around the match
                const context = getLineContext(lines, i);
                
                results.push({
                  id: `${rule.id}-${path.basename(file)}-${i}`,
                  technology: rule.name,
                  filePath: file,
                  lineNumber: i + 1,
                  lineContent: line.trim(),
                  severity: rule.severity,
                  message: rule.message,
                  recommendedVersion: rule.recommendedVersion || 'latest',
                  remediationSteps: rule.recommendation,
                  ruleId: rule.id,
                  detectedAt: new Date()
                });
              }
            }
          } catch (fileError) {
            log.warn(`Error processing file ${file} with rule ${rule.id}`, { error: fileError });
          }
        }
      } catch (ruleError) {
        log.warn(`Error processing rule ${rule.id}`, { error: ruleError });
      }
    }
    
    log.info(`Technology scanning completed. Found ${results.length} outdated technology usages`);
    
    return results;
  } catch (error) {
    log.error('Error during technology scanning', { error });
    return [];
  }
}

/**
 * Get line context around the matched line
 */
function getLineContext(lines: string[], lineIndex: number, contextSize = 2): string {
  const start = Math.max(0, lineIndex - contextSize);
  const end = Math.min(lines.length - 1, lineIndex + contextSize);
  
  return lines.slice(start, end + 1).join('\n');
}

/**
 * JavaScript rules for outdated patterns and APIs
 */
function getJavaScriptRules(): TechnologyRule[] {
  return [
    {
      id: 'js-var',
      name: 'JavaScript var declarations',
      pattern: /\bvar\s+[A-Za-z_$]/,
      filePattern: '*.js',
      severity: 'medium',
      message: 'Use of var is outdated and can lead to scoping issues',
      recommendation: 'Replace var with let or const for better variable scoping',
      documentationUrl: 'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/let'
    },
    {
      id: 'js-document-write',
      name: 'document.write()',
      pattern: /document\.write\s*\(/,
      filePattern: '*.js',
      severity: 'medium',
      message: 'document.write() is considered a poor practice and can be problematic',
      recommendation: 'Use DOM manipulation methods like appendChild() or insertAdjacentHTML()'
    },
    {
      id: 'js-xmlhttprequest',
      name: 'XMLHttpRequest',
      pattern: /\bnew\s+XMLHttpRequest\s*\(/,
      filePattern: '*.js',
      severity: 'low',
      message: 'XMLHttpRequest is older API for AJAX requests',
      recommendation: 'Use the Fetch API or axios for HTTP requests',
      documentationUrl: 'https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API'
    },
    {
      id: 'js-eval',
      name: 'eval() usage',
      pattern: /\beval\s*\(/,
      filePattern: '*.js',
      severity: 'critical',
      message: 'Using eval() is a security risk and reduces performance',
      recommendation: 'Avoid eval() and use safer alternatives like JSON.parse() for JSON data'
    },
    {
      id: 'js-old-node-buffer',
      name: 'Old Node.js Buffer',
      pattern: /new\s+Buffer\s*\(/,
      filePattern: '*.js',
      severity: 'high',
      message: 'new Buffer() constructor is deprecated due to security and usability concerns',
      recommendation: 'Use Buffer.from(), Buffer.alloc(), or Buffer.allocUnsafe() instead',
      documentationUrl: 'https://nodejs.org/api/buffer.html#buffer_buffer_from_buffer_alloc_and_buffer_allocunsafe'
    }
  ];
}

/**
 * TypeScript rules for outdated patterns and APIs
 */
function getTypeScriptRules(): TechnologyRule[] {
  return [
    {
      id: 'ts-any',
      name: 'TypeScript any type',
      pattern: /: any[\s,)]/,
      filePattern: '*.ts',
      severity: 'low',
      message: 'Excessive use of the any type defeats the purpose of using TypeScript',
      recommendation: 'Use more specific types, unknown, or generics instead of any'
    },
    {
      id: 'ts-namespace',
      name: 'TypeScript namespace',
      pattern: /\bnamespace\s+[A-Za-z_$]/,
      filePattern: '*.ts',
      severity: 'medium',
      message: 'TypeScript namespaces are being phased out in favor of ES modules',
      recommendation: 'Use ES modules (import/export) instead of namespaces'
    },
    {
      id: 'ts-old-compiler-options',
      name: 'Old TypeScript compiler options',
      pattern: /"target":\s*"(ES3|ES5|ES2015|ES2016|ES2017)"/,
      filePattern: 'tsconfig.json',
      severity: 'medium',
      message: 'Using outdated TypeScript compiler target',
      recommendation: 'Use ES2018 or newer as the TypeScript compiler target',
      recommendedVersion: 'ES2020'
    }
  ];
}

/**
 * React rules for outdated patterns and APIs
 */
function getReactRules(): TechnologyRule[] {
  return [
    {
      id: 'react-unsafe-lifecycle',
      name: 'React unsafe lifecycle methods',
      pattern: /\b(componentWillMount|componentWillReceiveProps|componentWillUpdate)\b/,
      filePattern: '*.jsx',
      severity: 'high',
      message: 'Using deprecated unsafe React lifecycle methods',
      recommendation: 'Use getDerivedStateFromProps, componentDidUpdate, or useEffect hook instead'
    },
    {
      id: 'react-finddomnode',
      name: 'React findDOMNode',
      pattern: /\bfindDOMNode\s*\(/,
      filePattern: '*.jsx',
      severity: 'high',
      message: 'findDOMNode is deprecated and will be removed in a future version of React',
      recommendation: 'Use refs with callback refs or useRef hook instead'
    },
    {
      id: 'react-string-refs',
      name: 'React string refs',
      pattern: /ref=['"]\w+['"]/,
      filePattern: '*.jsx',
      severity: 'high',
      message: 'String refs are deprecated and will be removed in a future version of React',
      recommendation: 'Use callback refs or createRef instead'
    }
  ];
}

/**
 * Python rules for outdated patterns and APIs
 */
function getPythonRules(): TechnologyRule[] {
  return [
    {
      id: 'python-2-print',
      name: 'Python 2 print statement',
      pattern: /\bprint\s+(?!\()/,
      filePattern: '*.py',
      severity: 'high',
      message: 'Using Python 2 print statement instead of print function',
      recommendation: 'Use print() function syntax for Python 3 compatibility',
      recommendedVersion: '3.0.0'
    },
    {
      id: 'python-2-except',
      name: 'Python 2 except syntax',
      pattern: /\bexcept\s+\w+\s*,\s*\w+\s*:/,
      filePattern: '*.py',
      severity: 'high',
      message: 'Using Python 2 except ExceptionType, var syntax',
      recommendation: 'Use except ExceptionType as var syntax for Python 3 compatibility',
      recommendedVersion: '3.0.0'
    },
    {
      id: 'python-insecure-pickle',
      name: 'Insecure pickle usage',
      pattern: /\bpickle\.loads\s*\(/,
      filePattern: '*.py',
      severity: 'high',
      message: 'Using pickle.loads() with potentially untrusted data can lead to remote code execution',
      recommendation: 'Use safer alternatives like JSON for external data or ensure data is trusted'
    }
  ];
}

/**
 * Docker rules for outdated patterns and APIs
 */
function getDockerRules(): TechnologyRule[] {
  return [
    {
      id: 'docker-add-command',
      name: 'ADD instead of COPY',
      pattern: /\bADD\s+/,
      filePattern: 'Dockerfile',
      severity: 'low',
      message: 'Using ADD instead of COPY',
      recommendation: 'Use COPY for simple file copying as it is more predictable than ADD'
    },
    {
      id: 'docker-latest-tag',
      name: 'Using latest tag',
      pattern: /\bFROM\s+\w+:latest/,
      filePattern: 'Dockerfile',
      severity: 'medium',
      message: 'Using latest tag for base image',
      recommendation: 'Use specific version tags for base images to ensure reproducibility'
    }
  ];
}

/**
 * Find files with a specific pattern recursively
 */
async function findFiles(rootDir: string, pattern: string): Promise<string[]> {
  try {
    const extension = pattern.replace('*.', '');
    const { stdout } = await execAsync(`find ${rootDir} -name "*.${extension}" -type f`);
    return stdout.trim().split('\n').filter(Boolean);
  } catch (error) {
    log.error(`Error finding files matching pattern ${pattern}`, { error });
    return [];
  }
}
