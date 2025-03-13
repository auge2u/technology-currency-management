import { exec } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { log } from '../utils/logging';
import { OutdatedTechnology } from '../types/scanning';

const execAsync = promisify(exec);

/**
 * Scanner for detecting outdated technology patterns in the codebase
 */
export async function scanTechnologyPatterns(rootDir: string): Promise<OutdatedTechnology[]> {
  try {
    log.info('Starting technology pattern scanning');
    
    const results: OutdatedTechnology[] = [];
    
    // Scan for different technology categories
    const jsResults = await scanJavaScriptPatterns(rootDir);
    const cssResults = await scanCssPatterns(rootDir);
    const htmlResults = await scanHtmlPatterns(rootDir);
    const pythonResults = await scanPythonPatterns(rootDir);
    const javaResults = await scanJavaPatterns(rootDir);
    const dotnetResults = await scanDotnetPatterns(rootDir);
    const frameworkResults = await scanFrameworkPatterns(rootDir);
    
    results.push(
      ...jsResults,
      ...cssResults,
      ...htmlResults,
      ...pythonResults,
      ...javaResults,
      ...dotnetResults,
      ...frameworkResults
    );
    
    log.info(`Technology pattern scanning completed. Found ${results.length} outdated technology patterns`);
    
    return results;
  } catch (error) {
    log.error('Error during technology pattern scanning', { error });
    return [];
  }
}

/**
 * Scan for outdated JavaScript patterns
 */
async function scanJavaScriptPatterns(rootDir: string): Promise<OutdatedTechnology[]> {
  try {
    // Find JavaScript and TypeScript files
    const { stdout } = await execAsync(`find ${rootDir} -type f \( -name "*.js" -o -name "*.jsx" -o -name "*.ts" -o -name "*.tsx" \) -not -path "*/node_modules/*" -not -path "*/dist/*" -not -path "*/build/*"`);
    const jsFiles = stdout.trim().split('\n').filter(Boolean);
    
    const results: OutdatedTechnology[] = [];
    
    const patterns = [
      {
        name: 'document.write',
        regex: /document\.write\s*\(/g,
        severity: 'high' as const,
        message: 'document.write() is considered harmful and deprecated. It can cause performance issues and is blocked in some contexts.',
        recommended: 'Use DOM manipulation methods like document.createElement or modern frameworks instead.',
        ruleId: 'js-doc-write'
      },
      {
        name: 'var keyword',
        regex: /\bvar\s+[\w$]/g,
        severity: 'low' as const,
        message: 'The var keyword is outdated. It lacks block scoping and can lead to unexpected behavior.',
        recommended: 'Use let or const instead of var for variable declarations.',
        ruleId: 'js-var-keyword'
      },
      {
        name: 'jQuery',
        regex: /(?:jQuery|\$)\s*\(/g,
        severity: 'medium' as const,
        message: 'jQuery is largely unnecessary in modern web development with the advancements in native browser APIs.',
        recommended: 'Use native DOM APIs or modern frameworks instead of jQuery.',
        ruleId: 'js-jquery'
      },
      {
        name: 'Internet Explorer Conditional Comments',
        regex: /\@cc_on|\@if\s*\(/g,
        severity: 'high' as const,
        message: 'IE conditional comments are no longer supported as Internet Explorer is deprecated.',
        recommended: 'Use feature detection or modern polyfills instead of targeting specific browsers.',
        ruleId: 'js-ie-conditionals'
      },
      {
        name: 'Synchronous XMLHttpRequest',
        regex: /\.open\s*\(\s*['"]GET['"].*[,\s]false\s*\)/g,
        severity: 'high' as const,
        message: 'Synchronous XMLHttpRequest is deprecated and harmful to user experience.',
        recommended: 'Use asynchronous requests with Promises, async/await, or the Fetch API.',
        ruleId: 'js-sync-xhr'
      },
      {
        name: 'setTimeout with string argument',
        regex: /setTimeout\s*\(\s*['"][^'"]+['"]/g,
        severity: 'high' as const,
        message: 'Using setTimeout with a string argument is similar to eval() and is considered harmful.',
        recommended: 'Pass a function reference to setTimeout instead of a string.',
        ruleId: 'js-settimeout-string'
      },
      {
        name: 'Older React Component Patterns',
        regex: /React\.createClass\s*\(/g,
        severity: 'medium' as const,
        message: 'React.createClass is deprecated in modern React.',
        recommended: 'Use ES6 classes or function components with hooks instead.',
        ruleId: 'react-create-class'
      },
      {
        name: 'componentWillMount/componentWillReceiveProps',
        regex: /componentWill(?:Mount|ReceiveProps|Update)\s*\(/g,
        severity: 'medium' as const,
        message: 'These React lifecycle methods are deprecated and will be removed in a future version.',
        recommended: 'Use componentDidMount, getDerivedStateFromProps, or useEffect hook instead.',
        ruleId: 'react-legacy-lifecycle'
      },
      {
        name: 'PropTypes in React Package',
        regex: /React\.PropTypes|from\s+['"]react['"].*PropTypes/g,
        severity: 'low' as const,
        message: 'PropTypes were moved to a separate package in React 15.5.',
        recommended: 'Import PropTypes from the prop-types package instead.',
        ruleId: 'react-proptypes-package'
      },
      {
        name: 'AngularJS (Angular 1.x)',
        regex: /angular\.module\s*\(/g,
        severity: 'medium' as const,
        message: 'AngularJS (Angular 1.x) is deprecated and will eventually reach end-of-life.',
        recommended: 'Migrate to Angular (2+) or another modern framework.',
        ruleId: 'angularjs-usage'
      },
      {
        name: 'CoffeeScript',
        regex: /\#\s*=\s*require|\->/g,
        severity: 'medium' as const,
        message: 'CoffeeScript has declined in popularity and may lead to maintenance issues.',
        recommended: 'Use modern JavaScript or TypeScript instead.',
        ruleId: 'coffeescript-usage'
      },
      {
        name: 'Mixins in JavaScript',
        regex: /\b(?:mixin|mixins)\s*[=:]|\bmixins\s*\:/g,
        severity: 'medium' as const,
        message: 'Mixins are considered an outdated pattern in modern JavaScript development.',
        recommended: 'Use composition, higher-order components, or hooks instead of mixins.',
        ruleId: 'js-mixins'
      },
      {
        name: 'Backbone.js',
        regex: /Backbone\.[A-Z][\w]+\.extend\(/g,
        severity: 'medium' as const, 
        message: 'Backbone.js is less actively maintained and has been superseded by modern frameworks.',
        recommended: 'Consider migrating to React, Vue, Angular, or another modern framework.',
        ruleId: 'backbone-usage'
      }
    ];
    
    for (const filePath of jsFiles) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n');
        
        for (const pattern of patterns) {
          let match;
          const contentWithLineNumbers = lines.map((line, i) => ({ line, num: i + 1 }));
          
          for (const { line, num } of contentWithLineNumbers) {
            pattern.regex.lastIndex = 0;
            if (pattern.regex.test(line)) {
              results.push({
                id: `${pattern.ruleId}-${path.basename(filePath)}-${num}`,
                technology: pattern.name,
                filePath,
                lineNumber: num,
                lineContent: line.trim(),
                severity: pattern.severity,
                message: pattern.message,
                recommendedVersion: 'N/A',
                remediationSteps: pattern.recommended,
                ruleId: pattern.ruleId,
                detectedAt: new Date()
              });
            }
          }
        }
      } catch (fileError) {
        log.warn(`Error processing JavaScript file ${filePath}`, { error: fileError });
      }
    }
    
    return results;
  } catch (error) {
    log.error('Error scanning JavaScript patterns', { error });
    return [];
  }
}

/**
 * Scan for outdated CSS patterns
 */
async function scanCssPatterns(rootDir: string): Promise<OutdatedTechnology[]> {
  try {
    // Find CSS files
    const { stdout } = await execAsync(`find ${rootDir} -type f \( -name "*.css" -o -name "*.scss" -o -name "*.less" \) -not -path "*/node_modules/*" -not -path "*/dist/*" -not -path "*/build/*"`);
    const cssFiles = stdout.trim().split('\n').filter(Boolean);
    
    const results: OutdatedTechnology[] = [];
    
    const patterns = [
      {
        name: 'IE-specific filters',
        regex: /filter:\s*progid:DXImageTransform\.Microsoft|\-ms\-filter|zoom:\s*1/g,
        severity: 'high' as const,
        message: 'Internet Explorer specific filters and hacks are outdated as IE is now deprecated.',
        recommended: 'Use standard CSS features with modern browser support.',
        ruleId: 'css-ie-filters'
      },
      {
        name: 'Vendor prefixes',
        regex: /\-webkit\-|\-moz\-|\-ms\-|\-o\-/g,
        severity: 'low' as const,
        message: 'Manual vendor prefixes may be unnecessary with modern browsers or when using tools like Autoprefixer.',
        recommended: 'Use a tool like Autoprefixer or PostCSS to automatically manage vendor prefixes.',
        ruleId: 'css-vendor-prefixes'
      },
      {
        name: 'Float-based layouts',
        regex: /float:\s*(?:left|right)|clear:\s*(?:left|right|both)/g,
        severity: 'medium' as const,
        message: 'Float-based layouts are an outdated approach to page layout.',
        recommended: 'Use Flexbox or CSS Grid for layout instead of floats.',
        ruleId: 'css-float-layouts'
      },
      {
        name: 'Old CSS hacks',
        regex: /\*html|\*\+html|\*:first-child\+html|html>body/g,
        severity: 'high' as const,
        message: 'Old CSS hacks for targeting specific browsers are outdated and unnecessary.',
        recommended: 'Use feature detection with @supports or modernize your approach.',
        ruleId: 'css-browser-hacks'
      },
      {
        name: '!important overuse',
        regex: /!important/g,
        severity: 'medium' as const,
        message: 'Overuse of !important is considered bad practice and can lead to CSS maintenance issues.',
        recommended: 'Improve CSS specificity instead of relying on !important.',
        ruleId: 'css-important-overuse'
      },
      {
        name: 'Obsolete HTML5 Shiv',
        regex: /html5shiv|html5\.js/g,
        severity: 'high' as const,
        message: 'HTML5 Shiv is no longer necessary as HTML5 is supported by all modern browsers.',
        recommended: 'Remove HTML5 Shiv and related polyfills if not supporting very old browsers.',
        ruleId: 'html5-shiv'
      }
    ];
    
    for (const filePath of cssFiles) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n');
        
        for (const pattern of patterns) {
          let match;
          const contentWithLineNumbers = lines.map((line, i) => ({ line, num: i + 1 }));
          
          for (const { line, num } of contentWithLineNumbers) {
            pattern.regex.lastIndex = 0;
            if (pattern.regex.test(line)) {
              results.push({
                id: `${pattern.ruleId}-${path.basename(filePath)}-${num}`,
                technology: pattern.name,
                filePath,
                lineNumber: num,
                lineContent: line.trim(),
                severity: pattern.severity,
                message: pattern.message,
                recommendedVersion: 'N/A',
                remediationSteps: pattern.recommended,
                ruleId: pattern.ruleId,
                detectedAt: new Date()
              });
            }
          }
        }
      } catch (fileError) {
        log.warn(`Error processing CSS file ${filePath}`, { error: fileError });
      }
    }
    
    return results;
  } catch (error) {
    log.error('Error scanning CSS patterns', { error });
    return [];
  }
}

/**
 * Scan for outdated HTML patterns
 */
async function scanHtmlPatterns(rootDir: string): Promise<OutdatedTechnology[]> {
  try {
    // Find HTML files
    const { stdout } = await execAsync(`find ${rootDir} -type f \( -name "*.html" -o -name "*.htm" -o -name "*.xhtml" \) -not -path "*/node_modules/*" -not -path "*/dist/*" -not -path "*/build/*"`);
    const htmlFiles = stdout.trim().split('\n').filter(Boolean);
    
    const results: OutdatedTechnology[] = [];
    
    const patterns = [
      {
        name: 'XHTML DOCTYPE',
        regex: /<!DOCTYPE[^>]*XHTML/i,
        severity: 'medium' as const,
        message: 'XHTML DOCTYPEs are outdated in the HTML5 era.',
        recommended: 'Use the HTML5 DOCTYPE: <!DOCTYPE html>',
        ruleId: 'html-xhtml-doctype'
      },
      {
        name: 'HTML4 DOCTYPE',
        regex: /<!DOCTYPE[^>]*HTML 4/i,
        severity: 'medium' as const,
        message: 'HTML4 DOCTYPEs are outdated in the HTML5 era.',
        recommended: 'Use the HTML5 DOCTYPE: <!DOCTYPE html>',
        ruleId: 'html-html4-doctype'
      },
      {
        name: 'Deprecated HTML tags',
        regex: /<\s*(?:font|center|strike|frameset|frame|applet|marquee|basefont|big|tt|acronym|blink)\b[^>]*>/i,
        severity: 'high' as const,
        message: 'This HTML tag is deprecated or obsolete in modern HTML standards.',
        recommended: 'Use CSS for styling instead of deprecated HTML tags.',
        ruleId: 'html-deprecated-tags'
      },
      {
        name: 'Deprecated HTML attributes',
        regex: /\s(?:bgcolor|border|cellpadding|cellspacing|align|valign|width|height)\s*=/i,
        severity: 'medium' as const,
        message: 'These HTML attributes are deprecated in favor of using CSS.',
        recommended: 'Move presentation attributes to CSS stylesheets.',
        ruleId: 'html-deprecated-attrs'
      },
      {
        name: 'Internet Explorer conditional comments',
        regex: /<!\-\-\[if\s+[^\]]+\]>|<\!\[endif\]\-\->/i,
        severity: 'high' as const,
        message: 'IE conditional comments are obsolete as Internet Explorer is deprecated.',
        recommended: 'Remove IE-specific code and use feature detection if needed.',
        ruleId: 'html-ie-comments'
      },
      {
        name: 'Table-based layouts',
        regex: /<table[^>]*class\s*=\s*["'][^"']*(?:layout|grid)["']/i,
        severity: 'high' as const,
        message: 'Table-based layouts are an outdated approach to page structure.',
        recommended: 'Use CSS Grid, Flexbox, or other modern layout techniques.',
        ruleId: 'html-table-layout'
      }
    ];
    
    for (const filePath of htmlFiles) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n');
        
        for (const pattern of patterns) {
          let match;
          const contentWithLineNumbers = lines.map((line, i) => ({ line, num: i + 1 }));
          
          for (const { line, num } of contentWithLineNumbers) {
            pattern.regex.lastIndex = 0;
            if (pattern.regex.test(line)) {
              results.push({
                id: `${pattern.ruleId}-${path.basename(filePath)}-${num}`,
                technology: pattern.name,
                filePath,
                lineNumber: num,
                lineContent: line.trim(),
                severity: pattern.severity,
                message: pattern.message,
                recommendedVersion: 'N/A',
                remediationSteps: pattern.recommended,
                ruleId: pattern.ruleId,
                detectedAt: new Date()
              });
            }
          }
        }
      } catch (fileError) {
        log.warn(`Error processing HTML file ${filePath}`, { error: fileError });
      }
    }
    
    return results;
  } catch (error) {
    log.error('Error scanning HTML patterns', { error });
    return [];
  }
}

/**
 * Scan for outdated Python patterns
 */
async function scanPythonPatterns(rootDir: string): Promise<OutdatedTechnology[]> {
  try {
    // Find Python files
    const { stdout } = await execAsync(`find ${rootDir} -type f -name "*.py" -not -path "*/venv/*" -not -path "*/.env/*"`);
    const pythonFiles = stdout.trim().split('\n').filter(Boolean);
    
    const results: OutdatedTechnology[] = [];
    
    const patterns = [
      {
        name: 'Python 2.x print statement',
        regex: /^\s*print\s+[^(]/,
        severity: 'high' as const,
        message: 'Python 2.x style print statements are outdated. Python 2 reached end-of-life in 2020.',
        recommended: 'Use Python 3.x print function: print()',
        ruleId: 'py-print-statement'
      },
      {
        name: 'Python 2.x exception handling',
        regex: /except\s+\w+\s*,\s*\w+:/,
        severity: 'high' as const,
        message: 'Python 2.x style exception handling with comma is outdated.',
        recommended: 'Use Python 3.x exception handling: except ExceptionType as var:',
        ruleId: 'py-except-comma'
      },
      {
        name: 'deprecated modules',
        regex: /import\s+(?:sets|fpformat|md5|sha|new|thread|commands|compiler|{0,1}httplib|urllib2|urlparse|collections\.MutableMapping)/,
        severity: 'high' as const,
        message: 'Usage of deprecated Python modules.',
        recommended: 'Use modern equivalents: sets -> set, md5/sha -> hashlib, thread -> threading, etc.',
        ruleId: 'py-deprecated-modules'
      },
      {
        name: 'Deprecated Django functionality',
        regex: /from\s+django\.conf\.urls\s+import\s+patterns/,
        severity: 'high' as const,
        message: 'The django.conf.urls.patterns function is deprecated.',
        recommended: 'Use a list of django.urls.re_path() or path() instances instead.',
        ruleId: 'django-deprecated-patterns'
      },
      {
        name: 'File-like object .next() method',
        regex: /\.[a-zA-Z0-9_]+\.next\(\)/,
        severity: 'medium' as const,
        message: 'The .next() method for iterators is outdated.',
        recommended: 'Use the built-in next() function instead.',
        ruleId: 'py-iterator-next'
      },
      {
        name: 'exec statement',
        regex: /^\s*exec\s+[^(]/,
        severity: 'medium' as const,
        message: 'The exec statement syntax is outdated.',
        recommended: 'Use the exec() function instead.',
        ruleId: 'py-exec-statement'
      }
    ];
    
    for (const filePath of pythonFiles) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n');
        
        for (const pattern of patterns) {
          let match;
          const contentWithLineNumbers = lines.map((line, i) => ({ line, num: i + 1 }));
          
          for (const { line, num } of contentWithLineNumbers) {
            pattern.regex.lastIndex = 0;
            if (pattern.regex.test(line)) {
              results.push({
                id: `${pattern.ruleId}-${path.basename(filePath)}-${num}`,
                technology: pattern.name,
                filePath,
                lineNumber: num,
                lineContent: line.trim(),
                severity: pattern.severity,
                message: pattern.message,
                recommendedVersion: 'N/A',
                remediationSteps: pattern.recommended,
                ruleId: pattern.ruleId,
                detectedAt: new Date()
              });
            }
          }
        }
      } catch (fileError) {
        log.warn(`Error processing Python file ${filePath}`, { error: fileError });
      }
    }
    
    return results;
  } catch (error) {
    log.error('Error scanning Python patterns', { error });
    return [];
  }
}

/**
 * Scan for outdated Java patterns
 */
async function scanJavaPatterns(rootDir: string): Promise<OutdatedTechnology[]> {
  // Implementation similar to other language scanners
  return [];
}

/**
 * Scan for outdated .NET patterns
 */
async function scanDotnetPatterns(rootDir: string): Promise<OutdatedTechnology[]> {
  // Implementation similar to other language scanners
  return [];
}

/**
 * Scan for outdated framework patterns
 */
async function scanFrameworkPatterns(rootDir: string): Promise<OutdatedTechnology[]> {
  // Implementation would scan for outdated framework usage
  return [];
}
