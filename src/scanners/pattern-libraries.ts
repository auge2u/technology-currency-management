import { DeprecationPattern } from '../types/scanning';

/**
 * Get language-specific deprecated patterns
 */
export function getLanguagePatterns(language: string): DeprecationPattern[] {
  switch (language) {
    case 'javascript':
    case 'typescript':
      return getJavaScriptPatterns();
    case 'python':
      return getPythonPatterns();
    case 'java':
      return getJavaPatterns();
    case 'csharp':
      return getCSharpPatterns();
    case 'php':
      return getPhpPatterns();
    case 'ruby':
      return getRubyPatterns();
    case 'go':
      return getGoPatterns();
    default:
      return [];
  }
}

/**
 * Get framework-specific deprecated patterns
 */
export function getFrameworkPatterns(framework: string): DeprecationPattern[] {
  switch (framework) {
    case 'react':
      return getReactPatterns();
    case 'angular':
      return getAngularPatterns();
    case 'vue':
      return getVuePatterns();
    case 'jquery':
      return getJQueryPatterns();
    case 'dotnet':
      return getDotNetPatterns();
    case 'django':
      return getDjangoPatterns();
    case 'flask':
      return getFlaskPatterns();
    case 'laravel':
      return getLaravelPatterns();
    case 'spring':
      return getSpringPatterns();
    default:
      return [];
  }
}

/**
 * JavaScript/TypeScript deprecated patterns
 */
function getJavaScriptPatterns(): DeprecationPattern[] {
  return [
    {
      id: 'js-var-keyword',
      technology: 'javascript',
      message: 'Use of deprecated "var" keyword',
      description: 'The "var" keyword is deprecated in favor of "let" and "const" which have block scoping and help avoid common issues with hoisting.',
      remediation: 'Replace "var" with "let" for variables that change, or "const" for variables that don\'t change after assignment.',
      documentationUrl: 'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/let',
      regex: '\\bvar\\s+[a-zA-Z_$][\\w$]*',
      severity: 'medium',
      fileTypes: ['js', 'jsx', 'ts', 'tsx']
    },
    {
      id: 'js-document-write',
      technology: 'javascript',
      message: 'Use of deprecated document.write()',
      description: 'document.write() is considered a bad practice as it can overwrite the entire document, doesn\'t work in XHTML, and has poor performance.',
      remediation: 'Use modern DOM methods like document.createElement() and appendChild(), or innerHTML for simple cases.',
      documentationUrl: 'https://developer.mozilla.org/en-US/docs/Web/API/Document/write',
      regex: '\\bdocument\\.write\\s*\\(',
      severity: 'high',
      fileTypes: ['js', 'jsx', 'ts', 'tsx']
    },
    {
      id: 'js-sync-xhr',
      technology: 'javascript',
      message: 'Use of synchronous XMLHttpRequest',
      description: 'Synchronous XMLHttpRequest is deprecated because it freezes the page and creates a poor user experience.',
      remediation: 'Use asynchronous XMLHttpRequest or preferably fetch() API or axios.',
      documentationUrl: 'https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/Synchronous_and_Asynchronous_Requests',
      regex: 'new\\s+XMLHttpRequest\\([^)]*\\).*\\.open\\([^)]*false[^)]*\\)',
      severity: 'high',
      fileTypes: ['js', 'jsx', 'ts', 'tsx']
    },
    {
      id: 'js-eval',
      technology: 'javascript',
      message: 'Use of eval() function',
      description: 'eval() executes arbitrary code with the caller\'s privileges, creating security vulnerabilities. It also runs slower than alternatives.',
      remediation: 'Refactor to avoid eval(). Use safer alternatives like JSON.parse() for JSON data.',
      documentationUrl: 'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval',
      regex: '\\beval\\s*\\(',
      severity: 'critical',
      fileTypes: ['js', 'jsx', 'ts', 'tsx']
    },
    {
      id: 'node-crypto-createcipher',
      technology: 'node.js',
      message: 'Use of insecure crypto.createCipher',
      description: 'crypto.createCipher and crypto.createDecipher are deprecated because they use a weak key derivation function. They will be removed in a future Node.js version.',
      remediation: 'Use crypto.createCipheriv and crypto.createDecipheriv instead, which allow specifying the initialization vector.',
      documentationUrl: 'https://nodejs.org/api/crypto.html#crypto_crypto_createcipher_algorithm_password_options',
      regex: '(?:crypto|require\\(["\']crypto["\']\\))\\s*\\.\\s*createCipher\\s*\\(',
      severity: 'critical',
      fileTypes: ['js', 'ts']
    },
    {
      id: 'node-new-buffer',
      technology: 'node.js',
      message: 'Use of deprecated Buffer constructor',
      description: 'The Buffer() constructor is deprecated due to security and usability concerns.',
      remediation: 'Use Buffer.alloc(), Buffer.from(), or Buffer.allocUnsafe() instead.',
      documentationUrl: 'https://nodejs.org/api/buffer.html#buffer_buffer',
      regex: 'new\\s+Buffer\\s*\\(',
      severity: 'high',
      fileTypes: ['js', 'ts']
    }
  ];
}

/**
 * Python deprecated patterns
 */
function getPythonPatterns(): DeprecationPattern[] {
  return [
    {
      id: 'python-print-statement',
      technology: 'python',
      message: 'Use of print statement instead of print function',
      description: 'The print statement was removed in Python 3. Use the print() function instead.',
      remediation: 'Convert print statements to print() function calls.',
      documentationUrl: 'https://docs.python.org/3/whatsnew/3.0.html#print-is-a-function',
      regex: '^\\s*print\\s+[^(]',
      severity: 'medium',
      fileTypes: ['py']
    },
    {
      id: 'python-deprecated-modules',
      technology: 'python',
      message: 'Use of deprecated Python module',
      description: 'This module has been deprecated and may be removed in future Python versions.',
      remediation: 'Use the recommended alternative module.',
      documentationUrl: 'https://docs.python.org/3/library/index.html',
      regex: '\\bimport\\s+(imp|commands|dl|formatter|fpformat|md5|sha|optparse|sets|mimetools|mimetypes|mimewriter|mimify|multifile|MimeWriter|rfc822|SimpleHTTPServer|StringIO|cookielib|importlib\\.machinery)\\b|\\bfrom\\s+(imp|commands|dl|formatter|fpformat|md5|sha|optparse|sets|mimetools|mimetypes|mimewriter|mimify|multifile|MimeWriter|rfc822|SimpleHTTPServer|StringIO|cookielib|importlib\\.machinery)\\s+import',
      severity: 'medium',
      fileTypes: ['py']
    },
    {
      id: 'python-urllib2',
      technology: 'python',
      message: 'Use of deprecated urllib2 module',
      description: 'The urllib2 module has been split into parts and reorganized in Python 3.',
      remediation: 'Use urllib.request, urllib.error, and urllib.parse instead.',
      documentationUrl: 'https://docs.python.org/3/library/urllib.request.html',
      regex: '\\bimport\\s+urllib2\\b|\\bfrom\\s+urllib2\\s+import',
      severity: 'medium',
      fileTypes: ['py']
    },
    {
      id: 'python-xrange',
      technology: 'python',
      message: 'Use of deprecated xrange() function',
      description: 'xrange() has been removed in Python 3. range() now behaves like xrange() used to.',
      remediation: 'Use range() instead of xrange().',
      documentationUrl: 'https://docs.python.org/3/whatsnew/3.0.html#integers',
      regex: '\\bxrange\\s*\\(',
      severity: 'medium',
      fileTypes: ['py']
    }
  ];
}

/**
 * Java deprecated patterns
 */
function getJavaPatterns(): DeprecationPattern[] {
  return [
    {
      id: 'java-date-constructor',
      technology: 'java',
      message: 'Use of deprecated Date constructor',
      description: 'Most java.util.Date constructors have been deprecated in favor of Calendar or newer java.time API.',
      remediation: 'Use java.time classes (LocalDate, LocalDateTime, ZonedDateTime) from Java 8+.',
      documentationUrl: 'https://docs.oracle.com/javase/8/docs/api/java/time/package-summary.html',
      regex: 'new\\s+Date\\s*\\(\\s*([0-9]+|["\'].+["\'])\\s*\\)',
      severity: 'medium',
      fileTypes: ['java']
    },
    {
      id: 'java-vector',
      technology: 'java',
      message: 'Use of Vector class',
      description: 'Vector is considered legacy. While not deprecated, ArrayList is generally preferred.',
      remediation: 'Use ArrayList or other modern collection classes. If synchronization is needed, use Collections.synchronizedList().',
      documentationUrl: 'https://docs.oracle.com/javase/8/docs/api/java/util/ArrayList.html',
      regex: '(\\bnew\\s+Vector\\s*<|\\bVector\\s+[a-zA-Z_$][\\w$]*|<Vector\\s*<|,\\s*Vector\\s*<)',
      severity: 'low',
      fileTypes: ['java']
    },
    {
      id: 'java-thread-stop',
      technology: 'java',
      message: 'Use of deprecated Thread.stop() method',
      description: 'Thread.stop() is deprecated because it is inherently unsafe and can lead to data corruption.',
      remediation: 'Use thread interruption and cooperative cancellation techniques.',
      documentationUrl: 'https://docs.oracle.com/javase/8/docs/technotes/guides/concurrency/threadPrimitiveDeprecation.html',
      regex: '\\.[a-zA-Z_$][\\w$]*\\s*\\.\\s*stop\\s*\\(\\s*\\)',
      severity: 'high',
      fileTypes: ['java']
    }
  ];
}

/**
 * C# deprecated patterns
 */
function getCSharpPatterns(): DeprecationPattern[] {
  return [
    {
      id: 'csharp-webforms',
      technology: 'csharp',
      message: 'Use of ASP.NET Web Forms',
      description: 'ASP.NET Web Forms is a legacy technology. Microsoft recommends using ASP.NET Core for new development.',
      remediation: 'Migrate to ASP.NET Core MVC or Razor Pages for better performance, cross-platform support, and modern development practices.',
      documentationUrl: 'https://docs.microsoft.com/en-us/aspnet/core/',
      regex: '<%@\\s+Page|<asp:|runat="server"',
      severity: 'medium',
      fileTypes: ['aspx', 'ascx']
    },
    {
      id: 'csharp-wcf',
      technology: 'csharp',
      message: 'Use of WCF (Windows Communication Foundation)',
      description: 'WCF is not available in .NET Core/.NET 5+ and is primarily a Windows-only technology now.',
      remediation: 'Consider migrating to gRPC, ASP.NET Core Web APIs, or other modern cross-platform communication mechanisms.',
      documentationUrl: 'https://docs.microsoft.com/en-us/dotnet/core/porting/windows-compat/wcf-updates',
      regex: 'using\\s+System\\.ServiceModel|\\[ServiceContract\\]|\\[OperationContract\\]',
      severity: 'medium',
      fileTypes: ['cs']
    }
  ];
}

/**
 * PHP deprecated patterns
 */
function getPhpPatterns(): DeprecationPattern[] {
  return [
    {
      id: 'php-mysql-extension',
      technology: 'php',
      message: 'Use of deprecated mysql_ functions',
      description: 'The mysql_ extension is deprecated and has been removed from PHP 7+. It has known security issues.',
      remediation: 'Use mysqli_ or PDO for database access.',
      documentationUrl: 'https://www.php.net/manual/en/intro.mysql.php',
      regex: '\\bmysql_[a-zA-Z_]+\\s*\\(',
      severity: 'critical',
      fileTypes: ['php']
    },
    {
      id: 'php-short-tags',
      technology: 'php',
      message: 'Use of PHP short tags',
      description: 'Short open tags are deprecated and may be disabled by default in some PHP configurations.',
      remediation: 'Use <?php rather than <? to open PHP blocks.',
      documentationUrl: 'https://www.php.net/manual/en/language.basic-syntax.phptags.php',
      regex: '<\\?(?!php|=|xml)',
      severity: 'medium',
      fileTypes: ['php']
    }
  ];
}

/**
 * Ruby deprecated patterns
 */
function getRubyPatterns(): DeprecationPattern[] {
  return [
    {
      id: 'ruby-safe-level',
      technology: 'ruby',
      message: 'Use of deprecated $SAFE feature',
      description: 'The $SAFE feature has been deprecated in Ruby 2.6 and removed in Ruby 3.0.',
      remediation: 'Remove usage of $SAFE and use more robust security mechanisms.',
      documentationUrl: 'https://www.ruby-lang.org/en/news/2019/12/12/separation-of-positional-and-keyword-arguments-in-ruby-3-0/',
      regex: '\\$SAFE\\s*=',
      severity: 'medium',
      fileTypes: ['rb']
    }
  ];
}

/**
 * Go deprecated patterns
 */
function getGoPatterns(): DeprecationPattern[] {
  return [
    {
      id: 'go-ioutil',
      technology: 'go',
      message: 'Use of deprecated ioutil package',
      description: 'The ioutil package is deprecated as of Go 1.16. Its functions have been moved to io or os packages.',
      remediation: 'Use equivalent functions from io and os packages.',
      documentationUrl: 'https://golang.org/doc/go1.16#ioutil',
      regex: '\\bioutil\\.',
      severity: 'medium',
      fileTypes: ['go']
    }
  ];
}

/**
 * React deprecated patterns
 */
function getReactPatterns(): DeprecationPattern[] {
  return [
    {
      id: 'react-component-will-mount',
      technology: 'react',
      message: 'Use of deprecated componentWillMount lifecycle method',
      description: 'componentWillMount has been deprecated since React 16.3 and will be removed in a future release.',
      remediation: 'Use componentDidMount instead or use hooks with useEffect.',
      documentationUrl: 'https://reactjs.org/docs/react-component.html#unsafe_componentwillmount',
      regex: '\\bcomponentWillMount\\s*\\(|\\bUNSAFE_componentWillMount\\s*\\(',
      severity: 'medium',
      fileTypes: ['js', 'jsx', 'ts', 'tsx']
    },
    {
      id: 'react-component-will-receive-props',
      technology: 'react',
      message: 'Use of deprecated componentWillReceiveProps lifecycle method',
      description: 'componentWillReceiveProps has been deprecated since React 16.3 and will be removed in a future release.',
      remediation: 'Use static getDerivedStateFromProps or componentDidUpdate instead, or use hooks with useEffect.',
      documentationUrl: 'https://reactjs.org/docs/react-component.html#unsafe_componentwillreceiveprops',
      regex: '\\bcomponentWillReceiveProps\\s*\\(|\\bUNSAFE_componentWillReceiveProps\\s*\\(',
      severity: 'medium',
      fileTypes: ['js', 'jsx', 'ts', 'tsx']
    }
  ];
}

/**
 * Angular deprecated patterns
 */
function getAngularPatterns(): DeprecationPattern[] {
  return [
    {
      id: 'angular-http',
      technology: 'angular',
      message: 'Use of deprecated HttpModule',
      description: 'The HttpModule and @angular/http have been deprecated since Angular 5 in favor of HttpClientModule.',
      remediation: 'Use HttpClientModule and services from @angular/common/http instead.',
      documentationUrl: 'https://angular.io/guide/http',
      regex: 'import\\s+[^;]*\\bHttpModule\\b|import\\s+[^;]*from\\s+["\']@angular\\/http["\']',
      severity: 'medium',
      fileTypes: ['ts']
    }
  ];
}

/**
 * Vue deprecated patterns
 */
function getVuePatterns(): DeprecationPattern[] {
  return [
    {
      id: 'vue-filters',
      technology: 'vue',
      message: 'Use of filters in Vue 3',
      description: 'Filters have been removed in Vue 3 and are no longer supported.',
      remediation: 'Use computed properties or methods instead of filters.',
      documentationUrl: 'https://v3.vuejs.org/guide/migration/filters.html',
      regex: '\\|\\s*[a-zA-Z][a-zA-Z0-9_]*\\s*(?:\\([^)]*\\))?',
      severity: 'medium',
      fileTypes: ['vue']
    }
  ];
}

/**
 * jQuery deprecated patterns
 */
function getJQueryPatterns(): DeprecationPattern[] {
  return [
    {
      id: 'jquery-size',
      technology: 'jquery',
      message: 'Use of deprecated .size() method',
      description: 'The .size() method has been deprecated since jQuery 1.8 and removed in jQuery 3.0.',
      remediation: 'Use .length property instead.',
      documentationUrl: 'https://api.jquery.com/size/',
      regex: '\\$\\([^)]*\\)\\.size\\(\\)|\\$\\.[^\\.(]*\\.size\\(\\)|jQuery\\([^)]*\\)\\.size\\(\\)',
      severity: 'medium',
      fileTypes: ['js', 'html']
    }
  ];
}

/**
 * .NET deprecated patterns
 */
function getDotNetPatterns(): DeprecationPattern[] {
  return [
    {
      id: 'dotnet-obsolete',
      technology: 'dotnet',
      message: 'Use of obsolete APIs marked with [Obsolete] attribute',
      description: 'The code is using APIs marked with the [Obsolete] attribute, which indicates they should no longer be used.',
      remediation: 'Replace with the recommended alternative mentioned in the attribute message.',
      documentationUrl: 'https://docs.microsoft.com/en-us/dotnet/api/system.obsoleteattribute',
      regex: '\\[Obsolete(Attribute)?\\]',
      severity: 'medium',
      fileTypes: ['cs']
    }
  ];
}

/**
 * Django deprecated patterns
 */
function getDjangoPatterns(): DeprecationPattern[] {
  return [
    {
      id: 'django-urls-import-path',
      technology: 'django',
      message: 'Use of deprecated url() function in URLconf',
      description: 'django.conf.urls.url() is deprecated since Django 2.0. Use django.urls.path() instead.',
      remediation: 'Use path() or re_path() from django.urls instead.',
      documentationUrl: 'https://docs.djangoproject.com/en/stable/ref/urls/',
      regex: 'from\\s+django\\.conf\\.urls\\s+import\\s+url|url\\(',
      severity: 'medium',
      fileTypes: ['py']
    }
  ];
}

/**
 * Flask deprecated patterns
 */
function getFlaskPatterns(): DeprecationPattern[] {
  return [
    {
      id: 'flask-ext-import',
      technology: 'flask',
      message: 'Use of deprecated flask.ext imports',
      description: 'The flask.ext namespace is deprecated since Flask 0.11.',
      remediation: 'Import Flask extensions directly from their own packages.',
      documentationUrl: 'https://flask.palletsprojects.com/en/2.0.x/extensiondev/',
      regex: 'from\\s+flask\\.ext\\.',
      severity: 'medium',
      fileTypes: ['py']
    }
  ];
}

/**
 * Laravel deprecated patterns
 */
function getLaravelPatterns(): DeprecationPattern[] {
  return [
    {
      id: 'laravel-old-helpers',
      technology: 'laravel',
      message: 'Use of deprecated Laravel helper functions',
      description: 'Several global helper functions have been deprecated in Laravel 5.8+ and moved to separate packages.',
      remediation: 'Use the recommended replacements or add the laravel/helpers package.',
      documentationUrl: 'https://laravel.com/docs/5.8/upgrade#update-helper-functions',
      regex: '\\b(array_add|array_collapse|array_divide|array_dot|array_except|array_first|array_last|array_only|array_prepend|array_pull|array_random|array_set|array_sort|array_sort_recursive|array_where|camel_case|ends_with|snake_case|str_limit|str_contains|str_finish|str_is|str_plural|str_random|str_singular|str_slug|starts_with|studly_case)\\s*\\(',
      severity: 'medium',
      fileTypes: ['php']
    }
  ];
}

/**
 * Spring deprecated patterns
 */
function getSpringPatterns(): DeprecationPattern[] {
  return [
    {
      id: 'spring-web-request-mapping',
      technology: 'spring',
      message: 'Use of generic @RequestMapping',
      description: 'Using @RequestMapping without an HTTP method is deprecated in favor of method-specific annotations.',
      remediation: 'Use @GetMapping, @PostMapping, @PutMapping, @DeleteMapping, etc. to make the HTTP method explicit.',
      documentationUrl: 'https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/bind/annotation/package-summary.html',
      regex: '@RequestMapping\\s*\\([^)]*\\)(?!\\s*class)',
      exclusionRegex: 'method\\s*=',  // Exclude if method is specified
      severity: 'low',
      fileTypes: ['java']
    }
  ];
}
