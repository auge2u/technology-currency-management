import { OutdatedTechnologySeverity } from '../../types/scanning';

/**
 * Represents a rule for detecting outdated technologies
 */
export interface TechnologyRule {
  id: string;
  name: string;
  description: string;
  technology: string;
  filePattern?: string;
  fileNamePattern?: string;
  contentPattern?: string;
  severity: OutdatedTechnologySeverity;
  message: string;
  recommendedVersion: string;
  remediationSteps: string;
  examples?: string[];
  reference?: string;
  enabled: boolean;
  tags?: string[];
}

/**
 * Predefined technology rules for common outdated technologies
 */
export const defaultTechnologyRules: TechnologyRule[] = [
  // JavaScript/Node.js
  {
    id: 'node-old-version',
    name: 'Node.js Old Version',
    description: 'Detects usage of outdated Node.js versions',
    technology: 'Node.js',
    filePattern: '{package.json,.nvmrc,.node-version}',
    contentPattern: '"node":\s*"([0-9]|10|11|12|13|14|15)\\.[0-9]+\\.[0-9]+"',
    severity: 'high',
    message: 'Using an outdated Node.js version which may have security vulnerabilities',
    recommendedVersion: '16.x LTS or later',
    remediationSteps: 'Update to Node.js 16.x LTS or later in package.json. Consider using a .nvmrc file to manage Node.js versions.',
    examples: ['"node": "12.16.1"'],
    reference: 'https://nodejs.org/en/about/releases/',
    enabled: true,
    tags: ['javascript', 'node', 'runtime']
  },
  {
    id: 'webpack-v4',
    name: 'Webpack 4.x',
    description: 'Detects usage of Webpack 4.x which is outdated',
    technology: 'Webpack',
    filePattern: '{package.json,webpack.config.js}',
    contentPattern: '"webpack":\s*"\\^?4\\.[0-9]',
    severity: 'medium',
    message: 'Using Webpack 4.x which is outdated',
    recommendedVersion: '5.x',
    remediationSteps: 'Update to Webpack 5.x by running npm install webpack@latest --save-dev. Note that there may be breaking changes.',
    examples: ['"webpack": "^4.43.0"'],
    reference: 'https://webpack.js.org/migrate/5/',
    enabled: true,
    tags: ['javascript', 'bundler', 'webpack']
  },
  {
    id: 'babel-v6',
    name: 'Babel 6.x',
    description: 'Detects usage of Babel 6.x which is outdated',
    technology: 'Babel',
    filePattern: '{package.json,.babelrc,babel.config.js}',
    contentPattern: '"babel-core":|"babel-preset-|"babel-plugin-|"@babel/core":\s*"\\^?6\\.',
    severity: 'medium',
    message: 'Using Babel 6.x which is outdated',
    recommendedVersion: '7.x',
    remediationSteps: 'Update to Babel 7.x. See the migration guide for details.',
    reference: 'https://babeljs.io/docs/en/v7-migration',
    enabled: true,
    tags: ['javascript', 'transpiler', 'babel']
  },
  {
    id: 'react-v16',
    name: 'React 16.x',
    description: 'Detects usage of React 16.x which is outdated',
    technology: 'React',
    filePattern: 'package.json',
    contentPattern: '"react":\s*"\\^?16\\.',
    severity: 'medium',
    message: 'Using React 16.x which is outdated',
    recommendedVersion: '18.x',
    remediationSteps: 'Update to React 18.x by running npm install react@latest react-dom@latest. Review the migration guide for breaking changes.',
    reference: 'https://react.dev/blog/2022/03/29/react-v18',
    enabled: true,
    tags: ['javascript', 'react', 'frontend']
  },
  
  // Python
  {
    id: 'python-2',
    name: 'Python 2.x',
    description: 'Detects usage of Python 2.x which is end-of-life',
    technology: 'Python',
    filePattern: '{requirements.txt,setup.py,runtime.txt,.python-version,Pipfile}',
    contentPattern: 'Python\\s*2\\.[0-9]|python-2\\.[0-9]|python2\\.[0-9]|"python":\s*"2\\.[0-9]',
    severity: 'critical',
    message: 'Using Python 2.x which reached end-of-life on January 1, 2020',
    recommendedVersion: '3.9 or later',
    remediationSteps: 'Update to Python 3.9+ and update code to be compatible with Python 3. Use tools like 2to3 to assist with migration.',
    reference: 'https://www.python.org/doc/sunset-python-2/',
    enabled: true,
    tags: ['python', 'runtime']
  },
  {
    id: 'django-2',
    name: 'Django 2.x',
    description: 'Detects usage of Django 2.x which is end-of-life',
    technology: 'Django',
    filePattern: '{requirements.txt,setup.py,Pipfile}',
    contentPattern: 'Django==2\\.[0-9]|django==2\\.[0-9]|Django>=2\\.[0-9],<3|django>=2\\.[0-9],<3',
    severity: 'high',
    message: 'Using Django 2.x which is end-of-life',
    recommendedVersion: '4.2 LTS or later',
    remediationSteps: 'Update to Django 4.2 LTS or later. Review the migration guide for breaking changes.',
    reference: 'https://www.djangoproject.com/download/#supported-versions',
    enabled: true,
    tags: ['python', 'django', 'framework']
  },
  
  // Java
  {
    id: 'java-8',
    name: 'Java 8',
    description: 'Detects usage of Java 8 which is outdated for enterprise use',
    technology: 'Java',
    filePattern: '{pom.xml,build.gradle,.java-version}',
    contentPattern: 'sourceCompatibility\\s*=\\s*1\\.8|targetCompatibility\\s*=\\s*1\\.8|<java.version>1\\.8|<java.version>8|compileJava \\{\\s*sourceCompatibility = \'8\'',
    severity: 'medium',
    message: 'Using Java 8 which is outdated for enterprise applications',
    recommendedVersion: 'Java 17 LTS or later',
    remediationSteps: 'Update to Java 17 LTS or later. Update your build configuration and check for deprecated APIs.',
    reference: 'https://www.oracle.com/java/technologies/java-se-support-roadmap.html',
    enabled: true,
    tags: ['java', 'runtime']
  },
  {
    id: 'spring-boot-2',
    name: 'Spring Boot 2.x',
    description: 'Detects usage of Spring Boot 2.x which will be EOL soon',
    technology: 'Spring Boot',
    filePattern: '{pom.xml,build.gradle,gradle.properties}',
    contentPattern: '<spring-boot.version>2\\.[0-9]|<spring-boot-starter-parent.version>2\\.[0-9]|springBootVersion\\s*=\\s*\'2\\.[0-9]|org.springframework.boot:spring-boot-starter-parent:2\\.[0-9]',
    severity: 'medium',
    message: 'Using Spring Boot 2.x which will reach end-of-life soon',
    recommendedVersion: '3.x',
    remediationSteps: 'Update to Spring Boot 3.x. Review the migration guide for breaking changes, especially related to Java 17 requirement.',
    reference: 'https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-3.0-Migration-Guide',
    enabled: true,
    tags: ['java', 'spring', 'framework']
  },
  
  // PHP
  {
    id: 'php-7',
    name: 'PHP 7.x',
    description: 'Detects usage of PHP 7.x which is approaching end-of-life',
    technology: 'PHP',
    filePattern: '{composer.json,.php-version}',
    contentPattern: '"php":\s*">=[5-7]\\.[0-9]|"php":\s*"7\\.[0-9]',
    severity: 'high',
    message: 'Using PHP 7.x which is approaching end-of-life',
    recommendedVersion: '8.1 or later',
    remediationSteps: 'Update to PHP 8.1 or later. Review your code for deprecated features and backwards compatibility issues.',
    reference: 'https://www.php.net/supported-versions.php',
    enabled: true,
    tags: ['php', 'runtime']
  },
  {
    id: 'laravel-8',
    name: 'Laravel 8.x',
    description: 'Detects usage of Laravel 8.x which is outdated',
    technology: 'Laravel',
    filePattern: 'composer.json',
    contentPattern: '"laravel/framework":\s*"\\^?8\\.',
    severity: 'medium',
    message: 'Using Laravel 8.x which is outdated',
    recommendedVersion: '10.x',
    remediationSteps: 'Update to Laravel 10.x. Review the upgrade guide for breaking changes.',
    reference: 'https://laravel.com/docs/10.x/upgrade',
    enabled: true,
    tags: ['php', 'laravel', 'framework']
  },
  
  // .NET
  {
    id: 'dotnet-3',
    name: '.NET Core 3.x',
    description: 'Detects usage of .NET Core 3.x which is outdated',
    technology: '.NET',
    filePattern: '{*.csproj,global.json}',
    contentPattern: '<TargetFramework>netcoreapp3\\.[0-9]</TargetFramework>|<TargetFramework>netstandard2\\.[0-9]</TargetFramework>',
    severity: 'high',
    message: 'Using .NET Core 3.x which is outdated',
    recommendedVersion: '.NET 7.0 or later',
    remediationSteps: 'Update to .NET 7.0 or later. Update your project files and check for deprecated APIs.',
    reference: 'https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core',
    enabled: true,
    tags: ['dotnet', 'runtime']
  },
  
  // Go
  {
    id: 'go-1-15',
    name: 'Go 1.15 or earlier',
    description: 'Detects usage of Go 1.15 or earlier which is outdated',
    technology: 'Go',
    filePattern: '{go.mod,Dockerfile,*.go}',
    contentPattern: 'go\\s1\\.(\\d|1[0-5])\\b',
    severity: 'medium',
    message: 'Using Go 1.15 or earlier which is outdated',
    recommendedVersion: '1.20 or later',
    remediationSteps: 'Update to Go 1.20 or later. Update go.mod file and check for deprecated APIs.',
    reference: 'https://golang.org/doc/devel/release.html',
    enabled: true,
    tags: ['go', 'runtime']
  },
  
  // Ruby
  {
    id: 'ruby-2-6',
    name: 'Ruby 2.6 or earlier',
    description: 'Detects usage of Ruby 2.6 or earlier which is EOL',
    technology: 'Ruby',
    filePattern: '{Gemfile,Gemfile.lock,.ruby-version,.tool-versions}',
    contentPattern: 'ruby\\s*([1-9]\\.[0-9]+|2\\.[0-6])',
    severity: 'high',
    message: 'Using Ruby 2.6 or earlier which is EOL',
    recommendedVersion: '3.2 or later',
    remediationSteps: 'Update to Ruby 3.2 or later. Check for deprecated APIs and syntax changes.',
    reference: 'https://www.ruby-lang.org/en/downloads/releases/',
    enabled: true,
    tags: ['ruby', 'runtime']
  },
  {
    id: 'rails-6',
    name: 'Rails 6.x',
    description: 'Detects usage of Rails 6.x which is outdated',
    technology: 'Rails',
    filePattern: '{Gemfile,Gemfile.lock}',
    contentPattern: 'rails\\s*([1-5]\\.[0-9]+|6\\.[0-9]+)',
    severity: 'medium',
    message: 'Using Rails 6.x which is outdated',
    recommendedVersion: '7.0 or later',
    remediationSteps: 'Update to Rails 7.0 or later. Review the upgrade guide for breaking changes.',
    reference: 'https://guides.rubyonrails.org/upgrading_ruby_on_rails.html',
    enabled: true,
    tags: ['ruby', 'rails', 'framework']
  },
  
  // Android
  {
    id: 'android-api-28',
    name: 'Android API level 28 (Android 9) or earlier',
    description: 'Detects usage of Android API level 28 or earlier',
    technology: 'Android',
    filePattern: '{build.gradle,app/build.gradle}',
    contentPattern: 'targetSdkVersion\\s*(1?\\d|2[0-8])\\b|compileSdkVersion\\s*(1?\\d|2[0-8])\\b',
    severity: 'high',
    message: 'Using Android API level 28 (Android 9) or earlier, which may not be accepted in app stores soon',
    recommendedVersion: 'API level 33 (Android 13) or later',
    remediationSteps: 'Update to target and compile with API level 33 or later. Test thoroughly for compatibility issues.',
    reference: 'https://developer.android.com/distribute/best-practices/develop/target-sdk',
    enabled: true,
    tags: ['android', 'mobile']
  },
  
  // iOS
  {
    id: 'ios-12',
    name: 'iOS 12 or earlier',
    description: 'Detects usage of iOS 12 or earlier as deployment target',
    technology: 'iOS',
    filePattern: '{*.pbxproj,*.xcodeproj/project.pbxproj,Podfile}',
    contentPattern: 'IPHONEOS_DEPLOYMENT_TARGET\\s*=\\s*(\\d|1[0-2])\\.',
    severity: 'medium',
    message: 'Using iOS 12 or earlier as deployment target, which is outdated',
    recommendedVersion: 'iOS 15 or later',
    remediationSteps: 'Update deployment target to iOS 15 or later. Test thoroughly for compatibility issues.',
    reference: 'https://developer.apple.com/support/app-store/',
    enabled: true,
    tags: ['ios', 'mobile']
  },
  
  // Database
  {
    id: 'mongodb-3',
    name: 'MongoDB 3.x',
    description: 'Detects usage of MongoDB 3.x which is approaching EOL',
    technology: 'MongoDB',
    filePattern: '{package.json,requirements.txt,Gemfile,composer.json,go.mod,pom.xml}',
    contentPattern: 'mongodb:\\s*"\\^?3\\.|pymongo\\s*==\\s*3\\.|mongo-go-driver\\s*v3\\.',
    severity: 'medium',
    message: 'Using MongoDB 3.x which is approaching end-of-life',
    recommendedVersion: '5.0 or later',
    remediationSteps: 'Update to MongoDB 5.0 or later and update client drivers accordingly.',
    reference: 'https://www.mongodb.com/support-policy',
    enabled: true,
    tags: ['database', 'mongodb']
  },
  {
    id: 'mysql-5',
    name: 'MySQL 5.x',
    description: 'Detects usage of MySQL 5.x which is outdated for new projects',
    technology: 'MySQL',
    filePattern: '{Dockerfile,docker-compose.yml,*.sql}',
    contentPattern: 'mysql:\\s*5\\.|image:\\s*mysql:5|FROM\\s+mysql:5',
    severity: 'medium',
    message: 'Using MySQL 5.x which is outdated for new projects',
    recommendedVersion: '8.0 or later',
    remediationSteps: 'Update to MySQL 8.0 or later. Check for SQL syntax compatibility issues.',
    reference: 'https://www.mysql.com/support/',
    enabled: true,
    tags: ['database', 'mysql']
  },
  
  // General
  {
    id: 'jquery-2',
    name: 'jQuery 2.x or earlier',
    description: 'Detects usage of jQuery 2.x or earlier which is outdated',
    technology: 'jQuery',
    filePattern: '{package.json,bower.json,*.html}',
    contentPattern: 'jquery\\s*"\\^?([0-1]\\.|2\\.)|\\/jquery\\@([0-1]\\.|2\\.)|jquery-([0-1]\\.|2\\.)|jquery\\.js|jquery\\.min\\.js',
    severity: 'medium',
    message: 'Using jQuery 2.x or earlier which is outdated and may have security vulnerabilities',
    recommendedVersion: '3.6 or later, or consider using modern alternatives',
    remediationSteps: 'Update to jQuery 3.6 or later, or consider using native JavaScript APIs or a modern framework.',
    reference: 'https://jquery.com/upgrade-guide/',
    enabled: true,
    tags: ['javascript', 'jquery', 'frontend']
  },
  {
    id: 'bootstrap-4',
    name: 'Bootstrap 4.x',
    description: 'Detects usage of Bootstrap 4.x which is outdated',
    technology: 'Bootstrap',
    filePattern: '{package.json,bower.json,*.html}',
    contentPattern: 'bootstrap\\s*"\\^?4\\.|bootstrap@4|bootstrap-4|bootstrap\\/4|bootstrap\\.min\\.css|bootstrap\\.min\\.js',
    severity: 'low',
    message: 'Using Bootstrap 4.x which is outdated',
    recommendedVersion: '5.x',
    remediationSteps: 'Update to Bootstrap 5.x. Be aware of breaking changes, especially in grid system and JavaScript plugins.',
    reference: 'https://getbootstrap.com/docs/5.3/migration/',
    enabled: true,
    tags: ['css', 'bootstrap', 'frontend']
  },
  {
    id: 'docker-old-base',
    name: 'Outdated Docker base images',
    description: 'Detects usage of outdated or vulnerable Docker base images',
    technology: 'Docker',
    filePattern: '{Dockerfile,docker-compose.yml}',
    contentPattern: 'FROM\\s+debian:(jessie|stretch)|FROM\\s+ubuntu:(trusty|xenial|bionic)|FROM\\s+alpine:3\\.[0-8]',
    severity: 'high',
    message: 'Using outdated Docker base images which may have security vulnerabilities',
    recommendedVersion: 'Use the latest stable versions of base images',
    remediationSteps: 'Update base images to latest stable versions. For Alpine, use 3.17+, for Ubuntu, use 22.04+, for Debian, use 11+.',
    reference: 'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/',
    enabled: true,
    tags: ['docker', 'container', 'devops']
  }
];
