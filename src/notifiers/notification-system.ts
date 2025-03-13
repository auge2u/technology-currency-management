import * as nodemailer from 'nodemailer';
import axios from 'axios';
import { SecurityVulnerability, OutdatedDependency, ExtensionIssue } from '../types/scanning';
import { log } from '../utils/logging';

/**
 * Configuration for the notification system
 */
export interface NotificationConfig {
  // Email notifications
  email?: {
    enabled: boolean;
    smtpConfig: {
      host: string;
      port: number;
      secure: boolean;
      auth: {
        user: string;
        pass: string;
      };
    };
    recipients: string[];
    fromAddress: string;
  };

  // Slack notifications
  slack?: {
    enabled: boolean;
    webhookUrl: string;
    channel?: string;
  };

  // Microsoft Teams notifications
  teams?: {
    enabled: boolean;
    webhookUrl: string;
  };

  // Jira ticket creation
  jira?: {
    enabled: boolean;
    host: string;
    auth: {
      email: string;
      apiToken: string;
    };
    projectKey: string;
    issueType: string;
  };

  // Generic webhook notifications (for custom integrations)
  webhook?: {
    enabled: boolean;
    url: string;
    headers?: Record<string, string>;
  };

  // Notification thresholds
  thresholds: {
    // Minimum severity level to notify (low, medium, high, critical)
    minimumSeverity: 'low' | 'medium' | 'high' | 'critical';
    
    // Days before EOL to start notifications
    daysBeforeEol: number;
    
    // Version difference thresholds
    versionsBehind: {
      major: number; // Major versions behind for notification
      minor: number; // Minor versions behind for notification
    };
  };
}

/**
 * Notification content
 */
export interface NotificationPayload {
  title: string;
  summary: string;
  details: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  sourceSystem: string;
  affectedComponents: string[];
  remediationSteps?: string;
  links?: Array<{ title: string; url: string }>;
  detected: Date;
}

/**
 * Result of sending a notification
 */
export interface NotificationResult {
  channel: string;
  success: boolean;
  message?: string;
  timestamp: Date;
  recipientInfo?: string;
  payload: NotificationPayload;
}

/**
 * The notification system for proactively alerting teams about outdated technologies
 * and security vulnerabilities
 */
export class NotificationSystem {
  private config: NotificationConfig;
  private emailTransporter: any | null = null;

  constructor(config: NotificationConfig) {
    this.config = config;
    this.initializeChannels();
  }

  /**
   * Initialize notification channels
   */
  private initializeChannels(): void {
    // Initialize email if enabled
    if (this.config.email?.enabled) {
      try {
        this.emailTransporter = nodemailer.createTransport(this.config.email.smtpConfig);
        log.info('Email notification channel initialized');
      } catch (error) {
        log.error('Failed to initialize email notification channel', { error });
      }
    }

    // Log initialization of other channels
    if (this.config.slack?.enabled) {
      log.info('Slack notification channel initialized');
    }

    if (this.config.teams?.enabled) {
      log.info('Microsoft Teams notification channel initialized');
    }

    if (this.config.jira?.enabled) {
      log.info('Jira notification channel initialized');
    }

    if (this.config.webhook?.enabled) {
      log.info('Webhook notification channel initialized');
    }
  }

  /**
   * Send notification about outdated dependencies
   */
  async notifyOutdatedDependencies(dependencies: OutdatedDependency[]): Promise<NotificationResult[]> {
    if (dependencies.length === 0) {
      log.info('No outdated dependencies to notify about');
      return [];
    }

    const results: NotificationResult[] = [];
    const filteredDependencies = this.filterBySeverityThreshold(dependencies);

    if (filteredDependencies.length === 0) {
      log.info('No outdated dependencies meet notification threshold criteria');
      return [];
    }

    // Group dependencies by severity for better notification
    const groupedByPackageManager = this.groupDependenciesByPackageManager(filteredDependencies);

    // Send notifications for each package manager group
    for (const [packageManager, deps] of Object.entries(groupedByPackageManager)) {
      // Create a notification payload
      const criticalCount = deps.filter(d => d.severity === 'critical').length;
      const highCount = deps.filter(d => d.severity === 'high').length;
      const mediumCount = deps.filter(d => d.severity === 'medium').length;
      const lowCount = deps.filter(d => d.severity === 'low').length;
      
      const criticalAndHighDeps = deps.filter(d => d.severity === 'critical' || d.severity === 'high');
      
      // Determine overall severity for the notification
      let overallSeverity: 'low' | 'medium' | 'high' | 'critical' = 'low';
      if (criticalCount > 0) overallSeverity = 'critical';
      else if (highCount > 0) overallSeverity = 'high';
      else if (mediumCount > 0) overallSeverity = 'medium';

      // Create notification summary
      const title = `${criticalCount + highCount} critical/high outdated ${packageManager} dependencies require attention`;
      
      const summary = `${deps.length} outdated ${packageManager} dependencies detected: ` + 
                     `${criticalCount} critical, ${highCount} high, ${mediumCount} medium, and ${lowCount} low severity issues.`;
      
      // Generate details focusing on critical and high severity dependencies
      let details = `The following ${packageManager} dependencies require immediate attention:\n\n`;
      
      // Add critical and high severity dependencies to details
      criticalAndHighDeps.forEach(dep => {
        details += `- ${dep.name} (${dep.currentVersion} → ${dep.latestVersion}): ${dep.severity.toUpperCase()} severity\n`;
        details += `  Path: ${dep.path}\n`;
        details += `  Remediation: ${dep.remediationSteps}\n\n`;
      });
      
      // Add summary of lower severity dependencies
      if (mediumCount + lowCount > 0) {
        details += `\nAdditionally, there are ${mediumCount} medium and ${lowCount} low severity outdated dependencies.`;
      }
      
      // Create links for package documentation
      const links = criticalAndHighDeps.map(dep => ({
        title: `${dep.name} documentation`,
        url: this.getPackageDocUrl(dep.name, dep.packageManager)
      }));
      
      // Create affected components list
      const affectedComponents = Array.from(new Set(deps.map(d => d.path)));
      
      const payload: NotificationPayload = {
        title,
        summary,
        details,
        severity: overallSeverity,
        sourceSystem: 'Dependency Scanner',
        affectedComponents,
        remediationSteps: 'Update the dependencies to their latest versions or apply the specific remediation steps.',
        links,
        detected: new Date()
      };
      
      // Send the notification through all configured channels
      const notificationResults = await this.sendNotification(payload);
      results.push(...notificationResults);
    }

    return results;
  }

  /**
   * Send notification about security vulnerabilities
   */
  async notifySecurityVulnerabilities(vulnerabilities: SecurityVulnerability[]): Promise<NotificationResult[]> {
    if (vulnerabilities.length === 0) {
      log.info('No security vulnerabilities to notify about');
      return [];
    }

    const results: NotificationResult[] = [];
    const filteredVulnerabilities = this.filterBySeverityThreshold(vulnerabilities);

    if (filteredVulnerabilities.length === 0) {
      log.info('No security vulnerabilities meet notification threshold criteria');
      return [];
    }

    // Group vulnerabilities by affected package for better notification organization
    const groupedByPackage = this.groupVulnerabilitiesByPackage(filteredVulnerabilities);

    // Send notifications for each package group with vulnerabilities
    for (const [packageName, vulns] of Object.entries(groupedByPackage)) {
      // Create a notification payload
      const criticalCount = vulns.filter(v => v.severity === 'critical').length;
      const highCount = vulns.filter(v => v.severity === 'high').length;
      const mediumCount = vulns.filter(v => v.severity === 'medium').length;
      const lowCount = vulns.filter(v => v.severity === 'low').length;
      
      // Determine overall severity for the notification
      let overallSeverity: 'low' | 'medium' | 'high' | 'critical' = 'low';
      if (criticalCount > 0) overallSeverity = 'critical';
      else if (highCount > 0) overallSeverity = 'high';
      else if (mediumCount > 0) overallSeverity = 'medium';

      // Create notification summary
      const title = `${criticalCount + highCount} critical/high security vulnerabilities in ${packageName}`;
      
      const summary = `${vulns.length} security vulnerabilities detected in ${packageName}: ` + 
                     `${criticalCount} critical, ${highCount} high, ${mediumCount} medium, and ${lowCount} low severity issues.`;
      
      // Generate detailed information about the vulnerabilities
      let details = `The following security vulnerabilities require attention:\n\n`;
      
      // Sort vulnerabilities by severity (critical first)
      const sortedVulns = [...vulns].sort((a, b) => {
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        return severityOrder[a.severity] - severityOrder[b.severity];
      });
      
      // Add vulnerabilities to details
      sortedVulns.forEach(vuln => {
        details += `- ${vuln.title} (${vuln.vulnerabilityId}): ${vuln.severity.toUpperCase()} severity (CVSS: ${vuln.cvss})\n`;
        details += `  Package: ${vuln.packageName}@${vuln.packageVersion}\n`;
        details += `  Description: ${vuln.description}\n`;
        details += `  Fixed in: ${vuln.fixedInVersion}\n`;
        details += `  Path: ${vuln.path}\n`;
        details += `  Remediation: ${vuln.remediationSteps}\n\n`;
      });
      
      // Create links for vulnerability references
      const links = Array.from(
        new Set(
          sortedVulns.flatMap(vuln => 
            vuln.references.map(ref => ({
              title: `${vuln.vulnerabilityId} reference`,
              url: ref
            }))
          )
        )
      );
      
      // Create affected components list
      const affectedComponents = Array.from(new Set(vulns.map(v => v.path)));
      
      const payload: NotificationPayload = {
        title,
        summary,
        details,
        severity: overallSeverity,
        sourceSystem: 'Security Vulnerability Scanner',
        affectedComponents,
        remediationSteps: 'Update the affected packages to the fixed versions or apply the specific remediation steps.',
        links,
        detected: new Date()
      };
      
      // Send the notification through all configured channels
      const notificationResults = await this.sendNotification(payload);
      results.push(...notificationResults);
    }

    return results;
  }

  /**
   * Send notification about browser extension issues
   */
  async notifyBrowserExtensionIssues(extensionIssues: ExtensionIssue[]): Promise<NotificationResult[]> {
    if (extensionIssues.length === 0) {
      log.info('No browser extension issues to notify about');
      return [];
    }

    const results: NotificationResult[] = [];
    const filteredIssues = this.filterBySeverityThreshold(extensionIssues);

    if (filteredIssues.length === 0) {
      log.info('No browser extension issues meet notification threshold criteria');
      return [];
    }

    // Group issues by browser for better notification organization
    const groupedByBrowser = this.groupExtensionIssuesByBrowser(filteredIssues);

    // Send notifications for each browser group
    for (const [browser, issues] of Object.entries(groupedByBrowser)) {
      // Create a notification payload
      const criticalCount = issues.filter(i => i.severity === 'critical').length;
      const highCount = issues.filter(i => i.severity === 'high').length;
      const mediumCount = issues.filter(i => i.severity === 'medium').length;
      const lowCount = issues.filter(i => i.severity === 'low').length;
      
      // Determine overall severity for the notification
      let overallSeverity: 'low' | 'medium' | 'high' | 'critical' = 'low';
      if (criticalCount > 0) overallSeverity = 'critical';
      else if (highCount > 0) overallSeverity = 'high';
      else if (mediumCount > 0) overallSeverity = 'medium';

      // Create notification summary
      const title = `${criticalCount + highCount} critical/high ${browser} extension issues detected`;
      
      const summary = `${issues.length} ${browser} extension issues detected: ` + 
                    `${criticalCount} critical, ${highCount} high, ${mediumCount} medium, and ${lowCount} low severity issues.`;
      
      // Generate detailed information about the issues
      let details = `The following ${browser} extension issues require attention:\n\n`;
      
      // Sort issues by severity (critical first)
      const sortedIssues = [...issues].sort((a, b) => {
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        return severityOrder[a.severity] - severityOrder[b.severity];
      });
      
      // Add issues to details
      sortedIssues.forEach(issue => {
        details += `- ${issue.extensionName} (${issue.extensionVersion}): ${issue.severity.toUpperCase()} severity\n`;
        details += `  Issue: ${issue.title}\n`;
        details += `  Description: ${issue.description}\n`;
        details += `  Extension ID: ${issue.extensionId}\n`;
        details += `  Issue Type: ${issue.issueType}\n`;
        details += `  Remediation: ${issue.remediationSteps}\n\n`;
      });
      
      // Create links for extension documentation or store pages
      const links = Array.from(
        new Set(
          sortedIssues.map(issue => ({
            title: `${issue.extensionName} in ${browser} store`,
            url: this.getExtensionStoreUrl(issue.browser, issue.extensionId)
          }))
        )
      );
      
      // Create affected components list - in this case, just the browser name
      const affectedComponents = [browser];
      
      const payload: NotificationPayload = {
        title,
        summary,
        details,
        severity: overallSeverity,
        sourceSystem: 'Browser Extension Scanner',
        affectedComponents,
        remediationSteps: 'Update or remove the affected browser extensions.',
        links,
        detected: new Date()
      };
      
      // Send the notification through all configured channels
      const notificationResults = await this.sendNotification(payload);
      results.push(...notificationResults);
    }

    return results;
  }

  /**
   * Filter items by configured severity threshold
   */
  private filterBySeverityThreshold<T extends { severity: 'low' | 'medium' | 'high' | 'critical' }>(items: T[]): T[] {
    const { minimumSeverity } = this.config.thresholds;
    const severityOrder = { low: 0, medium: 1, high: 2, critical: 3 };
    const threshold = severityOrder[minimumSeverity];
    
    return items.filter(item => severityOrder[item.severity] >= threshold);
  }

  /**
   * Group dependencies by package manager
   */
  private groupDependenciesByPackageManager(dependencies: OutdatedDependency[]): Record<string, OutdatedDependency[]> {
    return dependencies.reduce((acc, dep) => {
      const packageManager = dep.packageManager;
      if (!acc[packageManager]) {
        acc[packageManager] = [];
      }
      acc[packageManager].push(dep);
      return acc;
    }, {} as Record<string, OutdatedDependency[]>);
  }

  /**
   * Group vulnerabilities by package name
   */
  private groupVulnerabilitiesByPackage(vulnerabilities: SecurityVulnerability[]): Record<string, SecurityVulnerability[]> {
    return vulnerabilities.reduce((acc, vuln) => {
      const packageName = vuln.packageName;
      if (!acc[packageName]) {
        acc[packageName] = [];
      }
      acc[packageName].push(vuln);
      return acc;
    }, {} as Record<string, SecurityVulnerability[]>);
  }

  /**
   * Group extension issues by browser
   */
  private groupExtensionIssuesByBrowser(issues: ExtensionIssue[]): Record<string, ExtensionIssue[]> {
    return issues.reduce((acc, issue) => {
      const browser = issue.browser;
      if (!acc[browser]) {
        acc[browser] = [];
      }
      acc[browser].push(issue);
      return acc;
    }, {} as Record<string, ExtensionIssue[]>);
  }

  /**
   * Send a notification through all configured channels
   */
  async sendNotification(payload: NotificationPayload): Promise<NotificationResult[]> {
    const results: NotificationResult[] = [];

    // Send via email if configured
    if (this.config.email?.enabled && this.emailTransporter) {
      try {
        const result = await this.sendEmailNotification(payload);
        results.push(result);
      } catch (error) {
        log.error('Failed to send email notification', { error });
        results.push({
          channel: 'email',
          success: false,
          message: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date(),
          payload
        });
      }
    }

    // Send via Slack if configured
    if (this.config.slack?.enabled) {
      try {
        const result = await this.sendSlackNotification(payload);
        results.push(result);
      } catch (error) {
        log.error('Failed to send Slack notification', { error });
        results.push({
          channel: 'slack',
          success: false,
          message: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date(),
          payload
        });
      }
    }

    // Send via Microsoft Teams if configured
    if (this.config.teams?.enabled) {
      try {
        const result = await this.sendTeamsNotification(payload);
        results.push(result);
      } catch (error) {
        log.error('Failed to send Microsoft Teams notification', { error });
        results.push({
          channel: 'teams',
          success: false,
          message: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date(),
          payload
        });
      }
    }

    // Create Jira ticket if configured
    if (this.config.jira?.enabled) {
      try {
        const result = await this.createJiraIssue(payload);
        results.push(result);
      } catch (error) {
        log.error('Failed to create Jira issue', { error });
        results.push({
          channel: 'jira',
          success: false,
          message: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date(),
          payload
        });
      }
    }

    // Send via webhook if configured
    if (this.config.webhook?.enabled) {
      try {
        const result = await this.sendWebhookNotification(payload);
        results.push(result);
      } catch (error) {
        log.error('Failed to send webhook notification', { error });
        results.push({
          channel: 'webhook',
          success: false,
          message: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date(),
          payload
        });
      }
    }

    return results;
  }

  /**
   * Send email notification
   */
  private async sendEmailNotification(payload: NotificationPayload): Promise<NotificationResult> {
    if (!this.config.email || !this.emailTransporter) {
      throw new Error('Email notification channel not configured');
    }

    // Prepare email content
    let htmlContent = `<h1>${payload.title}</h1>`;
    htmlContent += `<p><strong>${payload.summary}</strong></p>`;
    htmlContent += `<h2>Details</h2>`;
    htmlContent += `<pre>${payload.details}</pre>`;
    
    if (payload.remediationSteps) {
      htmlContent += `<h2>Remediation Steps</h2>`;
      htmlContent += `<p>${payload.remediationSteps}</p>`;
    }
    
    if (payload.links && payload.links.length > 0) {
      htmlContent += `<h2>References</h2><ul>`;
      for (const link of payload.links) {
        htmlContent += `<li><a href="${link.url}">${link.title}</a></li>`;
      }
      htmlContent += `</ul>`;
    }
    
    // Send the email
    const mailOptions = {
      from: this.config.email.fromAddress,
      to: this.config.email.recipients.join(','),
      subject: `[${payload.severity.toUpperCase()}] ${payload.title}`,
      html: htmlContent,
      text: payload.summary + '\n\n' + payload.details
    };
    
    await this.emailTransporter.sendMail(mailOptions);
    
    return {
      channel: 'email',
      success: true,
      timestamp: new Date(),
      recipientInfo: this.config.email.recipients.join(','),
      payload
    };
  }

  /**
   * Send Slack notification
   */
  private async sendSlackNotification(payload: NotificationPayload): Promise<NotificationResult> {
    if (!this.config.slack) {
      throw new Error('Slack notification channel not configured');
    }

    // Map severity to color
    const severityColors = {
      low: '#2eb886',      // green
      medium: '#daa038',   // yellow
      high: '#dc7633',     // orange
      critical: '#cc0000'  // red
    };

    // Build Slack message
    const slackMessage = {
      channel: this.config.slack.channel,
      attachments: [
        {
          color: severityColors[payload.severity],
          pretext: `*${payload.title}*`,
          text: payload.summary,
          fields: [
            {
              title: 'Severity',
              value: payload.severity.toUpperCase(),
              short: true
            },
            {
              title: 'Source',
              value: payload.sourceSystem,
              short: true
            },
            {
              title: 'Details',
              value: payload.details.length > 2000 
                ? payload.details.substring(0, 2000) + '... (truncated)' 
                : payload.details,
              short: false
            }
          ],
          footer: `Detected at ${payload.detected.toISOString()}`
        }
      ]
    };

    // Add remediation steps if available
    if (payload.remediationSteps) {
      slackMessage.attachments[0].fields.push({
        title: 'Remediation',
        value: payload.remediationSteps,
        short: false
      });
    }

    // Add links if available
    if (payload.links && payload.links.length > 0) {
      const linksSection = payload.links
        .map(link => `<${link.url}|${link.title}>`)
        .join(' | ');
      
      slackMessage.attachments[0].fields.push({
        title: 'References',
        value: linksSection,
        short: false
      });
    }

    // Send to Slack
    await axios.post(this.config.slack.webhookUrl, slackMessage);

    return {
      channel: 'slack',
      success: true,
      timestamp: new Date(),
      recipientInfo: this.config.slack.channel,
      payload
    };
  }

  /**
   * Send Microsoft Teams notification
   */
  private async sendTeamsNotification(payload: NotificationPayload): Promise<NotificationResult> {
    if (!this.config.teams) {
      throw new Error('Microsoft Teams notification channel not configured');
    }

    // Map severity to color
    const severityColors = {
      low: '2eb886',      // green
      medium: 'daa038',   // yellow
      high: 'dc7633',     // orange
      critical: 'cc0000'  // red
    };

    // Build Teams message card
    const teamsMessage = {
      "@type": "MessageCard",
      "@context": "http://schema.org/extensions",
      "themeColor": severityColors[payload.severity],
      "summary": payload.title,
      "sections": [
        {
          "activityTitle": payload.title,
          "activitySubtitle": `Severity: ${payload.severity.toUpperCase()} | Source: ${payload.sourceSystem}`,
          "text": payload.summary,
          "facts": [
            {
              "name": "Details",
              "value": payload.details.length > 2000 
                ? payload.details.substring(0, 2000) + '... (truncated)' 
                : payload.details
            },
            {
              "name": "Detected At",
              "value": payload.detected.toISOString()
            }
          ]
        }
      ]
    };

    // Add remediation steps if available
    if (payload.remediationSteps) {
      teamsMessage.sections[0].facts.push({
        "name": "Remediation",
        "value": payload.remediationSteps
      });
    }

    // Add links if available
    if (payload.links && payload.links.length > 0) {
      teamsMessage.potentialAction = payload.links.map(link => ({
        "@type": "OpenUri",
        "name": link.title,
        "targets": [
          { "os": "default", "uri": link.url }
        ]
      }));
    }

    // Send to Microsoft Teams
    await axios.post(this.config.teams.webhookUrl, teamsMessage);

    return {
      channel: 'teams',
      success: true,
      timestamp: new Date(),
      payload
    };
  }

  /**
   * Create Jira issue
   */
  private async createJiraIssue(payload: NotificationPayload): Promise<NotificationResult> {
    if (!this.config.jira) {
      throw new Error('Jira notification channel not configured');
    }

    // Build the Jira issue data
    const jiraIssue = {
      fields: {
        project: {
          key: this.config.jira.projectKey
        },
        issuetype: {
          name: this.config.jira.issueType
        },
        summary: payload.title,
        description: `${payload.summary}\n\n*Details*:\n${payload.details}\n\n*Remediation Steps*:\n${payload.remediationSteps || 'N/A'}\n\n*Detected At*: ${payload.detected.toISOString()}`,
        priority: {
          name: this.mapSeverityToJiraPriority(payload.severity)
        },
        labels: [
          'tech-currency',
          `severity-${payload.severity}`,
          `source-${payload.sourceSystem.toLowerCase().replace(/\s+/g, '-')}`
        ]
      }
    };

    // Add links as comments if available
    let linksComment = '';
    if (payload.links && payload.links.length > 0) {
      linksComment = 'References:\n' + payload.links.map(link => `- [${link.title}|${link.url}]`).join('\n');
      jiraIssue.fields.description += `\n\n${linksComment}`;
    }

    // Create the issue in Jira
    const response = await axios.post(
      `${this.config.jira.host}/rest/api/2/issue`,
      jiraIssue,
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Basic ${Buffer.from(
            `${this.config.jira.auth.email}:${this.config.jira.auth.apiToken}`
          ).toString('base64')}`
        }
      }
    );

    return {
      channel: 'jira',
      success: true,
      message: `Created Jira issue: ${response.data.key}`,
      timestamp: new Date(),
      recipientInfo: `${this.config.jira.projectKey} project`,
      payload
    };
  }

  /**
   * Send webhook notification
   */
  private async sendWebhookNotification(payload: NotificationPayload): Promise<NotificationResult> {
    if (!this.config.webhook) {
      throw new Error('Webhook notification channel not configured');
    }

    // Prepare the webhook payload
    const webhookPayload = {
      title: payload.title,
      summary: payload.summary,
      details: payload.details,
      severity: payload.severity,
      sourceSystem: payload.sourceSystem,
      affectedComponents: payload.affectedComponents,
      remediationSteps: payload.remediationSteps,
      links: payload.links,
      detected: payload.detected.toISOString(),
      timestamp: new Date().toISOString()
    };

    // Send to webhook
    await axios.post(
      this.config.webhook.url,
      webhookPayload,
      {
        headers: this.config.webhook.headers || {}
      }
    );

    return {
      channel: 'webhook',
      success: true,
      timestamp: new Date(),
      recipientInfo: this.config.webhook.url,
      payload
    };
  }

  /**
   * Map our severity levels to Jira priority levels
   */
  private mapSeverityToJiraPriority(severity: 'low' | 'medium' | 'high' | 'critical'): string {
    switch (severity) {
      case 'critical': return 'Highest';
      case 'high': return 'High';
      case 'medium': return 'Medium';
      case 'low': return 'Low';
      default: return 'Medium';
    }
  }

  /**
   * Get package documentation URL based on package manager
   */
  private getPackageDocUrl(packageName: string, packageManager: string): string {
    switch (packageManager) {
      case 'npm':
      case 'yarn':
        return `https://www.npmjs.com/package/${packageName}`;
      case 'pip':
      case 'pipenv':
        return `https://pypi.org/project/${packageName}`;
      case 'maven':
        // This is a simplified URL, in reality would need group and artifact IDs
        return `https://mvnrepository.com/artifact/${packageName}`;
      case 'composer':
        return `https://packagist.org/packages/${packageName}`;
      case 'nuget':
        return `https://www.nuget.org/packages/${packageName}`;
      case 'gem':
        return `https://rubygems.org/gems/${packageName}`;
      case 'cargo':
        return `https://crates.io/crates/${packageName}`;
      case 'go':
        return `https://pkg.go.dev/${packageName}`;
      default:
        return ``;
    }
  }

  /**
   * Get browser extension store URL
   */
  private getExtensionStoreUrl(browser: string, extensionId: string): string {
    switch (browser) {
      case 'Chrome':
        return `https://chrome.google.com/webstore/detail/${extensionId}`;
      case 'Firefox':
        return `https://addons.mozilla.org/en-US/firefox/addon/${extensionId}`;
      case 'Edge':
        return `https://microsoftedge.microsoft.com/addons/detail/${extensionId}`;
      case 'Safari':
        // Safari doesn't have persistent IDs in the same way
        return `https://apps.apple.com/us/app/${extensionId}`;
      default:
        return ``;
    }
  }
}
