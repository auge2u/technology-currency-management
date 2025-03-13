import nodemailer from 'nodemailer';
import axios from 'axios';
import { log } from '../utils/logging';
import config from '../config';
import { OutdatedTechnology, OutdatedDependency, SecurityVulnerability, OutdatedExtension } from '../types/scanning';

/**
 * Base notification data interface
 */
interface NotificationData {
  title: string;
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  scanType: string;
  metadata?: Record<string, any>;
}

/**
 * Notification channel handler interface
 */
interface NotificationChannel {
  name: string;
  enabled: boolean;
  send(data: NotificationData): Promise<boolean>;
}

/**
 * Email notification channel
 */
class EmailNotificationChannel implements NotificationChannel {
  name = 'email';
  enabled = config.notifications.email.enabled;
  
  async send(data: NotificationData): Promise<boolean> {
    try {
      if (!this.enabled) {
        log.debug('Email notifications are disabled');
        return false;
      }
      
      const { host, port, secure, user, pass, from, recipients } = config.notifications.email;
      
      if (!recipients || recipients.length === 0) {
        log.warn('No email recipients configured');
        return false;
      }
      
      // Create transport
      const transport = nodemailer.createTransport({
        host,
        port,
        secure,
        auth: user && pass ? { user, pass } : undefined
      });
      
      // Format the message based on severity
      const subject = `[${data.severity.toUpperCase()}] ${data.title}`;
      
      // Send email
      const result = await transport.sendMail({
        from: from || user,
        to: recipients.join(','),
        subject,
        text: data.message,
        html: formatHtmlEmail(data)
      });
      
      log.info(`Email notification sent: ${result.messageId}`);
      return true;
    } catch (error) {
      log.error('Error sending email notification', { error });
      return false;
    }
  }
}

/**
 * Slack notification channel
 */
class SlackNotificationChannel implements NotificationChannel {
  name = 'slack';
  enabled = config.notifications.slack.enabled;
  
  async send(data: NotificationData): Promise<boolean> {
    try {
      if (!this.enabled) {
        log.debug('Slack notifications are disabled');
        return false;
      }
      
      const { webhookUrl, channel } = config.notifications.slack;
      
      if (!webhookUrl) {
        log.warn('No Slack webhook URL configured');
        return false;
      }
      
      // Create the Slack message payload
      const color = getSeverityColor(data.severity);
      
      const payload = {
        channel,
        attachments: [
          {
            color,
            title: data.title,
            text: data.message,
            fields: [
              {
                title: 'Severity',
                value: data.severity.toUpperCase(),
                short: true
              },
              {
                title: 'Scan Type',
                value: data.scanType,
                short: true
              }
            ],
            footer: 'Technology Currency Management Tool',
            ts: Math.floor(Date.now() / 1000)
          }
        ]
      };
      
      // Add custom fields from metadata
      if (data.metadata) {
        for (const [key, value] of Object.entries(data.metadata)) {
          payload.attachments[0].fields.push({
            title: key,
            value: String(value),
            short: true
          });
        }
      }
      
      // Send to Slack
      const response = await axios.post(webhookUrl, payload);
      
      if (response.status === 200) {
        log.info('Slack notification sent successfully');
        return true;
      } else {
        log.warn('Error sending Slack notification', { status: response.status, data: response.data });
        return false;
      }
    } catch (error) {
      log.error('Error sending Slack notification', { error });
      return false;
    }
  }
}

/**
 * Microsoft Teams notification channel
 */
class TeamsNotificationChannel implements NotificationChannel {
  name = 'teams';
  enabled = config.notifications.teams.enabled;
  
  async send(data: NotificationData): Promise<boolean> {
    try {
      if (!this.enabled) {
        log.debug('Microsoft Teams notifications are disabled');
        return false;
      }
      
      const { webhookUrl } = config.notifications.teams;
      
      if (!webhookUrl) {
        log.warn('No Microsoft Teams webhook URL configured');
        return false;
      }
      
      // Create the Teams message payload
      const payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": getSeverityHexColor(data.severity),
        "summary": data.title,
        "sections": [
          {
            "activityTitle": data.title,
            "activitySubtitle": `Severity: ${data.severity.toUpperCase()} | Scan Type: ${data.scanType}`,
            "text": data.message,
            "facts": [
              {
                "name": "Severity",
                "value": data.severity.toUpperCase()
              },
              {
                "name": "Scan Type",
                "value": data.scanType
              },
              {
                "name": "Timestamp",
                "value": new Date().toISOString()
              }
            ]
          }
        ]
      };
      
      // Add custom facts from metadata
      if (data.metadata) {
        for (const [key, value] of Object.entries(data.metadata)) {
          payload.sections[0].facts.push({
            name: key,
            value: String(value)
          });
        }
      }
      
      // Send to Teams
      const response = await axios.post(webhookUrl, payload);
      
      if (response.status === 200) {
        log.info('Microsoft Teams notification sent successfully');
        return true;
      } else {
        log.warn('Error sending Microsoft Teams notification', { status: response.status, data: response.data });
        return false;
      }
    } catch (error) {
      log.error('Error sending Microsoft Teams notification', { error });
      return false;
    }
  }
}

/**
 * Webhook notification channel for custom integrations
 */
class WebhookNotificationChannel implements NotificationChannel {
  name = 'webhook';
  enabled = config.notifications.webhook.enabled;
  
  async send(data: NotificationData): Promise<boolean> {
    try {
      if (!this.enabled) {
        log.debug('Webhook notifications are disabled');
        return false;
      }
      
      const { url, headers } = config.notifications.webhook;
      
      if (!url) {
        log.warn('No webhook URL configured');
        return false;
      }
      
      // Create payload
      const payload = {
        title: data.title,
        message: data.message,
        severity: data.severity,
        scanType: data.scanType,
        timestamp: new Date().toISOString(),
        metadata: data.metadata || {}
      };
      
      // Send to webhook
      const response = await axios.post(url, payload, { headers });
      
      if (response.status >= 200 && response.status < 300) {
        log.info('Webhook notification sent successfully');
        return true;
      } else {
        log.warn('Error sending webhook notification', { status: response.status, data: response.data });
        return false;
      }
    } catch (error) {
      log.error('Error sending webhook notification', { error });
      return false;
    }
  }
}

/**
 * Gets a color based on severity for Slack
 */
function getSeverityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
      return '#FF0000'; // Red
    case 'high':
      return '#FFA500'; // Orange
    case 'medium':
      return '#FFFF00'; // Yellow
    case 'low':
    default:
      return '#00FF00'; // Green
  }
}

/**
 * Gets a hex color based on severity for MS Teams
 */
function getSeverityHexColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'FF0000'; // Red without #
    case 'high':
      return 'FFA500'; // Orange without #
    case 'medium':
      return 'FFFF00'; // Yellow without #
    case 'low':
    default:
      return '00FF00'; // Green without #
  }
}

/**
 * Formats an HTML email with proper styling
 */
function formatHtmlEmail(data: NotificationData): string {
  const severityColor = getSeverityColor(data.severity);
  
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #f0f0f0; padding: 10px; border-radius: 5px; }
        .severity { display: inline-block; padding: 5px 10px; border-radius: 3px; font-weight: bold; color: white; background-color: ${severityColor}; }
        .details { margin-top: 20px; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }
        .footer { margin-top: 20px; font-size: 12px; color: #777; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h2>${data.title}</h2>
          <div class="severity">${data.severity.toUpperCase()}</div>
          <p>Scan Type: ${data.scanType}</p>
        </div>
        <div class="details">
          ${data.message.replace(/\n/g, '<br>')}
        </div>
        ${formatMetadataHtml(data.metadata)}
        <div class="footer">
          <p>This is an automated notification from the Technology Currency Management Tool.</p>
          <p>Timestamp: ${new Date().toISOString()}</p>
        </div>
      </div>
    </body>
    </html>
  `;
}

/**
 * Formats metadata as HTML
 */
function formatMetadataHtml(metadata?: Record<string, any>): string {
  if (!metadata || Object.keys(metadata).length === 0) {
    return '';
  }
  
  let html = '<div class="details"><h3>Additional Information</h3><ul>';
  
  for (const [key, value] of Object.entries(metadata)) {
    html += `<li><strong>${key}:</strong> ${value}</li>`;
  }
  
  html += '</ul></div>';
  return html;
}

/**
 * Gets all configured notification channels
 */
function getNotificationChannels(): NotificationChannel[] {
  return [
    new EmailNotificationChannel(),
    new SlackNotificationChannel(),
    new TeamsNotificationChannel(),
    new WebhookNotificationChannel()
  ].filter(channel => channel.enabled);
}

/**
 * Notifies about outdated technologies
 */
export async function notifyOutdatedTechnologies(
  technologies: OutdatedTechnology[],
  scanType: string
): Promise<void> {
  try {
    if (technologies.length === 0) {
      return;
    }
    
    // Check notification thresholds
    const { severityThreshold } = config.notifications;
    const severitiesToNotify = getSeveritiesToNotify(severityThreshold);
    
    // Filter technologies by severity threshold
    const filteredTechnologies = technologies.filter(tech => 
      severitiesToNotify.includes(tech.severity)
    );
    
    if (filteredTechnologies.length === 0) {
      log.debug('No technologies meet the notification severity threshold');
      return;
    }
    
    // Group technologies by severity for better reporting
    const groupedBySeverity = groupBySeverity(filteredTechnologies);
    
    // Create notification data
    const data: NotificationData = {
      title: `${filteredTechnologies.length} outdated technologies detected`,
      message: formatOutdatedTechnologiesMessage(groupedBySeverity),
      severity: getHighestSeverity(filteredTechnologies),
      scanType,
      metadata: {
        'Total Found': technologies.length,
        'Notified': filteredTechnologies.length,
        'Critical': groupedBySeverity.critical?.length || 0,
        'High': groupedBySeverity.high?.length || 0,
        'Medium': groupedBySeverity.medium?.length || 0,
        'Low': groupedBySeverity.low?.length || 0
      }
    };
    
    // Send notifications
    await sendNotifications(data);
  } catch (error) {
    log.error('Error sending outdated technologies notifications', { error });
  }
}

/**
 * Notifies about outdated dependencies
 */
export async function notifyOutdatedDependencies(
  dependencies: OutdatedDependency[]
): Promise<void> {
  try {
    if (dependencies.length === 0) {
      return;
    }
    
    // Check notification thresholds
    const { severityThreshold } = config.notifications;
    const severitiesToNotify = getSeveritiesToNotify(severityThreshold);
    
    // Filter dependencies by severity threshold
    const filteredDependencies = dependencies.filter(dep => 
      severitiesToNotify.includes(dep.severity)
    );
    
    if (filteredDependencies.length === 0) {
      log.debug('No dependencies meet the notification severity threshold');
      return;
    }
    
    // Group dependencies by severity for better reporting
    const groupedBySeverity = groupBySeverity(filteredDependencies);
    
    // Create notification data
    const data: NotificationData = {
      title: `${filteredDependencies.length} outdated dependencies detected`,
      message: formatOutdatedDependenciesMessage(groupedBySeverity),
      severity: getHighestSeverity(filteredDependencies),
      scanType: 'dependency',
      metadata: {
        'Total Found': dependencies.length,
        'Notified': filteredDependencies.length,
        'Critical': groupedBySeverity.critical?.length || 0,
        'High': groupedBySeverity.high?.length || 0,
        'Medium': groupedBySeverity.medium?.length || 0,
        'Low': groupedBySeverity.low?.length || 0
      }
    };
    
    // Send notifications
    await sendNotifications(data);
  } catch (error) {
    log.error('Error sending outdated dependencies notifications', { error });
  }
}

/**
 * Notifies about security vulnerabilities
 */
export async function notifySecurityVulnerabilities(
  vulnerabilities: SecurityVulnerability[]
): Promise<void> {
  try {
    if (vulnerabilities.length === 0) {
      return;
    }
    
    // Check notification thresholds
    const { severityThreshold } = config.notifications;
    const severitiesToNotify = getSeveritiesToNotify(severityThreshold);
    
    // Filter vulnerabilities by severity threshold
    const filteredVulnerabilities = vulnerabilities.filter(vuln => 
      severitiesToNotify.includes(vuln.severity)
    );
    
    if (filteredVulnerabilities.length === 0) {
      log.debug('No vulnerabilities meet the notification severity threshold');
      return;
    }
    
    // Group vulnerabilities by severity for better reporting
    const groupedBySeverity = groupBySeverity(filteredVulnerabilities);
    
    // Create notification data
    const data: NotificationData = {
      title: `${filteredVulnerabilities.length} security vulnerabilities detected`,
      message: formatSecurityVulnerabilitiesMessage(groupedBySeverity),
      severity: getHighestSeverity(filteredVulnerabilities),
      scanType: 'security',
      metadata: {
        'Total Found': vulnerabilities.length,
        'Notified': filteredVulnerabilities.length,
        'Critical': groupedBySeverity.critical?.length || 0,
        'High': groupedBySeverity.high?.length || 0,
        'Medium': groupedBySeverity.medium?.length || 0,
        'Low': groupedBySeverity.low?.length || 0,
        'Exploitable': filteredVulnerabilities.filter(v => v.exploitAvailable).length
      }
    };
    
    // Send notifications
    await sendNotifications(data);
  } catch (error) {
    log.error('Error sending security vulnerability notifications', { error });
  }
}

/**
 * Notifies about outdated browser extensions
 */
export async function notifyOutdatedExtensions(
  extensions: OutdatedExtension[]
): Promise<void> {
  try {
    if (extensions.length === 0) {
      return;
    }
    
    // Check notification thresholds
    const { severityThreshold } = config.notifications;
    const severitiesToNotify = getSeveritiesToNotify(severityThreshold);
    
    // Filter extensions by severity threshold
    const filteredExtensions = extensions.filter(ext => 
      severitiesToNotify.includes(ext.severity)
    );
    
    if (filteredExtensions.length === 0) {
      log.debug('No browser extensions meet the notification severity threshold');
      return;
    }
    
    // Group extensions by severity for better reporting
    const groupedBySeverity = groupBySeverity(filteredExtensions);
    
    // Create notification data
    const data: NotificationData = {
      title: `${filteredExtensions.length} outdated browser extensions detected`,
      message: formatOutdatedExtensionsMessage(groupedBySeverity),
      severity: getHighestSeverity(filteredExtensions),
      scanType: 'extension',
      metadata: {
        'Total Found': extensions.length,
        'Notified': filteredExtensions.length,
        'Critical': groupedBySeverity.critical?.length || 0,
        'High': groupedBySeverity.high?.length || 0,
        'Medium': groupedBySeverity.medium?.length || 0,
        'Low': groupedBySeverity.low?.length || 0,
        'With Security Issues': filteredExtensions.filter(e => e.hasSecurityIssues).length,
        'With Compatibility Issues': filteredExtensions.filter(e => e.hasCompatibilityIssues).length,
        'Deprecated': filteredExtensions.filter(e => e.isDeprecated).length
      }
    };
    
    // Send notifications
    await sendNotifications(data);
  } catch (error) {
    log.error('Error sending outdated extensions notifications', { error });
  }
}

/**
 * Sends notifications through all enabled channels
 */
async function sendNotifications(data: NotificationData): Promise<void> {
  const channels = getNotificationChannels();
  
  if (channels.length === 0) {
    log.warn('No notification channels enabled');
    return;
  }
  
  log.info(`Sending notifications via ${channels.length} channels`);
  
  const results = await Promise.all(
    channels.map(channel => {
      log.debug(`Sending notification via ${channel.name}`);
      return channel.send(data).catch(error => {
        log.error(`Error sending notification via ${channel.name}`, { error });
        return false;
      });
    })
  );
  
  const successCount = results.filter(Boolean).length;
  log.info(`Notifications sent successfully to ${successCount}/${channels.length} channels`);
}

/**
 * Gets severities to notify based on the threshold
 */
function getSeveritiesToNotify(threshold: string): Array<'low' | 'medium' | 'high' | 'critical'> {
  switch (threshold.toLowerCase()) {
    case 'critical':
      return ['critical'];
    case 'high':
      return ['critical', 'high'];
    case 'medium':
      return ['critical', 'high', 'medium'];
    case 'low':
    default:
      return ['critical', 'high', 'medium', 'low'];
  }
}

/**
 * Gets the highest severity from a list of items
 */
function getHighestSeverity<T extends { severity: 'low' | 'medium' | 'high' | 'critical' }>(
  items: T[]
): 'low' | 'medium' | 'high' | 'critical' {
  if (items.some(item => item.severity === 'critical')) return 'critical';
  if (items.some(item => item.severity === 'high')) return 'high';
  if (items.some(item => item.severity === 'medium')) return 'medium';
  return 'low';
}

/**
 * Groups items by severity
 */
function groupBySeverity<T extends { severity: 'low' | 'medium' | 'high' | 'critical' }>(
  items: T[]
): Record<'low' | 'medium' | 'high' | 'critical', T[]> {
  return {
    critical: items.filter(item => item.severity === 'critical'),
    high: items.filter(item => item.severity === 'high'),
    medium: items.filter(item => item.severity === 'medium'),
    low: items.filter(item => item.severity === 'low')
  };
}

/**
 * Formats a message for outdated technologies
 */
function formatOutdatedTechnologiesMessage(
  groupedBySeverity: Record<'low' | 'medium' | 'high' | 'critical', OutdatedTechnology[]>
): string {
  let message = 'Outdated technologies detected:\n\n';
  
  // Format each severity group
  for (const severity of ['critical', 'high', 'medium', 'low'] as const) {
    const technologies = groupedBySeverity[severity];
    if (technologies && technologies.length > 0) {
      message += `${severity.toUpperCase()} Severity (${technologies.length}):\n`;
      
      for (const tech of technologies) {
        message += `- ${tech.technology}: ${tech.message}\n`;
        message += `  File: ${tech.filePath}${tech.lineNumber ? ` (line ${tech.lineNumber})` : ''}\n`;
        message += `  Recommended: ${tech.recommendedVersion}\n`;
        message += `  Remediation: ${tech.remediationSteps}\n\n`;
      }
    }
  }
  
  return message;
}

/**
 * Formats a message for outdated dependencies
 */
function formatOutdatedDependenciesMessage(
  groupedBySeverity: Record<'low' | 'medium' | 'high' | 'critical', OutdatedDependency[]>
): string {
  let message = 'Outdated dependencies detected:\n\n';
  
  // Format each severity group
  for (const severity of ['critical', 'high', 'medium', 'low'] as const) {
    const dependencies = groupedBySeverity[severity];
    if (dependencies && dependencies.length > 0) {
      message += `${severity.toUpperCase()} Severity (${dependencies.length}):\n`;
      
      for (const dep of dependencies) {
        message += `- ${dep.name}: ${dep.currentVersion} → ${dep.latestVersion}`;
        if (dep.isDeprecated) message += ' (DEPRECATED)';
        message += '\n';
        message += `  Package Manager: ${dep.packageManager}\n`;
        message += `  File: ${dep.filePath}\n`;
        message += `  Remediation: ${dep.remediationSteps}\n\n`;
      }
    }
  }
  
  return message;
}

/**
 * Formats a message for security vulnerabilities
 */
function formatSecurityVulnerabilitiesMessage(
  groupedBySeverity: Record<'low' | 'medium' | 'high' | 'critical', SecurityVulnerability[]>
): string {
  let message = 'Security vulnerabilities detected:\n\n';
  
  // Format each severity group
  for (const severity of ['critical', 'high', 'medium', 'low'] as const) {
    const vulnerabilities = groupedBySeverity[severity];
    if (vulnerabilities && vulnerabilities.length > 0) {
      message += `${severity.toUpperCase()} Severity (${vulnerabilities.length}):\n`;
      
      for (const vuln of vulnerabilities) {
        message += `- ${vuln.title}${vuln.exploitAvailable ? ' (EXPLOIT AVAILABLE)' : ''}\n`;
        message += `  ID: ${vuln.id}\n`;
        message += `  Package: ${vuln.packageName}@${vuln.version}\n`;
        message += `  Fixed in: ${vuln.fixedIn || 'Unknown'}\n`;
        message += `  CVE: ${vuln.cve.join(', ') || 'N/A'}\n`;
        message += `  Remediation: ${vuln.remediationSteps}\n\n`;
      }
    }
  }
  
  return message;
}

/**
 * Formats a message for outdated browser extensions
 */
function formatOutdatedExtensionsMessage(
  groupedBySeverity: Record<'low' | 'medium' | 'high' | 'critical', OutdatedExtension[]>
): string {
  let message = 'Outdated browser extensions detected:\n\n';
  
  // Format each severity group
  for (const severity of ['critical', 'high', 'medium', 'low'] as const) {
    const extensions = groupedBySeverity[severity];
    if (extensions && extensions.length > 0) {
      message += `${severity.toUpperCase()} Severity (${extensions.length}):\n`;
      
      for (const ext of extensions) {
        message += `- ${ext.name} (${ext.browser}): ${ext.currentVersion} → ${ext.latestVersion}`;
        if (ext.isDeprecated) message += ' (DEPRECATED)';
        if (ext.hasSecurityIssues) message += ' (SECURITY ISSUES)';
        if (ext.hasCompatibilityIssues) message += ' (COMPATIBILITY ISSUES)';
        message += '\n';
        if (ext.updateUrl) {
          message += `  Update URL: ${ext.updateUrl}\n`;
        }
        message += '\n';
      }
    }
  }
  
  return message;
}
