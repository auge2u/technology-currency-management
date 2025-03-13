import fs from 'fs/promises';
import path from 'path';
import { log } from '../../utils/logging';
import { TechnologyRule, defaultTechnologyRules } from './technology-rules';
import config from '../../config';

/**
 * Loads all technology rules from various sources
 * - Default built-in rules
 * - User-defined custom rules
 * - Organization rules from the rules directory
 */
export async function loadAllTechnologyRules(): Promise<TechnologyRule[]> {
  try {
    const rules: TechnologyRule[] = [];
    
    // Load default rules
    rules.push(...defaultTechnologyRules.filter(rule => rule.enabled));
    log.debug(`Loaded ${rules.length} default technology rules`);
    
    // Load custom rules from configuration
    if (config.rules && config.rules.customRulesPath) {
      const customRules = await loadCustomRules(config.rules.customRulesPath);
      // Filter out duplicates by id
      const customRuleIds = new Set(customRules.map(rule => rule.id));
      rules.push(...customRules);
      log.debug(`Loaded ${customRules.length} custom rules from ${config.rules.customRulesPath}`);
    }
    
    // Apply rule overrides from configuration
    if (config.rules && config.rules.overrides) {
      applyRuleOverrides(rules, config.rules.overrides);
      log.debug('Applied rule overrides from configuration');
    }
    
    return rules;
  } catch (error) {
    log.error('Error loading technology rules', { error });
    // Fallback to default rules if loading fails
    return defaultTechnologyRules.filter(rule => rule.enabled);
  }
}

/**
 * Loads custom rules from a directory or file
 */
async function loadCustomRules(rulesPath: string): Promise<TechnologyRule[]> {
  try {
    const stats = await fs.stat(rulesPath);
    
    if (stats.isDirectory()) {
      // Load all .json and .js files in the directory
      const files = await fs.readdir(rulesPath);
      const ruleFiles = files.filter(file => {
        const ext = path.extname(file).toLowerCase();
        return ext === '.json' || ext === '.js';
      });
      
      const allRules: TechnologyRule[] = [];
      
      for (const file of ruleFiles) {
        try {
          const filePath = path.join(rulesPath, file);
          const rules = await loadRulesFromFile(filePath);
          allRules.push(...rules);
        } catch (fileError) {
          log.warn(`Error loading rules from ${file}`, { error: fileError });
        }
      }
      
      return allRules;
    } else {
      // Load rules from a single file
      return loadRulesFromFile(rulesPath);
    }
  } catch (error) {
    log.error(`Error loading custom rules from ${rulesPath}`, { error });
    return [];
  }
}

/**
 * Loads rules from a file
 */
async function loadRulesFromFile(filePath: string): Promise<TechnologyRule[]> {
  try {
    const ext = path.extname(filePath).toLowerCase();
    
    if (ext === '.json') {
      // Load JSON rules
      const content = await fs.readFile(filePath, 'utf-8');
      const data = JSON.parse(content);
      
      // Handle both array and object with rules property
      const rules = Array.isArray(data) ? data : data.rules || [];
      
      // Validate rules
      return rules.filter(rule => validateRule(rule));
    } else if (ext === '.js') {
      // Load JavaScript rules (using dynamic import)
      try {
        // Convert to absolute path for dynamic import
        const absolutePath = path.resolve(filePath);
        const module = await import(absolutePath);
        
        // Handle both default export and named export
        const rules = module.default || module.rules || [];
        
        // Validate rules
        return Array.isArray(rules) ? rules.filter(rule => validateRule(rule)) : [];
      } catch (importError) {
        log.error(`Error importing rules module ${filePath}`, { error: importError });
        return [];
      }
    } else {
      log.warn(`Unsupported rule file format: ${filePath}`);
      return [];
    }
  } catch (error) {
    log.error(`Error loading rules from file ${filePath}`, { error });
    return [];
  }
}

/**
 * Validates a technology rule
 */
function validateRule(rule: any): boolean {
  // Check required fields
  const requiredFields = [
    'id', 'name', 'description', 'technology', 
    'severity', 'message', 'recommendedVersion', 'remediationSteps'
  ];
  
  for (const field of requiredFields) {
    if (!rule[field]) {
      log.warn(`Rule missing required field: ${field}`, { rule: rule.id || 'unknown' });
      return false;
    }
  }
  
  // Check that at least one pattern is defined
  if (!rule.filePattern && !rule.fileNamePattern && !rule.contentPattern) {
    log.warn(
      'Rule must define at least one pattern: filePattern, fileNamePattern, or contentPattern',
      { rule: rule.id }
    );
    return false;
  }
  
  // Check severity is valid
  const validSeverities = ['low', 'medium', 'high', 'critical'];
  if (!validSeverities.includes(rule.severity)) {
    log.warn(`Rule has invalid severity: ${rule.severity}`, { rule: rule.id });
    return false;
  }
  
  return true;
}

/**
 * Applies rule overrides from configuration
 */
function applyRuleOverrides(rules: TechnologyRule[], overrides: Record<string, Partial<TechnologyRule>>) {
  for (const [ruleId, override] of Object.entries(overrides)) {
    const ruleIndex = rules.findIndex(rule => rule.id === ruleId);
    
    if (ruleIndex !== -1) {
      // Apply overrides to the rule
      rules[ruleIndex] = { ...rules[ruleIndex], ...override };
      log.debug(`Applied override to rule ${ruleId}`);
    } else {
      log.warn(`Attempted to override non-existent rule: ${ruleId}`);
    }
  }
}

/**
 * Gets a single technology rule by ID
 */
export async function getTechnologyRuleById(ruleId: string): Promise<TechnologyRule | null> {
  const rules = await loadAllTechnologyRules();
  return rules.find(rule => rule.id === ruleId) || null;
}
