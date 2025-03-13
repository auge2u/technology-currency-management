import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

interface IConfig {
  environment: string;
  server: {
    port: number;
    apiPrefix: string;
    clientUrl: string;
  };
  database: {
    url: string;
  };
  auth: {
    jwtSecret: string;
    jwtExpiresIn: string;
  };
  github: {
    apiUrl: string;
    token: string;
  };
  snyk: {
    token: string;
    apiUrl: string;
  };
  sonarqube: {
    url: string;
    token: string;
  };
  notifications: {
    slack: {
      webhookUrl: string;
    };
    teams: {
      webhookUrl: string;
    };
  };
  logging: {
    level: string;
  };
  security: {
    corsOrigins: string[];
    rateLimitWindowMs: number;
    rateLimitMax: number;
  };
  cache: {
    redisUrl: string;
  };
  scanning: {
    cronSchedule: string;
    timeoutMs: number;
    extension: {
      enabled: boolean;
      compatibilityCheckUrl: string;
    };
  };
  telemetry: {
    enabled: boolean;
    metricsPort: number;
  };
}

const config: IConfig = {
  environment: process.env.NODE_ENV || 'development',
  server: {
    port: parseInt(process.env.PORT || '3000', 10),
    apiPrefix: process.env.API_PREFIX || '/api/v1',
    clientUrl: process.env.CLIENT_URL || 'http://localhost:3001',
  },
  database: {
    url: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/tcms_dev',
  },
  auth: {
    jwtSecret: process.env.JWT_SECRET || 'dev-jwt-secret',
    jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1d',
  },
  github: {
    apiUrl: process.env.GITHUB_API_URL || 'https://api.github.com',
    token: process.env.GITHUB_TOKEN || '',
  },
  snyk: {
    token: process.env.SNYK_TOKEN || '',
    apiUrl: process.env.SNYK_API_URL || 'https://snyk.io/api/v1',
  },
  sonarqube: {
    url: process.env.SONARQUBE_URL || 'http://localhost:9000',
    token: process.env.SONARQUBE_TOKEN || '',
  },
  notifications: {
    slack: {
      webhookUrl: process.env.SLACK_WEBHOOK_URL || '',
    },
    teams: {
      webhookUrl: process.env.TEAMS_WEBHOOK_URL || '',
    },
  },
  logging: {
    level: process.env.LOG_LEVEL || 'info',
  },
  security: {
    corsOrigins: (process.env.CORS_ORIGINS || 'http://localhost:3001').split(','),
    rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 minutes
    rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX || '100', 10),
  },
  cache: {
    redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  },
  scanning: {
    cronSchedule: process.env.SCAN_CRON_SCHEDULE || '0 0 * * *', // Daily at midnight
    timeoutMs: parseInt(process.env.SCAN_TIMEOUT_MS || '300000', 10), // 5 minutes
    extension: {
      enabled: process.env.EXTENSION_SCAN_ENABLED === 'true',
      compatibilityCheckUrl: process.env.EXTENSION_COMPATIBILITY_CHECK_URL || '',
    },
  },
  telemetry: {
    enabled: process.env.METRICS_ENABLED === 'true',
    metricsPort: parseInt(process.env.METRICS_PORT || '9090', 10),
  },
};

// Validate essential configuration
if (config.environment === 'production') {
  // In production, these values must be set
  const requiredEnvVars = [
    'JWT_SECRET',
    'DATABASE_URL',
  ];

  for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
      throw new Error(`Environment variable ${envVar} is required in production mode`);
    }
  }
}

export default config;
