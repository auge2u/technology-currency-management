import 'express-async-errors';
import dotenv from 'dotenv';
import { setupServer } from './server';
import { setupScheduler } from './core/services/schedule-service';
import { log } from './utils/logging';
import { setupTelemetry } from './utils/telemetry';
import config from './config';

// Load environment variables
dotenv.config();

// Initialize telemetry if enabled
if (config.telemetry.enabled) {
  setupTelemetry('tcms-api');
}

async function start() {
  try {
    // Start the express server
    const server = setupServer();
    
    // Start the scheduler for periodic scans and tasks
    await setupScheduler();
    
    const port = config.server.port;
    server.listen(port, () => {
      log.info(`Server is running on port ${port}`);
      log.info(`Environment: ${config.environment}`);
      log.info(`API documentation available at ${config.server.apiPrefix}/docs`);
    });
    
    // Handle graceful shutdown
    const shutdown = async () => {
      log.info('Shutting down server...');
      server.close(() => {
        log.info('Server stopped');
        process.exit(0);
      });
    };
    
    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
    
  } catch (error) {
    log.error('Failed to start server:', { error: error instanceof Error ? error.message : String(error) });
    process.exit(1);
  }
}

// Start the application
start();
