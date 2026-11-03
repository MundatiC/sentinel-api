import 'dotenv/config';
import { createApp } from './app.js';
import { parseEnv } from './config/env.js';
import { createLogger } from './lib/logger.js';

const env = parseEnv(process.env);
const logger = createLogger(env);
const app = createApp(env, logger);

const server = app.listen(env.PORT, () => {
  logger.info(`sentinel-api listening on port ${env.PORT} (${env.NODE_ENV})`);
});

// Graceful shutdown: Docker sends SIGTERM on `docker stop`. We stop accepting new
// connections, let in-flight requests finish, then exit. A timer forces exit if stuck.
function shutdown(signal: string) {
  logger.info(`${signal} received, shutting down`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
