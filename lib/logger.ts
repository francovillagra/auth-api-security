import winston from 'winston';

const { combine, timestamp, printf, colorize, errors } = winston.format;

const logFormat = printf(({ level, message, timestamp, stack }) => {
  return `${timestamp} [${level}]: ${stack || message}`;
});

/**
 * Winston logger instance.
 * - Development: `debug` level, colorized console output.
 * - Production: `info` level, plain console output.
 */
export const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: combine(
    errors({ stack: true }),
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    logFormat
  ),
  transports: [
    new winston.transports.Console({
      format: combine(colorize(), logFormat),
    }),
  ],
});

/** Typed convenience wrapper around the Winston logger. */
export const log = {
  info: (message: string) => logger.info(message),
  error: (message: string, error?: Error) => logger.error(message, error),
  warn: (message: string) => logger.warn(message),
  debug: (message: string) => logger.debug(message),
};
