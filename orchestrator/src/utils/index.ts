import chalk from 'chalk';

/**
 * Centralized Logging for OpenClue.
 * Ensures every state transition and tool call is visible and debuggable.
 */
export const logger = {
  info: (phase: string, message: string, data?: any) => {
    console.log(`${chalk.blue(`[${new Date().toISOString()}]`)} ${chalk.green(`[${phase.toUpperCase()}]`)} ${message}`);
    if (data) console.dir(data, { depth: null });
  },
  warn: (phase: string, message: string, data?: any) => {
    console.log(`${chalk.yellow(`[${new Date().toISOString()}] [${phase.toUpperCase()}] WARN: ${message}`)}`);
    if (data) console.dir(data, { depth: null });
  },
  error: (phase: string, message: string, error: any) => {
    console.log(`${chalk.red(`[${new Date().toISOString()}] [${phase.toUpperCase()}] ERROR: ${message}`)}`);
    if (error) {
      if (error instanceof Error) {
        console.error(chalk.red(error.stack));
      } else {
        console.dir(error, { depth: null });
      }
    }
  },
  delta: (phase: string, memoryDiff: string) => {
    console.log(`${chalk.magenta(`[${new Date().toISOString()}] [${phase.toUpperCase()}] MEMORY DELTA:`)} ${memoryDiff}`);
  }
};

/**
 * Defensive execution wrapper.
 * Ensures a single tool failure doesn't crash the entire loop.
 */
export async function safeExecute<T>(
  taskName: string,
  fn: () => Promise<T>,
  onFailure?: (error: any) => void
): Promise<T | null> {
  try {
    return await fn();
  } catch (error) {
    logger.error('execution', `Failed task: ${taskName}`, error);
    if (onFailure) onFailure(error);
    return null;
  }
}
