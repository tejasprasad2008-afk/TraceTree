import fs from 'node:fs/promises';
import path from 'node:path';
import { logger } from './index.js';

const SESSIONS_DIR = path.join(process.cwd(), '.openclue', 'sessions');

/**
 * Ensures the persistence directory exists.
 */
async function ensureDir() {
  try {
    await fs.mkdir(SESSIONS_DIR, { recursive: true });
  } catch (error) {
    // If we can't create the directory, we'll handle it during write
  }
}

/**
 * Saves a session state to the local filesystem.
 */
export async function saveSession(sessionId: string, data: any): Promise<string | null> {
  await ensureDir();
  const filePath = path.join(SESSIONS_DIR, `${sessionId}.json`);
  
  try {
    await fs.writeFile(filePath, JSON.stringify(data, null, 2));
    return filePath;
  } catch (error: any) {
    logger.error('persistence', `Failed to save session ${sessionId} to disk.`, error);
    console.log('\n--- CRITICAL: SESSION DATA DUMP ---');
    console.log(JSON.stringify(data, null, 2));
    console.log('--- END DATA DUMP ---\n');
    return null;
  }
}

/**
 * Loads a session state from the local filesystem.
 */
export async function loadSession(sessionId: string): Promise<any | null> {
  const filePath = path.join(SESSIONS_DIR, `${sessionId}.json`);
  
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    return JSON.parse(content);
  } catch (error: any) {
    logger.error('persistence', `Failed to load session ${sessionId}`, error);
    return null;
  }
}

/**
 * Cleans up a session file.
 */
export async function deleteSession(sessionId: string): Promise<void> {
  const filePath = path.join(SESSIONS_DIR, `${sessionId}.json`);
  try {
    await fs.unlink(filePath);
  } catch (error) {
    // Ignore cleanup errors
  }
}
