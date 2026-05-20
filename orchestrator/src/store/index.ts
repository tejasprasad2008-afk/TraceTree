import Database from 'better-sqlite3';
import { 
  InvestigationPlan, 
  AuditLogEntry, 
  HITLState 
} from '../types/index.js';
import { logger } from '../utils/index.js';

/**
 * Enterprise Session Store
 * Centralized, multi-user shared state using SQLite.
 */
export class SessionStore {
  private db: Database.Database;

  constructor(dbPath: string = 'tracetree.db') {
    this.db = new Database(dbPath);
    this.initializeSchema();
  }

  private initializeSchema() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        prompt TEXT,
        steps TEXT,
        findings TEXT,
        status TEXT,
        phase TEXT,
        createdAt TEXT,
        updatedAt TEXT
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        sessionId TEXT,
        userId TEXT,
        action TEXT,
        timestamp TEXT,
        reasoning TEXT,
        metadata TEXT
      );

      CREATE TABLE IF NOT EXISTS hitl_states (
        sessionId TEXT PRIMARY KEY,
        stepId TEXT,
        toolCall TEXT,
        requestedAt TEXT,
        requesterReasoning TEXT,
        status TEXT
      );
    `);
    logger.info('store', 'Database schema initialized');
  }

  // --- Session Methods ---

  saveSession(session: InvestigationPlan) {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO sessions (id, prompt, steps, findings, status, phase, createdAt, updatedAt)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      session.id,
      session.prompt,
      JSON.stringify(session.steps),
      JSON.stringify(session.findings),
      session.status,
      session.phase,
      session.createdAt,
      session.updatedAt
    );
  }

  getSession(id: string): InvestigationPlan | null {
    const row = this.db.prepare('SELECT * FROM sessions WHERE id = ?').get(id) as any;
    if (!row) return null;
    return {
      ...row,
      steps: JSON.parse(row.steps),
      findings: JSON.parse(row.findings)
    };
  }

  // --- HITL Methods ---

  saveHITL(hitl: HITLState) {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO hitl_states (sessionId, stepId, toolCall, requestedAt, requesterReasoning, status)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      hitl.sessionId,
      hitl.stepId,
      JSON.stringify(hitl.toolCall),
      hitl.requestedAt,
      hitl.requesterReasoning,
      hitl.status
    );
  }

  getHITL(sessionId: string): HITLState | null {
    const row = this.db.prepare('SELECT * FROM hitl_states WHERE sessionId = ?').get(sessionId) as any;
    if (!row) return null;
    return {
      ...row,
      toolCall: JSON.parse(row.toolCall)
    };
  }

  // --- Audit Logs ---

  logAction(entry: AuditLogEntry) {
    const stmt = this.db.prepare(`
      INSERT INTO audit_logs (id, sessionId, userId, action, timestamp, reasoning, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      entry.id,
      entry.sessionId,
      entry.userId,
      entry.action,
      entry.timestamp,
      entry.reasoning,
      JSON.stringify(entry.metadata || {})
    );
  }
}
