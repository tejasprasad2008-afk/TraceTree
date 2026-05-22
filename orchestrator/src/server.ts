import Fastify from 'fastify';
import fastifyWebsocket from '@fastify/websocket';
import fastifyCors from '@fastify/cors';
import { nanoid } from 'nanoid';
import 'dotenv/config';

import { TraceTreeEngine } from './engine/index.js';
import { createLLMProvider } from './llm/index.js';
import { SessionStore } from './store/index.js';
import { logger } from './utils/index.js';
import { AuditLogEntry } from './types/index.js';

const fastify = Fastify({ logger: true });
const store = new SessionStore();
const llm = createLLMProvider();
const engine = new TraceTreeEngine(llm, store);

// --- Middleware & Plugins ---
fastify.register(fastifyCors, { origin: "*" });
fastify.register(fastifyWebsocket);

// Real-time Event Broadcast System
const connections = new Set<any>();

const broadcast = (event: string, payload: any) => {
  const message = JSON.stringify({ event, payload });
  for (const conn of connections) {
    conn.socket.send(message);
  }
};

// Inject broadcast into engine (refactored engine will use this)
(engine as any).onEvent = broadcast;

// --- API Routes ---

/**
 * Health Check
 */
fastify.get('/health', async () => ({ status: 'UP', engine: 'TraceTree v0.2.0' }));

/**
 * Start Investigation
 * POST /api/investigate
 */
fastify.post('/api/investigate', async (request, reply) => {
  const { prompt, userId } = request.body as { prompt: string; userId: string };
  
  try {
    const summary = await engine.investigate(prompt);
    broadcast('investigation_started', { prompt, userId });
    return summary;
  } catch (error: any) {
    fastify.log.error(error);
    reply.status(500).send({ error: 'Investigation failed' });
  }
});

/**
 * Background AI summary generation for CLI telemetry findings
 */
const generateAISummary = async (findingsStr: string) => {
  try {
    logger.info('server', 'Starting background AI summary generation via Ollama...');
    broadcast('ai_summary_started', {});
    
    let findings: any = {};
    try {
      findings = JSON.parse(findingsStr);
    } catch (e) {
      findings = { raw: findingsStr };
    }

    const messages = [
      {
        role: 'system' as const,
        content: 'You are a DevSecOps AI Assistant. Analyze the following sandbox analysis findings for a package/target. ' +
          'In exactly one concise paragraph (3-5 sentences), summarize what the package/target does, highlight any specific suspicious behaviors, signatures, or YARA matches, and state your final verdict on whether it is malicious or clean, and why. ' +
          'Do NOT use bullet points, numbered lists, or headers. Write ONLY the single paragraph.'
      },
      {
        role: 'user' as const,
        content: JSON.stringify({
          target: findings.pid,
          target_type: findings.target_type || 'unknown',
          verdict: findings.is_malicious ? 'MALICIOUS' : 'CLEAN',
          confidence: findings.confidence_score,
          total_severity: findings.total_severity,
          flagged_behaviors: findings.flagged_behaviors,
          behavioral_signatures: findings.behavioral_signatures,
          yara_matches: findings.yara_matches,
          suspicious_ngrams: findings.suspicious_ngrams,
          network_destinations: findings.network_destinations
        })
      }
    ];

    logger.info('server', 'Sending prompt to Ollama model ' + (process.env.OLLAMA_MODEL || 'qwen2.5-coder:7b') + '...');
    const response = await llm.generateCompletion(messages, { maxTokens: 300, temperature: 0.3 });
    let summary = response.content.trim();
    
    // Post-process to guarantee exactly one paragraph and strip bullet/numbered list artifacts
    summary = summary
      .split('\n')
      .map(line => {
        let clean = line.trim();
        if (clean.startsWith('#')) return '';
        clean = clean.replace(/^[\s\-*+•]+/, '');
        clean = clean.replace(/^\d+[\.\)]\s*/, '');
        return clean.trim();
      })
      .filter(line => line.length > 0)
      .join(' ');
      
    summary = summary.replace(/\s+/g, ' ').trim();
    
    logger.info('server', `AI summary completed successfully: "${summary}"`);
    broadcast('ai_summary_completed', { summary });
  } catch (error) {
    logger.error('server', 'Failed to generate AI summary: ' + error);
    broadcast('ai_summary_completed', { summary: 'Error generating AI summary: ' + (error as Error).message });
  }
};

/**
 * Broadcast Telemetry from CLI
 * POST /api/telemetry
 */
fastify.post('/api/telemetry', async (request, reply) => {
  const { event, payload } = request.body as { event: string; payload: any };
  
  try {
    broadcast(event, payload);

    // If findings are received, trigger the background AI summary generator
    if (event === 'step_completed' && payload?.findings) {
      generateAISummary(payload.findings).catch((err) => {
        fastify.log.error(err);
      });
    }

    return { status: 'OK' };
  } catch (error: any) {
    fastify.log.error(error);
    reply.status(500).send({ error: 'Failed to broadcast telemetry' });
  }
});


/**
 * HITL Approval
 * POST /api/approve
 */
fastify.post('/api/approve', async (request, reply) => {
  const { sessionId, approved, reasoning, userId, role } = request.body as { 
    sessionId: string; 
    approved: boolean; 
    reasoning: string;
    userId: string;
    role: string;
  };

  // RBAC Check
  if (role !== 'ADMINISTRATOR') {
    return reply.status(403).send({ error: 'Forbidden: Only Administrators can approve destructive actions' });
  }

  try {
    const session = store.getSession(sessionId);
    if (!session) return reply.status(404).send({ error: 'Session not found' });

    // Audit Logging
    const auditEntry: AuditLogEntry = {
      id: nanoid(),
      sessionId,
      userId,
      action: approved ? 'APPROVED_DESTRUCTIVE_STEP' : 'DENIED_DESTRUCTIVE_STEP',
      timestamp: new Date().toISOString(),
      reasoning
    };
    store.logAction(auditEntry);

    // Resume Engine
    const result = await engine.resumeWithApproval(sessionId, approved, reasoning);
    broadcast('hitl_resolved', { sessionId, approved, userId });
    
    return result;
  } catch (error: any) {
    fastify.log.error(error);
    reply.status(500).send({ error: 'Approval processing failed' });
  }
});

// --- WebSocket Gateway ---
fastify.register(async (fastify) => {
  fastify.get('/ws/live', { websocket: true }, (connection, req) => {
    connections.add(connection);
    logger.info('server', 'New collaborative client connected');

    connection.socket.on('close', () => {
      connections.delete(connection);
      logger.info('server', 'Collaborative client disconnected');
    });
  });
});

// --- Start Server ---
const start = async () => {
  try {
    const port = Number(process.env.PORT) || 3000;
    await fastify.listen({ port, host: '0.0.0.0' });
    logger.info('server', `TraceTree Unified Server running on port ${port}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
