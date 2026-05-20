import Fastify from 'fastify';
import fastifyWebsocket from '@fastify/websocket';
import fastifyCors from '@fastify/cors';
import { nanoid } from 'nanoid';
import 'dotenv/config';

import { OpenClueEngine } from './engine/index.js';
import { createLLMProvider } from './llm/index.js';
import { SessionStore } from './store/index.js';
import { logger } from './utils/index.js';
import { User, AuditLogEntry } from './types/index.js';

const fastify = Fastify({ logger: true });
const store = new SessionStore();
const llm = createLLMProvider();
const engine = new OpenClueEngine(llm, store);

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
fastify.get('/health', async () => ({ status: 'UP', engine: 'OpenClue v0.2.0' }));

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
