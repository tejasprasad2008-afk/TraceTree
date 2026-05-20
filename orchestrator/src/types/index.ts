/**
 * Unified TraceTree & OpenClue Type Definitions
 * Enterprise-grade multi-user support.
 */

export type UserRole = 'ANALYST' | 'ADMINISTRATOR';

export interface User {
  id: string;
  username: string;
  role: UserRole;
}

export type TriageDisposition = 
  | 'FALSE_POSITIVE' 
  | 'TRUE_POSITIVE' 
  | 'MALICIOUS' 
  | 'EXPECTED_BEHAVIOR';

/**
 * Low-level TraceTree Telemetry Primitives
 */
export interface TelemetryEvent {
  id: string;
  type: 'ebpf_syscall' | 'process_spawn' | 'network_flow' | 'file_mod';
  timestamp: string;
  pid?: number;
  comm?: string;
  source?: string;
  payload: Record<string, any>;
}

/**
 * Audit Logging for RBAC Compliance
 */
export interface AuditLogEntry {
  id: string;
  sessionId: string;
  userId: string;
  action: string;
  timestamp: string;
  reasoning?: string;
  metadata?: Record<string, any>;
}

export type InvestigationPhase = 'triage' | 'planning' | 'execution' | 'synthesis';
export type SessionStatus = 'ACTIVE' | 'HITL_PENDING' | 'COMPLETED' | 'FAILED';

export interface InvestigationStep {
  id: string;
  title: string;
  description: string;
  tool: string;
  parameters: Record<string, any>;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'blocked';
  dependsOn?: string[];
  isDestructive?: boolean;
}

export interface InvestigationPlan {
  id: string;
  prompt: string;
  steps: InvestigationStep[];
  findings: any[];
  status: SessionStatus;
  phase: InvestigationPhase;
  createdAt: string;
  updatedAt: string;
}

export interface HITLState {
  sessionId: string;
  stepId: string;
  toolCall: { name: string; arguments: any };
  requestedAt: string;
  requesterReasoning: string;
  status: 'PENDING' | 'APPROVED' | 'DENIED';
}

export interface InvestigationSummary {
  sessionId: string;
  verdict: TriageDisposition;
  summary: string; // Markdown
  timeline: any[];
  durationMs: number;
}

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: any;
  serverId: string;
}

export interface ToolCall {
  name: string;
  arguments: any;
}

export interface ToolResponse {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

export interface MCPServerConfig {
  id: string;
  type: 'stdio' | 'websocket';
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
}
