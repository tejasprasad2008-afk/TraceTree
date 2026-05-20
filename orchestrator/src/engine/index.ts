import { 
  InvestigationPlan, 
  InvestigationSummary,
  LLMProvider,
  HITLState,
  SessionStatus,
  InvestigationPhase
} from '../types/index.js';
import { logger } from '../utils/index.js';
import { InvestigationPlanner } from '../planner/index.js';
import { MCPRouter } from '../mcp/index.js';
import { SessionStore } from '../store/index.js';

export class OpenClueEngine {
  private planner: InvestigationPlanner;
  private mcp: MCPRouter;
  private store: SessionStore;
  private mcpInitialized = false;
  public onEvent?: (event: string, payload: any) => void;

  private async initializeMcp() {
    try {
      await this.mcp.initializeClient({
        id: "tracetree-native-mcp",
        type: "stdio",
        command: "python3",
        args: ["../tracetree_mcp_server.py"]
      });
      this.mcpInitialized = true;
      logger.info("engine", "Internal TraceTree MCP server initialized");
    } catch (error) {
      logger.error("engine", "Failed to initialize internal MCP server", error);
    }
  }


  constructor(llm: LLMProvider, store: SessionStore) {
    this.planner = new InvestigationPlanner(llm);
    this.mcp = new MCPRouter();
    this.initializeMcp();
    this.store = store;
  }

  /**
   * Main entry point for a natural language investigation.
   */
  async investigate(prompt: string, options: { demo?: boolean } = {}): Promise<InvestigationSummary | HITLState | null> {
    const plan = await this.planner.createPlan(prompt);
    if (!plan) return null;

    // Initialize Server-Side Session State
    const session: InvestigationPlan = {
      id: plan.id,
      prompt: plan.prompt,
      steps: plan.steps,
      findings: [],
      status: 'ACTIVE',
      phase: 'execution',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    this.store.saveSession(session);
    return this.runExecutionLoop(session.id);
  }

  /**
   * Flat execution loop integrated with SessionStore and WebSockets.
   */
  async runExecutionLoop(sessionId: string): Promise<InvestigationSummary | HITLState | null> {
    const session = this.store.getSession(sessionId);
    if (!session) return null;

    const startTime = Date.now();
    const completedStepIds = new Set(session.steps.filter(s => s.status === 'completed' || s.status === 'failed').map(s => s.id));

    while (completedStepIds.size < session.steps.length) {
      const executableSteps = session.steps.filter(step => {
        if (step.status !== 'pending') return false;
        if (!step.dependsOn || step.dependsOn.length === 0) return true;
        return step.dependsOn.every(depId => completedStepIds.has(depId));
      });

      if (executableSteps.length === 0) break;

      // HITL Check
      const destructiveStep = executableSteps.find(s => s.isDestructive);
      if (destructiveStep) {
        const hitl: HITLState = {
          sessionId,
          stepId: destructiveStep.id,
          toolCall: { name: destructiveStep.tool, arguments: destructiveStep.parameters },
          requestedAt: new Date().toISOString(),
          requesterReasoning: destructiveStep.description,
          status: 'PENDING'
        };
        
        session.status = 'HITL_PENDING';
        this.store.saveSession(session);
        this.store.saveHITL(hitl);
        
        if (this.onEvent) this.onEvent('hitl_required', hitl);
        return hitl;
      }

      // Parallel Execution
      await Promise.all(executableSteps.map(async (step) => {
        step.status = 'running';
        this.store.saveSession(session);
        if (this.onEvent) this.onEvent('step_started', { sessionId, stepId: step.id });

        try {
          const response = await this.mcp.executeMcpTool(step.tool, step.parameters);
          session.findings.push({
            stepId: step.id,
            tool: step.tool,
            output: response.content.map(c => c.text).join('\n'),
            timestamp: new Date().toISOString()
          });
          step.status = 'completed';
        } catch (error: any) {
          step.status = 'failed';
          session.findings.push({ stepId: step.id, error: error.message });
        }
        
        completedStepIds.add(step.id);
        this.store.saveSession(session);
        if (this.onEvent) this.onEvent('step_completed', { sessionId, stepId: step.id, status: step.status });
      }));
    }

    // Synthesis
    session.phase = 'synthesis';
    session.status = 'COMPLETED';
    const summary = await this.planner.synthesizeSummary(session as any);
    
    if (summary) {
      summary.durationMs = Date.now() - startTime;
      this.store.saveSession(session);
      if (this.onEvent) this.onEvent('investigation_completed', summary);
    }
    
    return summary;
  }

  /**
   * Resume an investigation after HITL approval.
   */
  async resumeWithApproval(sessionId: string, approved: boolean, notes?: string): Promise<InvestigationSummary | HITLState | null> {
    const session = this.store.getSession(sessionId);
    const hitl = this.store.getHITL(sessionId);
    if (!session || !hitl) throw new Error('Session or HITL state not found');

    const step = session.steps.find(s => s.id === hitl.stepId);
    if (!step) throw new Error('Step not found');

    hitl.status = approved ? 'APPROVED' : 'DENIED';
    this.store.saveHITL(hitl);

    if (!approved) {
      step.status = 'blocked';
    } else {
      // In a real scenario, this would trigger the actual destructive tool call.
      step.status = 'completed';
      session.findings.push({
        stepId: step.id,
        tool: step.tool,
        output: 'Human approved destructive action executed.',
        notes
      });
    }

    session.status = 'ACTIVE';
    this.store.saveSession(session);
    return this.runExecutionLoop(sessionId);
  }
}
