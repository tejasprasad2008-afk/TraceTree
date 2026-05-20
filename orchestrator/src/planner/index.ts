import { 
  InvestigationPlan, 
  InvestigationStep, 
  LLMProvider, 
  TriageDisposition,
  InvestigationSummary
} from '../types/index.js';
import { logger, safeExecute } from '../utils/index.js';

export class InvestigationPlanner {
  private llm: LLMProvider;

  constructor(llm: LLMProvider) {
    this.llm = llm;
  }

  /**
   * Generates a 5-6 step investigation plan based on a natural language prompt.
   */
  async createPlan(prompt: string): Promise<InvestigationPlan | null> {
    logger.info('planning', `Generating investigation plan for: "${prompt}"`);

    const systemPrompt = `
      You are the OpenClue Orchestrator, a senior security incident responder.
      Your goal is to generate a deterministic 5-6 step investigation plan for a given security alert or query.
      
      Rules:
      1. Each step must have a clear 'title', 'description', 'tool', and 'parameters'.
      2. Tools available: 'logs_query', 'threat_intel', 'slack_search', 'git_blame', 'auth_logs', 'endpoint_telemetry'.
      3. Identify steps that are 'isDestructive' (e.g., revoking credentials, isolating hosts).
      4. Ensure logical dependencies using 'dependsOn' (array of step IDs).
      
      Response Format (STRICT JSON):
      {
        "steps": [
          {
            "id": "step-1",
            "title": "...",
            "description": "...",
            "tool": "...",
            "parameters": {},
            "isDestructive": false,
            "dependsOn": []
          }
        ]
      }
    `;

    return await safeExecute('generate_plan', async () => {
      const response = await this.llm.generateCompletion([
        { role: 'system', content: systemPrompt },
        { role: 'user', content: prompt }
      ], { responseFormat: 'json' });

      const rawPlan = JSON.parse(response.content);
      
      return {
        id: `plan_${Date.now()}`,
        prompt,
        steps: rawPlan.steps.map((s: any) => ({
          ...s,
          status: 'pending'
        })),
        currentStepIndex: 0,
        findings: [],
        state: 'active'
      };
    });
  }

  /**
   * Synthesizes raw tool outputs into a Final Investigation Summary.
   */
  async synthesizeSummary(plan: InvestigationPlan): Promise<InvestigationSummary | null> {
    logger.info('synthesis', `Synthesizing results for plan ${plan.id}`);

    const systemPrompt = `
      You are the OpenClue Synthesis Engine. 
      Analyze the following investigation findings and provide a final verdict and Markdown summary.
      
      Dispositions: FALSE_POSITIVE, TRUE_POSITIVE, MALICIOUS, EXPECTED_BEHAVIOR.
      
      Required Markdown Sections:
      - ## Executive Summary
      - ## Investigation Timeline
      - ## Root Cause Analysis
      - ## Posture Gaps & Recommendations
    `;

    return await safeExecute('synthesize_summary', async () => {
      const response = await this.llm.generateCompletion([
        { role: 'system', content: systemPrompt },
        { role: 'user', content: JSON.stringify(plan.findings) }
      ]);

      // Simple heuristic for verdict extraction from LLM content if not explicitly structured
      let verdict: TriageDisposition = 'EXPECTED_BEHAVIOR';
      if (response.content.includes('MALICIOUS')) verdict = 'MALICIOUS';
      else if (response.content.includes('TRUE_POSITIVE')) verdict = 'TRUE_POSITIVE';
      else if (response.content.includes('FALSE_POSITIVE')) verdict = 'FALSE_POSITIVE';

      return {
        planId: plan.id,
        verdict,
        summary: response.content,
        timeline: plan.findings.map(f => ({
          timestamp: new Date().toISOString(), // In a real scenario, extract from finding
          event: f.stepTitle || 'Investigation Step',
          details: f.summary || 'Details not provided'
        })),
        postureGaps: [], // Extracted by LLM in summary content
        mitigationMetrics: {
          stepsExecuted: plan.steps.filter(s => s.status === 'completed').length,
          toolsUsed: [...new Set(plan.steps.map(s => s.tool))],
          durationMs: 0 // To be calculated by engine
        }
      };
    });
  }
}
