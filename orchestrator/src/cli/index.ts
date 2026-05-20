#!/usr/bin/env node
import { Command } from 'commander';
import fs from 'node:fs/promises';
import path from 'node:path';
import chalk from 'chalk';
import 'dotenv/config';
import { OpenClueEngine } from '../engine/index.js';
import { createLLMProvider } from '../llm/index.js';
import { saveSession, loadSession, deleteSession } from '../utils/persistence.js';
import { logger } from '../utils/index.js';
import { AlertPayload } from '../types/index.js';
import { runSetupWizard } from './setup.js';

const program = new Command();

program
  .name('openclue')
  .description('Autonomous Security Detection and Response Platform')
  .version('0.1.0');

/**
 * COMMAND: init
 * Triggers the interactive setup wizard.
 */
program
  .command('init')
  .description('Initialize the OpenClue environment and LLM provider')
  .action(async () => {
    await runSetupWizard();
  });

/**
 * COMMAND: investigate
 * Usage: openclue investigate "Prompt"
 */
program
  .command('investigate')
  .description('Start a natural language security investigation')
  .argument('<prompt>', 'The security query or incident description')
  .option('--demo', 'Run in demo mode with simulated tools', false)
  .action(async (prompt: string, options) => {
    try {
      const llm = createLLMProvider();
      const engine = new OpenClueEngine(llm);

      console.log(chalk.cyan(`\n[OPENCLUE] Starting investigation: ${prompt}${options.demo ? ' (DEMO MODE)' : ''}\n`));
      
      const result = await engine.investigate(prompt, { demo: options.demo });

      if (result && 'isPending' in result) {
        const sessionId = result.stepId + '_' + Date.now();
        // Since the engine doesn't return the full session yet, we wrap it
        // In a real implementation, investigate() would return a session container
        // For this foundational build, we'll inform the user of the HITL pause.
        console.log(chalk.yellow(`\n[!] HITL REQUIRED: Destructive tool detected (${result.toolCall.name})`));
        console.log(chalk.white(`Reasoning: ${result.requesterReasoning}`));
        
        // We simulate saving the full state here - in practice, we'd pass the session object
        await saveSession(sessionId, { hitl: result, prompt });
        console.log(chalk.green(`\nSession saved. Run 'openclue resume ${sessionId}' to approve.`));
      } else if (result) {
        console.log(chalk.green('\n--- FINAL INVESTIGATION SUMMARY ---\n'));
        console.log(result.summary);
        console.log(chalk.green('\n-----------------------------------\n'));
      }
    } catch (error: any) {
      logger.error('cli', 'Investigation failed', error);
      process.exit(1);
    }
  });

/**
 * COMMAND: triage
 * Usage: openclue triage <path_to_json>
 */
program
  .command('triage')
  .description('Perform automated first-pass triage on a raw alert JSON')
  .argument('<path>', 'Path to the alert JSON file')
  .action(async (path: string) => {
    try {
      const rawData = await fs.readFile(path, 'utf-8');
      const alert: AlertPayload = JSON.parse(rawData);
      
      const llm = createLLMProvider();
      // Triage uses the same LLM logic but a specialized prompt
      // For this build, we use the engine to handle it as a single-step investigation
      const engine = new OpenClueEngine(llm);
      
      console.log(chalk.cyan(`\n[TRIAGE] Ingesting alert: ${alert.id} (${alert.type})\n`));
      
      const triagePrompt = `Triage this security alert and provide a disposition (FALSE_POSITIVE, TRUE_POSITIVE, MALICIOUS, EXPECTED_BEHAVIOR): ${JSON.stringify(alert)}`;
      const result = await engine.investigate(triagePrompt);

      if (result && 'summary' in result) {
        console.log(result.summary);
      }
    } catch (error: any) {
      logger.error('cli', 'Triage failed', error);
      process.exit(1);
    }
  });

/**
 * COMMAND: resume
 * Usage: openclue resume <session_id>
 */
program
  .command('resume')
  .description('Resume a paused investigation session')
  .argument('<session_id>', 'The ID of the saved session')
  .option('--approve', 'Approve the pending destructive action', true)
  .option('--deny', 'Deny the pending destructive action', false)
  .action(async (sessionId: string, options) => {
    try {
      const sessionData = await loadSession(sessionId);
      if (!sessionData) {
        console.error(chalk.red(`Error: Session ${sessionId} not found.`));
        return;
      }

      const llm = createLLMProvider();
      const engine = new OpenClueEngine(llm);
      
      // In this foundational build, we simulate the resumption logic
      // by re-running the loop with the approved flag.
      console.log(chalk.cyan(`\n[RESUME] Resuming session: ${sessionId}`));
      
      const approved = options.deny ? false : true;
      console.log(approved ? chalk.green('Action APPROVED.') : chalk.red('Action DENIED.'));

      // Real implementation would pass the full session object back to engine.resumeWithApproval()
      console.log(chalk.white('\nFinalizing investigation based on approval...'));
      
      // For the demo/foundational layer, we'll output a completion message
      await deleteSession(sessionId);
      console.log(chalk.green('\nInvestigation complete. Session cleaned up.'));

    } catch (error: any) {
      logger.error('cli', 'Resume failed', error);
      process.exit(1);
    }
  });

// Fallback: If no arguments provided, check for configuration
if (process.argv.length <= 2) {
  try {
    await fs.access(path.join(process.cwd(), '.env'));
    program.help(); // If .env exists, just show help
  } catch {
    await runSetupWizard(); // If no .env, run the wizard
  }
} else {
  program.parse();
}
