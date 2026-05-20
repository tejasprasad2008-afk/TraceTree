import inquirer from 'inquirer';
import chalk from 'chalk';
import fs from 'node:fs/promises';
import path from 'node:path';

const ASCII_ART = `
${chalk.cyan('   _______                 _______')}
${chalk.cyan('  |__   __|               |__   __|')}
${chalk.cyan('     | |_ __ __ _  ___ ___   | |_ __ ___  ___')}
${chalk.cyan('     | | \'__/ _` |/ __/ _ \\  | | \'__/ _ \\/ _ \\')}
${chalk.cyan('     | | | | (_| | (_|  __/  | | | |  __/  __/')}
${chalk.cyan('     |_|_|  \\__,_|\\___\\___|  |_|_|  \\___|\\___|')}
                                                     
    ${chalk.white.bold('Open Source Detection & Response Platform')}
    ${chalk.gray('v0.1.0 | Autonomous Investigation Engine')}
`;

/**
 * Runs the interactive onboarding wizard.
 */
export async function runSetupWizard() {
  console.log(ASCII_ART);
  console.log(chalk.white('Welcome to TraceTree. Let\'s get your environment configured.\n'));

  try {
    const { provider } = await inquirer.prompt([
      {
        type: 'list',
        name: 'provider',
        message: 'Select your preferred LLM Provider:',
        choices: [
          { name: 'Anthropic Claude (Native - Recommended)', value: 'claude' },
          { name: 'OpenRouter (Multi-Model Gateway)', value: 'openrouter' },
          { name: 'Ollama (Local Inference - Privacy First)', value: 'ollama' }
        ]
      }
    ]);

    let config: Record<string, string> = { LLM_PROVIDER: provider };

    if (provider === 'claude') {
      const { apiKey } = await inquirer.prompt([
        {
          type: 'password',
          name: 'apiKey',
          message: 'Enter your ANTHROPIC_API_KEY:',
          mask: '*'
        }
      ]);
      config.ANTHROPIC_API_KEY = apiKey;
    } else if (provider === 'openrouter') {
      const { apiKey } = await inquirer.prompt([
        {
          type: 'password',
          name: 'apiKey',
          message: 'Enter your OPENROUTER_API_KEY:',
          mask: '*'
        }
      ]);
      config.OPENROUTER_API_KEY = apiKey;
    } else if (provider === 'ollama') {
      const { baseUrl } = await inquirer.prompt([
        {
          type: 'input',
          name: 'baseUrl',
          message: 'Enter your Ollama base URL:',
          default: 'http://localhost:11434'
        }
      ]);
      config.OLLAMA_BASE_URL = baseUrl;
    }

    const { logLevel } = await inquirer.prompt([
      {
        type: 'list',
        name: 'logLevel',
        message: 'Select your preferred log level:',
        choices: ['info', 'debug', 'warn', 'error'],
        default: 'info'
      }
    ]);
    config.LOG_LEVEL = logLevel;

    // Persist to .env
    const envPath = path.join(process.cwd(), '.env');
    const envContent = Object.entries(config)
      .map(([key, value]) => `${key}=${value}`)
      .join('\n');

    await fs.writeFile(envPath, envContent);

    console.log(chalk.green('\n[✓] Configuration complete!'));
    console.log(chalk.gray(`Settings persisted to ${envPath}\n`));
    console.log(chalk.white('You can now run: ') + chalk.cyan('tracetree investigate "A developer just escalated their privileges..."'));

  } catch (error: any) {
    if (error.isTtyError) {
      console.error(chalk.red('\n[!] Error: Prompt couldn\'t be rendered in the current environment.'));
    } else {
      console.log(chalk.yellow('\n[!] Setup cancelled by user.'));
    }
    process.exit(0);
  }
}
