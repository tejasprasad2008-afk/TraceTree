import { LLMMessage, LLMOptions, LLMResponse, LLMProvider } from '../types/index.js';
import { logger } from '../utils/index.js';

export class ClaudeProvider implements LLMProvider {
  name = 'claude';
  private apiKey: string;
  private model: string;
  private baseUrl: string;

  constructor(apiKey: string, model: string = 'claude-3-5-sonnet-20240620', baseUrl: string = 'https://api.anthropic.com') {
    this.apiKey = apiKey;
    this.model = model;
    this.baseUrl = baseUrl.replace(/\/$/, '');
  }

  async generateCompletion(messages: LLMMessage[], options?: LLMOptions): Promise<LLMResponse> {
    const systemMessage = messages.find(m => m.role === 'system')?.content;
    const userMessages = messages.filter(m => m.role !== 'system');

    const response = await fetch(`${this.baseUrl}/v1/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: this.model,
        system: systemMessage,
        messages: userMessages.map(m => ({ role: m.role, content: m.content })),
        max_tokens: options?.maxTokens || 4096,
        temperature: options?.temperature ?? 0.0,
        ...(options?.responseFormat === 'json' ? { response_format: { type: 'json_object' } } : {})
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Claude API error: ${response.status} - ${error}`);
    }

    const data = await response.json();
    return {
      content: data.content[0].text,
      usage: {
        promptTokens: data.usage.input_tokens,
        completionTokens: data.usage.output_tokens
      }
    };
  }
}

export class OpenRouterProvider implements LLMProvider {
  name = 'openrouter';
  private apiKey: string;
  private model: string;
  private baseUrl: string;

  constructor(apiKey: string, model: string = 'anthropic/claude-3.5-sonnet', baseUrl: string = 'https://openrouter.ai/api/v1') {
    this.apiKey = apiKey;
    this.model = model;
    this.baseUrl = baseUrl.replace(/\/$/, '');
  }

  async generateCompletion(messages: LLMMessage[], options?: LLMOptions): Promise<LLMResponse> {
    const response = await fetch(`${this.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
        'HTTP-Referer': 'https://github.com/tracetree/tracetree',
        'X-Title': 'TraceTree'
      },
      body: JSON.stringify({
        model: this.model,
        messages: messages.map(m => ({ role: m.role, content: m.content })),
        max_tokens: options?.maxTokens || 4096,
        temperature: options?.temperature ?? 0.0,
        response_format: options?.responseFormat === 'json' ? { type: 'json_object' } : undefined
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`OpenRouter API error: ${response.status} - ${error}`);
    }

    const data = await response.json();
    return {
      content: data.choices[0].message.content,
      usage: {
        promptTokens: data.usage.prompt_tokens,
        completionTokens: data.usage.completion_tokens
      }
    };
  }
}

/** OpenAI-compatible provider for users who bring an OpenAI API key. */
export class OpenAIProvider implements LLMProvider {
  name = 'openai';
  private apiKey: string;
  private model: string;
  private baseUrl: string;

  constructor(apiKey: string, model: string, baseUrl: string = 'https://api.openai.com/v1') {
    this.apiKey = apiKey;
    this.model = model;
    this.baseUrl = baseUrl.replace(/\/$/, '');
  }

  async generateCompletion(messages: LLMMessage[], options?: LLMOptions): Promise<LLMResponse> {
    const response = await fetch(`${this.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        model: this.model,
        messages: messages.map(m => ({ role: m.role, content: m.content })),
        max_tokens: options?.maxTokens || 4096,
        temperature: options?.temperature ?? 0.0,
        response_format: options?.responseFormat === 'json' ? { type: 'json_object' } : undefined,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`OpenAI API error: ${response.status} - ${error}`);
    }

    const data = await response.json();
    return {
      content: data.choices[0].message.content,
      usage: {
        promptTokens: data.usage?.prompt_tokens || 0,
        completionTokens: data.usage?.completion_tokens || 0,
      },
    };
  }
}

export class OllamaProvider implements LLMProvider {
  name = 'ollama';
  private baseUrl: string;
  private model: string;

  constructor(baseUrl: string, model: string = 'llama3') {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.model = model;
  }

  async generateCompletion(messages: LLMMessage[], options?: LLMOptions): Promise<LLMResponse> {
    const response = await fetch(`${this.baseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: this.model,
        messages: messages,
        stream: false,
        options: {
          temperature: options?.temperature ?? 0.0,
          num_predict: options?.maxTokens || 4096,
          stop: options?.stopSequences
        },
        format: options?.responseFormat === 'json' ? 'json' : undefined
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Ollama API error: ${response.status} - ${error}`);
    }

    const data = await response.json();
    return {
      content: data.message.content,
      usage: {
        promptTokens: data.prompt_eval_count || 0,
        completionTokens: data.eval_count || 0
      }
    };
  }
}

/**
 * Mock Provider for local testing without an API key.
 */
export class MockProvider implements LLMProvider {
  name = 'mock';

  async generateCompletion(messages: LLMMessage[], options?: LLMOptions): Promise<LLMResponse> {
    const prompt = messages[messages.length - 1].content;
    let content = "I have analyzed the request and found no significant issues.";

    // Simple pattern matching to simulate dynamic responses for common tests
    if (options?.responseFormat === 'json') {
      content = JSON.stringify({
        steps: [
          {
            id: "step-1",
            title: "Strace Analysis",
            description: "Analyzing syscall patterns for privilege escalation",
            tool: "analyze_strace",
            parameters: { "log_path": "/tmp/test.log", "pkg_path": "/tmp/pkg" },
            isDestructive: false,
            dependsOn: []
          },
          {
            id: "step-2",
            title: "Network Reputation Check",
            description: "Checking suspicious IPs discovered in logs",
            tool: "threat_intel",
            parameters: { "indicator": "185.151.242.15" },
            isDestructive: false,
            dependsOn: ["step-1"]
          }
        ]
      });
    }

    return {
      content,
      usage: { promptTokens: 0, completionTokens: 0 }
    };
  }
}

/**
 * Provider Factory
 */
export function createLLMProvider(): LLMProvider {
  // A fresh clone should be able to start the Workbench without a paid-provider
  // key. The setup screen can persist a provider later; mock mode keeps local
  // dashboard telemetry available until then.
  const provider = process.env.LLM_PROVIDER || 'mock';
  
  logger.info('llm', `Initializing provider: ${provider}`);

  switch (provider) {
    case 'openai':
      if (!process.env.OPENAI_API_KEY) throw new Error('OPENAI_API_KEY is required for the OpenAI provider. Run `cascade-analyze setup` or open the Workbench setup screen.');
      if (!process.env.OPENAI_MODEL) throw new Error('OPENAI_MODEL is required for the OpenAI provider. Run `cascade-analyze setup` or open the Workbench setup screen.');
      return new OpenAIProvider(
        process.env.OPENAI_API_KEY,
        process.env.OPENAI_MODEL,
        process.env.OPENAI_BASE_URL || 'https://api.openai.com/v1',
      );
    case 'claude':
      if (!process.env.ANTHROPIC_API_KEY) throw new Error('ANTHROPIC_API_KEY is required for the Anthropic provider. Run `cascade-analyze setup` or open the Workbench setup screen.');
      return new ClaudeProvider(
        process.env.ANTHROPIC_API_KEY,
        process.env.ANTHROPIC_MODEL || 'claude-3-5-sonnet-20240620',
        process.env.ANTHROPIC_BASE_URL || 'https://api.anthropic.com',
      );
    case 'openrouter':
      if (!process.env.OPENROUTER_API_KEY) throw new Error('OPENROUTER_API_KEY is required for the OpenRouter provider. Run `cascade-analyze setup` or open the Workbench setup screen.');
      return new OpenRouterProvider(
        process.env.OPENROUTER_API_KEY,
        process.env.OPENROUTER_MODEL || 'anthropic/claude-3.5-sonnet',
        process.env.OPENROUTER_BASE_URL || 'https://openrouter.ai/api/v1',
      );
    case 'ollama':
      return new OllamaProvider(
        process.env.OLLAMA_BASE_URL || 'http://localhost:11434',
        process.env.OLLAMA_MODEL || 'qwen2.5-coder:7b'
      );
    case 'mock':
      return new MockProvider();
    default:
      throw new Error(`Unsupported LLM provider: ${provider}`);
  }
}
