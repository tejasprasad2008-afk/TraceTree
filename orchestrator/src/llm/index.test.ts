import { describe, it, expect, vi, beforeEach, afterAll } from 'vitest';
import { createLLMProvider, ClaudeProvider, OpenAIProvider, OpenRouterProvider, OllamaProvider, MockProvider } from './index.js';
import { logger } from '../utils/index.js';

describe('createLLMProvider', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    vi.resetModules();
    // Reset process.env properties
    Object.keys(process.env).forEach(key => {
      delete process.env[key];
    });
    Object.assign(process.env, originalEnv);

    vi.spyOn(logger, 'info').mockImplementation(() => {});
  });

  afterAll(() => {
    Object.keys(process.env).forEach(key => {
      delete process.env[key];
    });
    Object.assign(process.env, originalEnv);
  });

  it('should create a MockProvider by default so a fresh clone can open the dashboard', () => {
    delete process.env.LLM_PROVIDER;
    const provider = createLLMProvider();
    expect(provider).toBeInstanceOf(MockProvider);
    expect(logger.info).toHaveBeenCalledWith('llm', 'Initializing provider: mock');
  });

  it('should create a ClaudeProvider when LLM_PROVIDER is set to claude', () => {
    process.env.LLM_PROVIDER = 'claude';
    process.env.ANTHROPIC_API_KEY = 'test-key';
    const provider = createLLMProvider();
    expect(provider).toBeInstanceOf(ClaudeProvider);
  });

  it('should throw an error if ANTHROPIC_API_KEY is missing for Claude', () => {
    process.env.LLM_PROVIDER = 'claude';
    delete process.env.ANTHROPIC_API_KEY;
    expect(() => createLLMProvider()).toThrow('ANTHROPIC_API_KEY is required for the Anthropic provider');
  });

  it('should create an OpenAIProvider when OpenAI configuration is complete', () => {
    process.env.LLM_PROVIDER = 'openai';
    process.env.OPENAI_API_KEY = 'test-key';
    process.env.OPENAI_MODEL = 'test-model';
    const provider = createLLMProvider();
    expect(provider).toBeInstanceOf(OpenAIProvider);
  });

  it('should explain the missing OpenAI model configuration', () => {
    process.env.LLM_PROVIDER = 'openai';
    process.env.OPENAI_API_KEY = 'test-key';
    delete process.env.OPENAI_MODEL;
    expect(() => createLLMProvider()).toThrow('OPENAI_MODEL is required for the OpenAI provider');
  });

  it('should create an OpenRouterProvider when LLM_PROVIDER is set to openrouter', () => {
    process.env.LLM_PROVIDER = 'openrouter';
    process.env.OPENROUTER_API_KEY = 'test-key';
    const provider = createLLMProvider();
    expect(provider).toBeInstanceOf(OpenRouterProvider);
    expect(logger.info).toHaveBeenCalledWith('llm', 'Initializing provider: openrouter');
  });

  it('should throw an error if OPENROUTER_API_KEY is missing for OpenRouter', () => {
    process.env.LLM_PROVIDER = 'openrouter';
    delete process.env.OPENROUTER_API_KEY;
    expect(() => createLLMProvider()).toThrow('OPENROUTER_API_KEY is required for the OpenRouter provider');
  });

  it('should create an OllamaProvider when LLM_PROVIDER is set to ollama', () => {
    process.env.LLM_PROVIDER = 'ollama';
    const provider = createLLMProvider();
    expect(provider).toBeInstanceOf(OllamaProvider);
    expect(logger.info).toHaveBeenCalledWith('llm', 'Initializing provider: ollama');
  });

  it('should create an OllamaProvider with custom URL and model', () => {
    process.env.LLM_PROVIDER = 'ollama';
    process.env.OLLAMA_BASE_URL = 'http://test-ollama:11434';
    process.env.OLLAMA_MODEL = 'test-model';
    const provider = createLLMProvider() as OllamaProvider;
    expect(provider).toBeInstanceOf(OllamaProvider);
    // Since properties are private, we just verify it doesn't throw and was created
  });

  it('should create a MockProvider when LLM_PROVIDER is set to mock', () => {
    process.env.LLM_PROVIDER = 'mock';
    const provider = createLLMProvider();
    expect(provider).toBeInstanceOf(MockProvider);
    expect(logger.info).toHaveBeenCalledWith('llm', 'Initializing provider: mock');
  });

  it('should throw an error for an unsupported provider', () => {
    process.env.LLM_PROVIDER = 'unsupported';
    expect(() => createLLMProvider()).toThrow('Unsupported LLM provider: unsupported');
  });
});
