import { spawn, ChildProcess } from 'node:child_process';
import { 
  MCPServerConfig, 
  ToolCall, 
  ToolResponse, 
  ToolDefinition 
} from '../types/index.js';
import { logger } from '../utils/index.js';

/**
 * Universal MCP Client Router
 * Handles JSON-RPC communication over Stdio and WebSocket with strict timeouts.
 */
export class MCPRouter {
  private clients: Map<string, ChildProcess> = new Map();
  private tools: Map<string, { serverId: string; definition: ToolDefinition }> = new Map();
  private requestCounter = 0;

  /**
   * Initializes a connection to an MCP server (Stdio focus for local-first).
   */
  async initializeClient(config: MCPServerConfig): Promise<void> {
    if (config.type !== 'stdio' || !config.command) {
      throw new Error(`Unsupported MCP server type or missing command for ${config.id}`);
    }

    logger.info('mcp', `Initializing client: ${config.id} (${config.command})`);

    const child = spawn(config.command, config.args || [], {
      env: { ...process.env, ...config.env },
      stdio: ['pipe', 'pipe', 'inherit']
    });

    return new Promise((resolve, reject) => {
      child.on('error', (err) => {
        logger.error('mcp', `Failed to start MCP server ${config.id}`, err);
        reject(err);
      });

      // Simple handshake for tool discovery
      // In a full implementation, this follows the official initialize -> tools/list flow
      this.sendRequest(child, 'list_tools', {}).then((response: any) => {
        const serverTools = response.tools || [];
        serverTools.forEach((tool: any) => {
          this.tools.set(tool.name, {
            serverId: config.id,
            definition: { ...tool, serverId: config.id }
          });
        });
        
        this.clients.set(config.id, child);
        logger.info('mcp', `Server ${config.id} registered ${serverTools.length} tools`);
        resolve();
      }).catch(reject);
    });
  }

  /**
   * Lists all aggregated tools from all registered servers.
   */
  listRegisteredTools(): ToolDefinition[] {
    return Array.from(this.tools.values()).map(t => t.definition);
  }

  /**
   * Executes an MCP tool with a deterministic 15s timeout and sanitization.
   */
  async executeMcpTool(toolName: string, args: Record<string, any>): Promise<ToolResponse> {
    const toolEntry = this.tools.get(toolName);
    if (!toolEntry) {
      throw new Error(`Tool ${toolName} not found in any registered MCP server`);
    }

    const client = this.clients.get(toolEntry.serverId);
    if (!client) {
      throw new Error(`Client for server ${toolEntry.serverId} is not connected`);
    }

    const timeoutMs = 15000;
    
    // Racing primitive to ensure no hanging tool blocks the engine
    const executionPromise = this.sendRequest(client, 'call_tool', {
      name: toolName,
      arguments: args
    });

    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error(`TIMEOUT_ERROR: Tool ${toolName} failed to respond within ${timeoutMs}ms`)), timeoutMs);
    });

    try {
      const result: any = await Promise.race([executionPromise, timeoutPromise]);
      
      // Strict Output Sanitization
      return {
        content: Array.isArray(result.content) ? result.content.map((c: any) => ({
          type: c.type || 'text',
          text: typeof c.text === 'string' ? c.text : JSON.stringify(c.text || c)
        })) : [{ type: 'text', text: JSON.stringify(result) }],
        isError: result.isError || false
      };

    } catch (error: any) {
      logger.error('mcp', `Execution error for ${toolName}`, error);
      return {
        content: [{ type: 'text', text: `Execution failed: ${error.message}` }],
        isError: true
      };
    }
  }

  /**
   * Low-level JSON-RPC request over Stdio.
   */
  private async sendRequest(child: ChildProcess, method: string, params: any): Promise<any> {
    const id = ++this.requestCounter;
    const request = JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n';

    return new Promise((resolve, reject) => {
      const onData = (data: Buffer) => {
        const responseString = data.toString();
        try {
          // Note: Real MCP servers might send multiple chunks or interleaved stdout
          // This simplified version assumes line-buffered JSON-RPC
          const response = JSON.parse(responseString);
          if (response.id === id) {
            child.stdout?.removeListener('data', onData);
            if (response.error) reject(new Error(response.error.message || 'Unknown JSON-RPC error'));
            else resolve(response.result);
          }
        } catch (e) {
          // Not our response or malformed chunk, wait for more data
        }
      };

      child.stdout?.on('data', onData);
      child.stdin?.write(request);
    });
  }

  /**
   * Gracefully shuts down all connected MCP servers.
   */
  async shutdown(): Promise<void> {
    for (const [id, child] of this.clients.entries()) {
      logger.info('mcp', `Shutting down server ${id}`);
      child.kill();
    }
    this.clients.clear();
    this.tools.clear();
  }
}
