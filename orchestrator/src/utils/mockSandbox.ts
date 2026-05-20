import { 
  MCPServerConfig, 
  ToolDefinition, 
  ToolResponse 
} from '../types/index.js';
import { logger } from './index.js';

/**
 * Mock Sandbox Simulator
 * Provides simulated security tool outputs for the --demo mode.
 */
export class MockSandbox {
  /**
   * Returns a simulated MCP configuration.
   */
  static getMockConfig(): MCPServerConfig {
    return {
      id: 'mock-security-suite',
      type: 'stdio',
      command: 'node',
      args: ['dist/utils/mockSandbox.js', '--server-mode']
    };
  }

  /**
   * Simulates tool execution for demo purposes.
   * This logic mimics what a real MCP server would return.
   */
  static async simulateToolCall(name: string, args: any): Promise<ToolResponse> {
    logger.info('sandbox', `Simulating tool call: ${name}`, args);
    
    // Simulate network latency
    await new Promise(resolve => setTimeout(resolve, 800));

    switch (name) {
      case 'logs_query':
        if (args.query?.includes('185.151.242.15')) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify([
                { timestamp: '2026-05-20T10:00:01Z', event: 'SSH Login Success', source_ip: '185.151.242.15', user: 'admin_svc' },
                { timestamp: '2026-05-20T10:05:22Z', event: 'Privilege Escalation', source_ip: '185.151.242.15', user: 'admin_svc', detail: 'sudoers modified' }
              ])
            }]
          };
        }
        return { content: [{ type: 'text', text: '[]' }] };

      case 'threat_intel':
        const ip = args.ip || args.indicator;
        if (ip === '185.151.242.15' || (typeof ip === 'string' && ip.includes('malicious-russian-dc'))) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                verdict: 'MALICIOUS',
                score: 98,
                provider: 'VirusTotal-Mock',
                tags: ['apt29', 'brute-force', 'russian-dc-exit-node']
              })
            }]
          };
        }
        return { content: [{ type: 'text', text: JSON.stringify({ verdict: 'CLEAN', score: 0 }) }] };

      case 'slack_search':
        return {
          content: [{
            type: 'text',
            text: `[#security-alerts] 2026-05-20 09:45: admin_svc: "Starting scheduled maintenance on DC-01."`
          }]
        };

      default:
        return {
          content: [{ type: 'text', text: `Sample output for ${name}` }]
        };
    }
  }
}

// Logic to run as a mock stdio server process if needed
if (process.argv.includes('--server-mode')) {
  process.stdin.on('data', async (data) => {
    try {
      const request = JSON.parse(data.toString());
      if (request.method === 'list_tools') {
        const tools = [
          { name: 'logs_query', description: 'Query authorization and system logs', inputSchema: {} },
          { name: 'threat_intel', description: 'Check IP/Domain reputation', inputSchema: {} },
          { name: 'slack_search', description: 'Search workspace communications', inputSchema: {} }
        ];
        process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, result: { tools } }) + '\n');
      } else if (request.method === 'call_tool') {
        const response = await MockSandbox.simulateToolCall(request.params.name, request.params.arguments);
        process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, result: response }) + '\n');
      }
    } catch (e) {
      // Ignore parse errors in mock
    }
  });
}
