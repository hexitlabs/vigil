/**
 * MCP (Model Context Protocol) server wrapper
 *
 * Wraps any MCP server tool with Vigil safety checks.
 * The agent's tool calls are validated before reaching your actual tool handlers.
 */
import { checkAction, type VigilResult } from 'vigil-agent-safety';

// Generic MCP tool handler type
type ToolHandler = (params: Record<string, unknown>) => Promise<unknown>;

/**
 * Wrap an MCP tool handler with Vigil safety checks
 */
function withVigilGuard(
  toolName: string,
  handler: ToolHandler,
  agentId = 'mcp-agent'
): ToolHandler {
  return async (params: Record<string, unknown>) => {
    const result: VigilResult = checkAction({
      agent: agentId,
      tool: toolName,
      params,
    });

    if (result.decision === 'BLOCK') {
      throw new Error(
        `[vigil] Blocked: ${result.reason} (rule: ${result.rule})`
      );
    }

    if (result.decision === 'ESCALATE') {
      console.warn(`[vigil] Escalated: ${result.reason}`);
      // In production, you might queue this for human review
    }

    return handler(params);
  };
}

// Example: wrapping MCP server tools
const tools = {
  exec: withVigilGuard('exec', async (params) => {
    // Your actual exec implementation
    return { output: `Executed: ${params.command}` };
  }),

  readFile: withVigilGuard('read', async (params) => {
    // Your actual file read implementation
    return { content: `Contents of ${params.path}` };
  }),

  webFetch: withVigilGuard('web_fetch', async (params) => {
    // Your actual fetch implementation
    return { html: `Fetched: ${params.url}` };
  }),
};

export { withVigilGuard, tools };
