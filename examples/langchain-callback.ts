/**
 * LangChain integration — validate tool calls via callback
 *
 * Works with LangChain's tool-calling agents by intercepting
 * tool invocations before they execute.
 */
import { checkAction, type VigilResult } from 'vigil-agent-safety';

/**
 * Create a LangChain-compatible tool wrapper that validates with Vigil
 *
 * Usage with LangChain:
 *   const safeTool = vigilTool(myTool, 'my-agent');
 *   const agent = createToolCallingAgent({ tools: [safeTool] });
 */
function vigilTool<T extends { name: string; invoke: (input: unknown) => Promise<unknown> }>(
  tool: T,
  agentId = 'langchain-agent'
): T {
  const originalInvoke = tool.invoke.bind(tool);

  tool.invoke = async (input: unknown): Promise<unknown> => {
    const params = typeof input === 'object' && input !== null
      ? input as Record<string, unknown>
      : { input };

    const result: VigilResult = checkAction({
      agent: agentId,
      tool: tool.name,
      params,
    });

    if (result.decision === 'BLOCK') {
      return `[BLOCKED by Vigil] ${result.reason}`;
    }

    if (result.decision === 'ESCALATE') {
      console.warn(`[vigil] Tool "${tool.name}" escalated: ${result.reason}`);
    }

    return originalInvoke(input);
  };

  return tool;
}

// Example usage:
// import { ShellTool } from 'langchain/tools';
// const shell = vigilTool(new ShellTool(), 'my-coding-agent');

export { vigilTool };
