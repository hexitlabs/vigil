/**
 * Generic before-tool-call hook pattern
 *
 * Works with any agent framework that supports pre-execution hooks.
 * Wrap your agent's tool dispatch with this pattern.
 */
import { checkAction, configure, type VigilInput, type VigilResult } from 'vigil-agent-safety';

// Configure Vigil once at startup
configure({
  mode: 'enforce',
  onViolation: (result: VigilResult, input: VigilInput) => {
    // Send to your logging/alerting system
    console.error(JSON.stringify({
      event: 'vigil_violation',
      decision: result.decision,
      rule: result.rule,
      agent: input.agent,
      tool: input.tool,
      reason: result.reason,
      timestamp: new Date().toISOString(),
    }));
  },
});

/**
 * Generic safety guard — call this before executing any tool
 */
function beforeToolCall(
  agent: string,
  tool: string,
  params: Record<string, unknown>
): { allowed: boolean; result: VigilResult } {
  const result = checkAction({ agent, tool, params });

  return {
    allowed: result.decision === 'ALLOW' || result.decision === 'ESCALATE',
    result,
  };
}

// Example: wrapping a generic agent loop
async function agentLoop(tasks: Array<{ tool: string; params: Record<string, unknown> }>) {
  for (const task of tasks) {
    const { allowed, result } = beforeToolCall('my-agent', task.tool, task.params);

    if (!allowed) {
      console.log(`⛔ Blocked: ${result.reason}`);
      continue;
    }

    // Execute the tool...
    console.log(`✅ Executing ${task.tool}`);
  }
}

export { beforeToolCall, agentLoop };
