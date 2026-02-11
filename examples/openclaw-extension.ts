/**
 * Vigil + OpenClaw/Clawdbot Integration
 *
 * Register Vigil as an OpenClaw extension that intercepts
 * every agent tool call via the before_tool_call hook.
 *
 * Setup:
 *   1. npm install vigil-agent-safety
 *   2. Save this file as your extension: ~/.openclaw/extensions/vigil/index.ts
 *   3. Add to config: plugins.load.paths: ["~/.openclaw/extensions/vigil"]
 *   4. Restart the gateway
 */

import { checkAction, configure } from 'vigil-agent-safety';

// Configure Vigil mode: 'enforce' blocks dangerous calls, 'warn' just logs them
configure({ mode: 'warn' });

const vigilPlugin = {
  id: 'vigil',
  name: 'Vigil Safety Firewall',
  description: 'Agent safety guardrail — validates tool calls before execution',

  register(api: any) {
    api.logger.info('[Vigil] Safety firewall loaded');

    api.on('before_tool_call', async (event: any) => {
      const { toolName, params } = event;
      const agentId = event.ctx?.agentId || 'unknown';

      const result = checkAction({
        agent: agentId,
        tool: toolName,
        params: params,
      });

      if (result.decision === 'BLOCK') {
        api.logger.warn(
          `[Vigil] 🚫 BLOCKED: ${toolName} by ${agentId} — ${result.reason} (${result.latencyMs}ms)`
        );

        // In enforce mode, actually block the tool call
        if (result.mode === 'enforce') {
          return {
            block: true,
            blockReason: `[Vigil] ${result.reason}`,
          };
        }
      }

      if (result.decision === 'ESCALATE') {
        api.logger.warn(
          `[Vigil] ⚠️ ESCALATE: ${toolName} by ${agentId} — ${result.reason}`
        );
      }

      return undefined; // Allow the tool call
    });
  },
};

export default vigilPlugin;
