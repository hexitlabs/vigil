/**
 * Express middleware pattern — intercept agent tool calls via HTTP
 *
 * POST /agent/tool-call
 * { "agent": "my-agent", "tool": "exec", "params": { "command": "..." } }
 */
import { checkAction, type VigilInput, type VigilResult } from 'vigil-agent-safety';

// Simulated Express types (so this example is self-contained)
interface Request { body: VigilInput }
interface Response { status(code: number): Response; json(data: unknown): void }
type NextFunction = () => void;

/**
 * Express middleware that validates tool calls before execution
 */
function vigilMiddleware(req: Request, res: Response, next: NextFunction): void {
  const { agent, tool, params } = req.body;

  const result: VigilResult = checkAction({ agent, tool, params });

  if (result.decision === 'BLOCK') {
    res.status(403).json({
      error: 'blocked',
      rule: result.rule,
      reason: result.reason,
    });
    return;
  }

  if (result.decision === 'ESCALATE') {
    // Log for human review, but allow the request to proceed
    console.warn(`[vigil] ESCALATE: ${result.reason}`);
  }

  next();
}

// Usage in Express app:
// app.post('/agent/tool-call', vigilMiddleware, handleToolCall);

export { vigilMiddleware };
