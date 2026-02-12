# 🛡️ Vigil

**Zero-dependency, <2ms safety guardrails for AI agents.**

Vigil validates what AI agents **do**, not what they say. Drop it in front of any tool-calling agent to catch destructive commands, data exfiltration, SSRF, injection attacks, and more — before they execute.

## Install

```bash
npm install vigil-agent-safety
```

## Quick Start

```typescript
import { checkAction } from 'vigil-agent-safety';

const result = checkAction({
  agent: 'my-agent',
  tool: 'exec',
  params: { command: 'rm -rf /' },
});

console.log(result.decision); // "BLOCK"
console.log(result.rule);     // "destructive"
console.log(result.reason);   // "Destructive command: matched pattern..."
```

## What It Catches

| Category | Examples | Decision |
|----------|----------|----------|
| **Destructive** | `rm -rf /`, `mkfs`, reverse shells | BLOCK |
| **SSRF** | `169.254.169.254`, `localhost:6379`, `gopher://` | BLOCK |
| **Exfiltration** | `curl evil.com`, `.ssh/id_rsa`, `.aws/credentials` | BLOCK |
| **SQL Injection** | `DROP TABLE`, `UNION SELECT`, `OR 1=1` | BLOCK |
| **Path Traversal** | `../../../etc/shadow`, `/proc/self` | BLOCK |
| **Prompt Injection** | "Ignore previous instructions", `[INST]` tags | BLOCK |
| **Encoding Attacks** | `base64 -d`, `eval(atob(...))`, hex escapes | BLOCK |
| **Credential Leaks** | API keys, AWS keys, private keys, tokens | ESCALATE |

22 battle-tested rules. All pattern-based. All under 2ms.

## Why Vigil?

Existing safety tools (Llama Guard, ShieldGemma) filter **content** — what agents say. Vigil validates **actions** — what agents do. Content safety ≠ action safety.

| | Vigil | Llama Guard | Regex | GPT-4 Review |
|---|---|---|---|---|
| **Latency** | <2ms | 200-500ms | <1ms | 2-5s |
| **Dependencies** | 0 | PyTorch | 0 | API key |
| **Validates** | Actions | Content | Strings | Content |
| **Offline** | ✅ | ✅ | ✅ | ❌ |

## CLI

```bash
# Check a tool call
npx vigil-agent-safety check --tool exec --params '{"command":"rm -rf /"}'

# JSON output for scripting
npx vigil-agent-safety check --tool exec --params '{"command":"ls"}' --json

# List policy templates
npx vigil-agent-safety policies
```

Exit codes: `0`=ALLOW, `1`=BLOCK, `2`=ESCALATE

## API

### `checkAction(input): VigilResult`

```typescript
import { checkAction } from 'vigil-agent-safety';

const result = checkAction({
  agent: 'my-agent',        // optional
  tool: 'exec',             // tool being called
  params: { command: '...' }, // tool parameters
  role: 'developer',        // optional
  context: ['...'],         // optional
});

// result: { decision, rule, confidence, risk_level, reason, latencyMs }
```

### `configure(config)`

```typescript
import { configure } from 'vigil-agent-safety';

configure({
  mode: 'warn',  // 'enforce' | 'warn' | 'log'
  onViolation: (result, input) => {
    console.log(`[vigil] ${result.decision}: ${result.reason}`);
  },
});
```

### `loadPolicy(name)`

```typescript
import { loadPolicy } from 'vigil-agent-safety';

const policy = loadPolicy('moderate'); // 'restrictive' | 'moderate' | 'permissive'
// Or load custom: loadPolicy('./my-policy.json')
```

## Integration Examples

See [`examples/`](./examples/) for complete integration patterns:

- **[basic.ts](./examples/basic.ts)** — Minimal usage
- **[express-middleware.ts](./examples/express-middleware.ts)** — HTTP middleware
- **[mcp-wrapper.ts](./examples/mcp-wrapper.ts)** — MCP server wrapper
- **[circleci-mcp.ts](./examples/circleci-mcp.ts)** — CircleCI CI/CD safety (protected branches, secret access, rate limiting)
- **[langchain-callback.ts](./examples/langchain-callback.ts)** — LangChain integration
- **[openclaw-extension.ts](./examples/openclaw-extension.ts)** — OpenClaw/Clawdbot agent extension
- **[generic-hook.ts](./examples/generic-hook.ts)** — Generic before-tool-call hook

## License

Apache 2.0 — Built by [Hexit Labs](https://github.com/hexitlabs)
