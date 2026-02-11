import { checkAction } from './rules.js';
import { loadPolicy, listPolicies } from './policies.js';

// ANSI colors (zero deps)
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';

const HELP = `
${BOLD}vigil${RESET} — AI agent safety guardrails

${BOLD}Usage:${RESET}
  vigil check --tool <tool> --params '<json>' [--agent <name>]
  vigil check --stdin
  vigil policies
  vigil --help

${BOLD}Commands:${RESET}
  check       Check a tool call against safety rules
  policies    List built-in policy templates

${BOLD}Options (check):${RESET}
  --tool      Tool being called (e.g., exec, read, write)
  --agent     Agent name/identifier
  --params    Tool parameters as JSON string
  --role      Agent's role description
  --stdin     Read JSON input from stdin
  --json      Output raw JSON (for scripting)

${BOLD}Exit codes:${RESET}
  0 = ALLOW    1 = BLOCK    2 = ESCALATE
`;

function colorDecision(decision: string): string {
  switch (decision) {
    case 'ALLOW': return `${GREEN}${BOLD}ALLOW${RESET}`;
    case 'BLOCK': return `${RED}${BOLD}BLOCK${RESET}`;
    case 'ESCALATE': return `${YELLOW}${BOLD}ESCALATE${RESET}`;
    default: return decision;
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || args.includes('--help') || args.includes('-h')) {
    console.log(HELP);
    process.exit(0);
  }

  if (command === 'policies') {
    const templates = listPolicies();
    console.log(`${BOLD}Built-in policy templates:${RESET}\n`);
    for (const name of templates) {
      const policy = loadPolicy(name);
      console.log(`  ${GREEN}${name}${RESET} — ${policy.description}`);
    }
    process.exit(0);
  }

  if (command === 'check') {
    const jsonMode = args.includes('--json');
    const stdinMode = args.includes('--stdin');

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let input: any = {};

    if (stdinMode) {
      const chunks: Buffer[] = [];
      for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
      input = JSON.parse(Buffer.concat(chunks).toString());
    } else {
      for (let i = 1; i < args.length; i++) {
        switch (args[i]) {
          case '--agent': input.agent = args[++i]; break;
          case '--tool': input.tool = args[++i]; break;
          case '--params': input.params = JSON.parse(args[++i]); break;
          case '--role': input.role = args[++i]; break;
        }
      }
    }

    const result = checkAction(input);

    if (jsonMode) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(`\n  ${BOLD}Decision:${RESET}    ${colorDecision(result.decision)}`);
      if (result.rule) {
        console.log(`  ${BOLD}Rule:${RESET}        ${result.rule}`);
      }
      console.log(`  ${BOLD}Risk:${RESET}        ${result.risk_level}`);
      console.log(`  ${BOLD}Confidence:${RESET}  ${result.confidence}`);
      console.log(`  ${BOLD}Reason:${RESET}      ${result.reason}`);
      console.log(`  ${DIM}Latency:     ${result.latencyMs}ms${RESET}\n`);
    }

    const exitCodes: Record<string, number> = { ALLOW: 0, BLOCK: 1, ESCALATE: 2 };
    process.exit(exitCodes[result.decision] ?? 2);
  }

  console.error(`Unknown command: ${command}. Run 'vigil --help' for usage.`);
  process.exit(1);
}

main().catch((err) => {
  console.error('Fatal:', err instanceof Error ? err.message : err);
  process.exit(2);
});
