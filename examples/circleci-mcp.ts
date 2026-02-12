/**
 * Vigil + CircleCI MCP Server Integration
 *
 * Wraps CircleCI's MCP server (@circleci/mcp-server-circleci) with Vigil
 * safety checks. Prevents AI agents from dangerous CI/CD operations like
 * force-pushing to main, skipping tests, or accessing production secrets.
 *
 * Why this matters:
 *   CircleCI's MCP server exposes your entire CI/CD pipeline to AI agents.
 *   Agents can trigger builds, read logs, modify configs, and access secrets.
 *   Without guardrails, a single hallucinated tool call could:
 *     - Deploy untested code to production
 *     - Expose environment secrets in logs
 *     - Trigger cascading pipeline failures
 *     - Skip required security scans
 *
 * Setup:
 *   1. npm install vigil-agent-safety @circleci/mcp-server-circleci
 *   2. Configure your CircleCI token (see circleci.com/docs)
 *   3. Use this wrapper instead of the raw MCP server
 */

import { checkAction, configure, loadPolicy, type VigilResult, type VigilInput } from 'vigil-agent-safety';

// ─── Vigil Configuration ───────────────────────────────────────────
// 'enforce' = block dangerous calls, 'warn' = log but allow
configure({ mode: 'enforce' });

// ─── CircleCI-Specific Safety Rules ────────────────────────────────

/** Branches that should never be directly modified by agents */
const PROTECTED_BRANCHES = ['main', 'master', 'production', 'release', 'staging'];

/** Pipeline parameters agents should never set */
const FORBIDDEN_PARAMS = ['skip-tests', 'skip-security', 'force-deploy', 'bypass-approval'];

/** Environment variable name patterns that indicate secrets */
const SECRET_PATTERNS = [
  /api[_-]?key/i,
  /secret/i,
  /token/i,
  /password/i,
  /private[_-]?key/i,
  /credentials/i,
  /aws[_-]?(access|secret)/i,
  /database[_-]?url/i,
];

// ─── CircleCI MCP Tool Interceptors ────────────────────────────────

interface CircleCIToolCall {
  tool: string;
  params: Record<string, unknown>;
  agentId?: string;
}

interface GuardResult {
  allowed: boolean;
  reason?: string;
  vigilResult: VigilResult;
}

/**
 * Main guard function — validates any CircleCI MCP tool call
 */
function guardCircleCICall(call: CircleCIToolCall): GuardResult {
  const { tool, params, agentId = 'ci-agent' } = call;

  // Step 1: Run Vigil's built-in checks (SSRF, injection, exfiltration, etc.)
  const vigilResult = checkAction({
    agent: agentId,
    tool,
    params,
  });

  if (vigilResult.decision === 'BLOCK') {
    return { allowed: false, reason: vigilResult.reason, vigilResult };
  }

  // Step 2: CircleCI-specific safety rules
  const ciCheck = checkCircleCIRules(tool, params);
  if (ciCheck) {
    return {
      allowed: false,
      reason: ciCheck,
      vigilResult: {
        ...vigilResult,
        decision: 'BLOCK',
        rule: 'destructive',
        risk_level: 'critical',
        reason: ciCheck,
      },
    };
  }

  return { allowed: true, vigilResult };
}

/**
 * CircleCI-specific rule checks beyond Vigil's built-in rules
 */
function checkCircleCIRules(tool: string, params: Record<string, unknown>): string | null {
  // Rule 1: Block pipeline triggers on protected branches without approval
  if (tool === 'trigger_pipeline' || tool === 'circleci_trigger_pipeline') {
    const branch = (params.branch as string) || '';
    if (PROTECTED_BRANCHES.some(b => branch === b || branch.endsWith(`/${b}`))) {
      return `Cannot trigger pipeline on protected branch '${branch}'. Use a feature branch and create a PR instead.`;
    }

    // Block forbidden pipeline parameters
    const pipelineParams = (params.parameters as Record<string, unknown>) || {};
    for (const forbidden of FORBIDDEN_PARAMS) {
      if (forbidden in pipelineParams) {
        return `Forbidden pipeline parameter '${forbidden}'. Safety checks cannot be skipped by agents.`;
      }
    }
  }

  // Rule 2: Block config modifications that disable security jobs
  if (tool === 'update_config' || tool === 'circleci_update_config') {
    const config = JSON.stringify(params).toLowerCase();
    if (config.includes('skip') && (config.includes('security') || config.includes('scan'))) {
      return 'Cannot modify config to skip security scans. Security jobs are required.';
    }
    if (config.includes('no_output_timeout') && config.includes('60m')) {
      return 'Suspiciously long timeout detected. Could indicate crypto mining or resource abuse.';
    }
  }

  // Rule 3: Block direct access to environment variable values
  if (tool === 'get_env_var' || tool === 'circleci_get_env_var') {
    const varName = (params.name as string) || '';
    if (SECRET_PATTERNS.some(p => p.test(varName))) {
      return `Cannot read secret environment variable '${varName}'. Agents should not access credentials directly.`;
    }
  }

  // Rule 4: Block deletion of production-related resources
  if (tool === 'delete_project' || tool === 'circleci_delete_project') {
    return 'Agents cannot delete CircleCI projects. This requires human approval.';
  }

  // Rule 5: Block SSH access to running jobs
  if (tool === 'rerun_with_ssh' || tool === 'circleci_rerun_job_with_ssh') {
    return 'Agents cannot SSH into CI jobs. This is a security boundary.';
  }

  // Rule 6: Rate-limit pipeline triggers (prevent runaway loops)
  if (tool === 'trigger_pipeline' || tool === 'circleci_trigger_pipeline') {
    if (!checkRateLimit(params.project_slug as string)) {
      return 'Pipeline trigger rate limit exceeded. Max 5 triggers per project per 10 minutes.';
    }
  }

  return null; // All checks passed
}

// ─── Rate Limiting ─────────────────────────────────────────────────

const triggerLog: Map<string, number[]> = new Map();
const RATE_LIMIT = 5;
const RATE_WINDOW_MS = 10 * 60 * 1000; // 10 minutes

function checkRateLimit(projectSlug: string = 'unknown'): boolean {
  const now = Date.now();
  const timestamps = triggerLog.get(projectSlug) || [];
  const recent = timestamps.filter(t => now - t < RATE_WINDOW_MS);

  if (recent.length >= RATE_LIMIT) {
    return false;
  }

  recent.push(now);
  triggerLog.set(projectSlug, recent);
  return true;
}

// ─── MCP Wrapper ───────────────────────────────────────────────────

type MCPHandler = (params: Record<string, unknown>) => Promise<unknown>;

/**
 * Wrap any CircleCI MCP tool handler with Vigil safety
 *
 * @example
 * ```ts
 * const safeTrigger = withCIGuard('trigger_pipeline', originalHandler, 'coding-agent');
 * const result = await safeTrigger({ branch: 'feat/new-ui', project_slug: 'gh/org/repo' });
 * ```
 */
function withCIGuard(toolName: string, handler: MCPHandler, agentId?: string): MCPHandler {
  return async (params: Record<string, unknown>) => {
    const { allowed, reason, vigilResult } = guardCircleCICall({
      tool: toolName,
      params,
      agentId,
    });

    if (!allowed) {
      console.error(
        `[vigil:circleci] 🚫 BLOCKED ${toolName}: ${reason} (${vigilResult.latencyMs}ms)`
      );
      throw new Error(`[vigil] Blocked: ${reason}`);
    }

    if (vigilResult.decision === 'ESCALATE') {
      console.warn(
        `[vigil:circleci] ⚠️ ESCALATED ${toolName}: ${vigilResult.reason}`
      );
    }

    console.log(
      `[vigil:circleci] ✅ ${toolName} (${vigilResult.latencyMs}ms)`
    );

    return handler(params);
  };
}

// ─── Usage Example ─────────────────────────────────────────────────

/*
 * Full integration with a CircleCI MCP server:
 *
 * ```ts
 * import { Server } from '@modelcontextprotocol/sdk/server/index.js';
 * import { withCIGuard } from './circleci-mcp.js';
 *
 * const server = new Server({ name: 'circleci-vigil', version: '1.0.0' });
 *
 * // Original CircleCI tool handlers
 * const circleCITools = {
 *   trigger_pipeline: async (params) => { ... },
 *   get_build_logs: async (params) => { ... },
 *   get_env_var: async (params) => { ... },
 *   rerun_with_ssh: async (params) => { ... },
 * };
 *
 * // Wrap ALL tools with Vigil safety
 * const safeTools = Object.fromEntries(
 *   Object.entries(circleCITools).map(([name, handler]) => [
 *     name,
 *     withCIGuard(name, handler, 'my-coding-agent'),
 *   ])
 * );
 *
 * // Register safe tools with MCP server
 * server.setRequestHandler(CallToolRequestSchema, async (request) => {
 *   const { name, arguments: args } = request.params;
 *   const tool = safeTools[name];
 *   if (!tool) throw new Error(`Unknown tool: ${name}`);
 *   return { content: [{ type: 'text', text: JSON.stringify(await tool(args)) }] };
 * });
 * ```
 *
 * What gets blocked:
 *
 *   ✗ trigger_pipeline({ branch: 'main' })
 *     → "Cannot trigger pipeline on protected branch 'main'"
 *
 *   ✗ trigger_pipeline({ parameters: { 'skip-tests': true } })
 *     → "Forbidden pipeline parameter 'skip-tests'"
 *
 *   ✗ get_env_var({ name: 'AWS_SECRET_ACCESS_KEY' })
 *     → "Cannot read secret environment variable"
 *
 *   ✗ rerun_with_ssh({ job_id: '...' })
 *     → "Agents cannot SSH into CI jobs"
 *
 *   ✗ delete_project({ project_slug: '...' })
 *     → "Agents cannot delete CircleCI projects"
 *
 *   ✗ 6th trigger_pipeline in 10 min
 *     → "Pipeline trigger rate limit exceeded"
 *
 * What gets allowed:
 *
 *   ✓ trigger_pipeline({ branch: 'feat/new-ui', project_slug: 'gh/org/repo' })
 *   ✓ get_build_logs({ job_id: '...' })
 *   ✓ get_env_var({ name: 'NODE_VERSION' })
 *   ✓ get_pipeline_status({ pipeline_id: '...' })
 */

export { guardCircleCICall, withCIGuard, PROTECTED_BRANCHES, FORBIDDEN_PARAMS };
