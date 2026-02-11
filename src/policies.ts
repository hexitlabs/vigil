import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { VigilPolicy } from './types.js';

/** Built-in policy template names */
export type PolicyTemplate = 'restrictive' | 'moderate' | 'permissive';

/** Built-in policy templates (inlined — no file I/O needed) */
const BUILTIN_POLICIES: Record<PolicyTemplate, VigilPolicy> = {
  restrictive: {
    name: 'restrictive',
    description: 'Maximum safety — blocks most tools, minimal autonomy',
    version: '1.0',
    rules: {
      allowedTools: ['read', 'web_search'],
      blockedTools: ['exec', 'write', 'delete', 'admin'],
      blockedPatterns: { exec: ['*'], write: ['*'], http_request: ['*'] },
      allowedPaths: ['/workspace/', '/tmp/'],
      blockedPaths: ['/etc/', '/root/', '/var/', '/usr/', '/bin/', '/sbin/'],
      maxParams: { 'exec.timeout': 30 },
      network: { allowOutbound: false, blockedDomains: ['*'] },
    },
  },
  moderate: {
    name: 'moderate',
    description: 'Balanced safety — allows common tools with guardrails',
    version: '1.0',
    rules: {
      allowedTools: ['exec', 'read', 'write', 'web_search', 'web_fetch', 'db_query'],
      blockedTools: ['admin', 'deploy', 'delete_namespace'],
      blockedPatterns: {
        exec: ['rm -rf /', 'mkfs', 'dd if=', 'chmod 777', 'curl * | bash'],
        db_query: ['DROP TABLE', 'TRUNCATE', 'DELETE FROM * WHERE 1=1'],
      },
      allowedPaths: ['/home/', '/workspace/', '/tmp/', '/var/log/'],
      blockedPaths: ['/etc/shadow', '/root/.ssh/', '/root/.aws/'],
      maxParams: { 'exec.timeout': 300 },
      network: {
        allowOutbound: true,
        blockedDomains: ['webhook.site', 'ngrok.io', 'requestbin.com', 'pipedream.net'],
      },
    },
  },
  permissive: {
    name: 'permissive',
    description: 'Minimal restrictions — trusts agent, blocks only critical threats',
    version: '1.0',
    rules: {
      allowedTools: ['*'],
      blockedTools: [],
      blockedPatterns: { exec: ['rm -rf /', 'mkfs', 'dd if=*/dev/*', ':(){ :|:& };:'] },
      allowedPaths: ['*'],
      blockedPaths: [],
      maxParams: { 'exec.timeout': 600 },
      network: { allowOutbound: true, blockedDomains: [] },
    },
  },
};

/**
 * Load a policy by built-in template name or from a JSON file path.
 * @param pathOrTemplate - 'restrictive' | 'moderate' | 'permissive' or a file path
 */
export function loadPolicy(pathOrTemplate: string): VigilPolicy {
  // Check built-in templates first
  if (pathOrTemplate in BUILTIN_POLICIES) {
    return { ...BUILTIN_POLICIES[pathOrTemplate as PolicyTemplate] };
  }

  // Load from file
  const filePath = resolve(pathOrTemplate);
  try {
    const raw = readFileSync(filePath, 'utf-8');
    return JSON.parse(raw) as VigilPolicy;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to load policy from "${filePath}": ${msg}`);
  }
}

/**
 * List available built-in policy template names
 */
export function listPolicies(): PolicyTemplate[] {
  return ['restrictive', 'moderate', 'permissive'];
}
