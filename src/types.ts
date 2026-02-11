/** Input to the Vigil safety check */
export interface VigilInput {
  /** Agent name or identifier */
  agent?: string;
  /** Tool being called (e.g., "exec", "read", "write", "http_request") */
  tool?: string;
  /** Tool parameters — the actual payload to validate */
  params?: Record<string, unknown> | string;
  /** Alias for params (for compatibility) */
  parameters?: Record<string, unknown> | string;
  /** Agent's role description */
  role?: string;
  /** Recent conversation context */
  context?: string | string[];
}

/** Safety decision */
export type Decision = 'ALLOW' | 'BLOCK' | 'ESCALATE';

/** Risk level classification */
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

/** Rule category */
export type RuleCategory =
  | 'ssrf'
  | 'destructive'
  | 'exfiltration'
  | 'sql_injection'
  | 'path_traversal'
  | 'prompt_injection'
  | 'encoding_attack'
  | 'credential_leak';

/** Result from a Vigil safety check */
export interface VigilResult {
  /** Safety decision: ALLOW, BLOCK, or ESCALATE */
  decision: Decision;
  /** Which rule category triggered (null if ALLOW) */
  rule: RuleCategory | null;
  /** Confidence level 0-1 */
  confidence: number;
  /** Risk level classification */
  risk_level: RiskLevel;
  /** Human-readable explanation */
  reason: string;
  /** Check latency in milliseconds */
  latencyMs: number;
}

/** Operating mode */
export type VigilMode = 'enforce' | 'warn' | 'log';

/** Configuration options */
export interface VigilConfig {
  /** Operating mode: enforce (block), warn (log + allow), log (silent) */
  mode?: VigilMode;
  /** Custom callback for BLOCK/ESCALATE events */
  onViolation?: (result: VigilResult, input: VigilInput) => void;
}

/** Rule set definition */
export interface RuleSet {
  patterns: RegExp[];
  decision: Decision;
  risk: RiskLevel;
  desc: string;
}

/** Policy template */
export interface VigilPolicy {
  name: string;
  description: string;
  version: string;
  rules: {
    allowedTools?: string[];
    blockedTools?: string[];
    blockedPatterns?: Record<string, string[]>;
    allowedPaths?: string[];
    blockedPaths?: string[];
    maxParams?: Record<string, number>;
    network?: {
      allowOutbound?: boolean;
      blockedDomains?: string[];
    };
  };
}
