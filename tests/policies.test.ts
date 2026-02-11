import { describe, it, expect } from 'vitest';
import { loadPolicy, listPolicies } from '../src/policies.js';

describe('Policy Loading', () => {
  it('lists all built-in policies', () => {
    const policies = listPolicies();
    expect(policies).toEqual(['restrictive', 'moderate', 'permissive']);
  });

  it('loads restrictive policy', () => {
    const policy = loadPolicy('restrictive');
    expect(policy.name).toBe('restrictive');
    expect(policy.version).toBe('1.0');
    expect(policy.rules).toBeDefined();
    expect(policy.rules.blockedTools).toContain('exec');
  });

  it('loads moderate policy', () => {
    const policy = loadPolicy('moderate');
    expect(policy.name).toBe('moderate');
    expect(policy.rules.allowedTools).toContain('exec');
  });

  it('loads permissive policy', () => {
    const policy = loadPolicy('permissive');
    expect(policy.name).toBe('permissive');
    expect(policy.rules.allowedTools).toContain('*');
  });

  it('throws on invalid path', () => {
    expect(() => loadPolicy('/nonexistent/policy.json')).toThrow('Failed to load policy');
  });
});
