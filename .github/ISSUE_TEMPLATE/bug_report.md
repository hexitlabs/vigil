---
name: Bug Report
about: Report a rule gap, false positive, or unexpected behavior
title: '[Bug] '
labels: bug
assignees: ''
---

## Description

A clear description of the bug.

## Tool Call

The tool call that triggered the issue:

```json
{
  "tool": "example_tool",
  "params": {
    "key": "value"
  }
}
```

## Expected Behavior

What should Vigil have done? (e.g., "Should have blocked this call" or "Should have allowed this call")

## Actual Behavior

What did Vigil actually do?

## Policy / Rules

Which policy or rules were active?

```ts
const vigil = createVigil({ policy: 'strict' });
```

## Environment

- **Vigil version**: 
- **Node version**: 
- **Integration**: (standalone / MCP / LangChain / other)

## Additional Context

Any other context, logs, or screenshots.
