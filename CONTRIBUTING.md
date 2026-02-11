# Contributing to Vigil

Thanks for your interest in making AI agents safer! Here's how to contribute.

## Development Setup

```bash
git clone https://github.com/hexitlabs/vigil.git
cd vigil
npm install
npm run build
npm test
```

## Adding Rules

Rules live in `src/rules.ts`. Each rule is a regex pattern in a category:

1. Add your pattern to the appropriate category array
2. Add a test case in `tests/rules.test.ts`
3. Run `npm test` to verify
4. Submit a PR

## Guidelines

- **Zero runtime dependencies** — this is non-negotiable
- **Keep it fast** — all checks must complete in <2ms
- **Test everything** — every rule needs at least one BLOCK and one ALLOW test
- **No false positives on common commands** — `git log`, `ls`, `npm install` must always ALLOW

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
