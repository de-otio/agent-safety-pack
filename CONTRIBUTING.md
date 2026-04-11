# Contributing to Agent Safety Pack

Thanks for your interest in improving AI agent safety!

## Getting Started

```bash
git clone https://github.com/de-otio/agent-safety-pack.git
cd agent-safety-pack
npm install
npm test
```

### Requirements

- Node.js >= 20

## Development Commands

```bash
npm run build      # ESM + CJS build
npm test           # Run tests (vitest)
npm run lint       # Biome check + tsc --noEmit
npm run lint:fix   # Auto-fix lint issues
```

## How to Contribute

### Adding Patterns

Pattern files live in `patterns/`. Each file is one regex per line with `#` comments.

When adding or modifying patterns:

1. Add the regex to the appropriate file in `patterns/`
2. Add test cases covering both true positives and true negatives
3. Test against realistic benign inputs to avoid false positives
4. Run `npm test` to verify no regressions

Pattern compilation flags are set per file in `src/factory.ts`:
- `bash-deny.txt` — `i` (case-insensitive)
- `webfetch-domain-blocklist.txt` — `i`
- `secrets-patterns.txt` — `im` (case-insensitive + multiline)
- `injection-patterns.txt` — `im`
- `websearch-leak-patterns.txt` — `im`
- `sensitive-paths.txt` — `i` (compiled in `sensitive-paths.ts`)

### Adding a Hook

Hook scripts live in `hooks/`. Each hook:

1. Reads JSON from stdin
2. Calls the safety checker library
3. Writes JSON to stdout
4. Exits with code 2 (deny), 0 (allow/ask)

See `hooks/pre-bash.js` as a reference. All hooks must include try/catch around `JSON.parse` and fail closed (exit 2) on parse errors.

Update `hooks/settings.json` with the new hook's matcher and command.

### Code Style

- TypeScript: run `npm run lint:fix` before committing
- Biome handles formatting and import ordering
- No runtime dependencies — dev dependencies only

## Pull Requests

1. Fork the repo and create a branch from `main`
2. Add tests for any new functionality
3. Run `npm run lint && npm test` locally
4. Keep PRs focused — one pattern category or one feature per PR

## Reporting Security Issues

If you find a bypass or vulnerability in the safety checks, please report it responsibly. Open a GitHub issue — these are safety patterns, not secrets, so public discussion helps the community.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
