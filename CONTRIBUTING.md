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
- bash, grep (with -E), jq, curl
- ShellCheck (for linting shell scripts)

## How to Contribute

### Adding Patterns

Pattern files live in `patterns/`. Each file is one regex per line with `#` comments.

When adding or modifying patterns:

1. Add the regex to the appropriate file in `patterns/`
2. Add test cases in `test/` covering both true positives and true negatives
3. Test against realistic benign inputs to avoid false positives

### Adding an Integration

See `integrations/claude-code/` as a reference. An integration is a thin adapter that:

1. Parses the agent's tool call format
2. Calls `lib/check.sh` functions or pipes to `integrations/generic/check-*.sh`
3. Maps results to the agent's allow/deny mechanism

### Code Style

- Shell scripts: follow ShellCheck recommendations, use `set -euo pipefail`
- JavaScript: run `npm run lint:fix` before committing

## Pull Requests

1. Fork the repo and create a branch from `main`
2. Add tests for any new functionality
3. Run `npm test` and `npm run lint` locally
4. Keep PRs focused -- one pattern category or one integration per PR

## Reporting Security Issues

If you find a bypass or vulnerability in the safety checks, please report it responsibly. Open a GitHub issue -- these are safety patterns, not secrets, so public discussion helps the community.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
