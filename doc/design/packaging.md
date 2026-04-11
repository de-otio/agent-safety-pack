# Packaging

## npm Package Structure

```
agent-safety-pack/
  src/                         TypeScript source
    index.ts
    factory.ts
    types.ts
    config.ts
    patterns/
    checkers/
    feeds/
    remote/
    utils/
  dist/                        Compiled TypeScript output (ESM)
    index.js
    index.d.ts
    index.d.ts.map
    ... (mirrors src/ structure)
  dist-cjs/                    CommonJS entry point
    index.cjs
    ... (mirrors src/ structure)
  patterns/                    Pattern .txt files (shipped as-is)
    bash-deny.txt
    secrets-patterns.txt
    sensitive-paths.txt
    webfetch-domain-blocklist.txt
    injection-patterns.txt
    websearch-leak-patterns.txt
  LICENSE
  README.md
```

## package.json

```jsonc
{
  "name": "@de-otio/agent-safety-pack",
  "version": "0.2.0",
  "description": "Safety checks and pattern databases for AI coding agents.",
  "license": "MIT",
  "type": "module",

  // Dual ESM/CJS support
  "main": "./dist-cjs/index.cjs",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "import": {
        "types": "./dist/index.d.ts",
        "default": "./dist/index.js"
      },
      "require": {
        "types": "./dist-cjs/index.d.cts",
        "default": "./dist-cjs/index.cjs"
      }
    },
    "./patterns/*": "./patterns/*"
  },

  "files": [
    "dist/",
    "dist-cjs/",
    "patterns/",
    "LICENSE",
    "README.md"
  ],

  "scripts": {
    "build": "tspc && tspc -p tsconfig.cjs.json",
    "test": "vitest run",
    "test:watch": "vitest",
    "lint": "biome check . && tsc --noEmit",
    "lint:fix": "biome check --write .",
    "prepublishOnly": "npm run build && npm test"
  },

  "devDependencies": {
    "@biomejs/biome": "^1.9.0",
    "typescript": "^5.5.0",
    "ts-patch": "^3.0.0",
    "vitest": "^2.0.0"
  },

  "engines": {
    "node": ">=20.0.0"
  },

  "os": ["darwin", "linux", "win32"]
}
```

## Minimum Node Version

**Node >= 20.0.0.** Rationale:
- Node 18 is EOL. Node 20 is the minimum supported LTS release.
- `fetch` is available globally starting Node 18 (required for remote API calls)
- `node:dns/promises` is stable in Node 18+
- `node:fs/promises` is stable in Node 18+

## TypeScript Configuration

**tsconfig.json (ESM):**
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "lib": ["ES2022"],
    "outDir": "dist",
    "rootDir": "src",
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "isolatedModules": true,
    "verbatimModuleSyntax": true
  },
  "include": ["src/**/*.ts"],
  "exclude": ["node_modules", "dist", "dist-cjs", "test"]
}
```

**tsconfig.cjs.json (CJS):**
```json
{
  "extends": "./tsconfig.json",
  "compilerOptions": {
    "module": "CommonJS",
    "moduleResolution": "node",
    "outDir": "dist-cjs",
    "verbatimModuleSyntax": false,
    "declaration": true
  }
}
```

CJS output uses `.cjs` extension (via build script renaming or `ts-patch` transform).

## ESM/CJS Dual Support

The library is authored as ESM (`"type": "module"` in package.json). CJS consumers get a separately compiled output in `dist-cjs/`. The `exports` field in package.json routes `import` to ESM and `require` to CJS.

**Why dual support:** Many AI agent frameworks still use CommonJS (older Express-based servers, AWS Lambda handlers). Requiring ESM-only would limit adoption.

## Pattern File Bundling

Pattern files are shipped as-is in the npm package. They are not compiled, bundled, or embedded in JavaScript. The library resolves the `patterns/` directory relative to its own installation:

```typescript
// src/config.ts
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

function defaultPatternsDir(): string {
  // dist/config.js -> dist/ -> package root -> patterns/
  return resolve(__dirname, '..', 'patterns');
}
```

For CJS:
```typescript
function defaultPatternsDir(): string {
  return resolve(__dirname, '..', 'patterns');
}
```

The `"./patterns/*"` export in package.json also allows consumers to import pattern files directly if they want to process them themselves.

## Dependencies

**Runtime dependencies: zero.** The library uses only Node built-in modules:
- `node:fs` and `node:fs/promises` -- file reading
- `node:path` -- path resolution
- `node:url` -- `fileURLToPath` for ESM `__dirname`
- `node:dns/promises` -- Spamhaus DBL lookup
- Global `fetch` -- URLhaus and Google Safe Browsing API calls (Node 18+)

**Dev dependencies:**
- `typescript` -- compilation
- `@biomejs/biome` -- linting/formatting
- `vitest` -- testing
- `ts-patch` -- optional, for CJS output renaming

## Test Strategy

Tests live in `test/`:

```
test/
  patterns/
    loader.test.ts
    matcher.test.ts
    sensitive-paths.test.ts
  checkers/
    command.test.ts
    url.test.ts
    path.test.ts
    content.test.ts
    search-query.test.ts
  feeds/
    loader.test.ts
  remote/
    urlhaus.test.ts
    google-safe-browsing.test.ts
    spamhaus-dbl.test.ts
  config.test.ts
  factory.test.ts
```

## Build and Publish

```bash
# Build
npm run build     # compiles src/ -> dist/ (ESM) and dist-cjs/ (CJS)

# Test
npm test          # runs vitest (unit + parity tests)

# Publish
npm publish       # runs prepublishOnly (build + test) then publishes
```
