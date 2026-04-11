#!/usr/bin/env node
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createSafetyChecker } from "../dist/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const patternsDir = resolve(__dirname, "..", "patterns");
const checker = createSafetyChecker({ patternsDir });
const strict = process.env.AGENT_SAFETY_MODE === "strict";

const input = JSON.parse(await readStdin());
const output = input?.tool_response?.output ?? "";

const result = checker.checkContentSecrets(output);

if (result.decision === "deny") {
  const context = `WARNING: Command output may contain secrets (${result.matchCount} pattern(s) matched: ${result.matchedPatterns.slice(0, 3).join(", ")}). Do not log, share, or use these values.`;
  if (strict) {
    process.stdout.write(JSON.stringify({ additionalContext: context }));
    process.exit(2);
  }
  process.stdout.write(JSON.stringify({ additionalContext: context }));
}

process.exit(0);

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf-8") || "{}";
}
