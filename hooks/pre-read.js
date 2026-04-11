#!/usr/bin/env node
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createSafetyChecker } from "../dist/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const patternsDir = resolve(__dirname, "..", "patterns");
const checker = createSafetyChecker({ patternsDir });

let input;
try {
  input = JSON.parse(await readStdin());
} catch {
  process.stdout.write(
    JSON.stringify({
      permissionDecision: "deny",
      additionalContext: "Safety hook failed to parse input — denying for safety",
    }),
  );
  process.exit(2);
}

const filePath = input?.tool_input?.file_path ?? "";

if (!filePath) {
  process.exit(0);
}

const result = checker.checkPath(filePath);

if (result.decision === "deny") {
  process.stdout.write(
    JSON.stringify({
      permissionDecision: "deny",
      additionalContext: result.reason ?? "File path blocked by safety check",
    }),
  );
  process.exit(2);
}

if (result.decision === "ask") {
  process.stdout.write(
    JSON.stringify({
      permissionDecision: "ask",
      additionalContext: result.reason ?? "File path requires user review",
    }),
  );
  process.exit(0);
}

process.exit(0);

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf-8") || "{}";
}
