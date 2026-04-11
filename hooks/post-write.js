#!/usr/bin/env node
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createSafetyChecker } from "../dist/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const patternsDir = resolve(__dirname, "..", "patterns");
const checker = createSafetyChecker({ patternsDir });
const strict = process.env.AGENT_SAFETY_MODE === "strict";

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

// Extract content from Write, Edit, or MultiEdit tool payloads
const toolName = input?.tool_name ?? "";
let content = "";
if (toolName === "Edit") {
  content = input?.tool_input?.new_string ?? "";
} else if (toolName === "MultiEdit") {
  content = (input?.tool_input?.edits ?? []).map((e) => e.new_string ?? "").join("\n");
} else {
  // Write tool or fallback
  content = input?.tool_input?.content ?? "";
}

const result = checker.checkContentSecrets(content);

if (result.decision === "deny") {
  const context = `WARNING: Written file content may contain secrets (${result.matchCount} pattern(s) matched: ${result.matchedPatterns.slice(0, 3).join(", ")}). Review the file and remove any credentials before committing.`;
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
