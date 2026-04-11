// src/config.ts
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { ResolvedConfig, SafetyCheckerConfig } from "./types.js";

function defaultPatternsDir(): string {
  // In CJS builds, the Node.js module wrapper injects __dirname as a local string.
  // In ESM builds, __dirname is typed by @types/node but undefined at runtime.
  // typeof avoids a ReferenceError when the variable truly doesn't exist.
  if (typeof __dirname === "string" && __dirname !== "") {
    return resolve(__dirname, "..", "patterns");
  }
  // ESM fallback: import.meta.url cannot be written directly in a file that is also
  // compiled for CommonJS (TS1343). Use new Function() to defer parsing to runtime.
  // eslint-disable-next-line no-new-func
  const metaUrl = new Function("return import.meta.url")() as string;
  return resolve(dirname(fileURLToPath(metaUrl)), "..", "patterns");
}

export function resolveConfig(input?: SafetyCheckerConfig): ResolvedConfig {
  const patternsDir = input?.patternsDir ?? defaultPatternsDir();
  const feedsDir = input?.feedsDir ?? resolve(patternsDir, "..", "feeds");

  // Strict mode: explicit config > env var > default false
  let strict = false;
  if (input?.strict !== undefined) {
    strict = input.strict;
  } else if (process.env.AGENT_SAFETY_MODE === "strict") {
    strict = true;
  }

  // localFeeds: explicit config > env var > default true
  let localFeeds = true;
  if (input?.localFeeds !== undefined) {
    localFeeds = input.localFeeds;
  } else if (process.env.AGENT_SAFETY_LOCAL_FEEDS === "0") {
    localFeeds = false;
  }

  // Remote APIs: explicit config > env var > default disabled
  const urlhaus =
    input?.remoteApis?.urlhaus !== undefined
      ? input.remoteApis.urlhaus
      : process.env.AGENT_SAFETY_URLHAUS === "1";

  const googleSafeBrowsing =
    input?.remoteApis?.googleSafeBrowsing !== undefined
      ? input.remoteApis.googleSafeBrowsing
      : process.env.AGENT_SAFETY_GSB_KEY;

  const spamhausDbl =
    input?.remoteApis?.spamhausDbl !== undefined
      ? input.remoteApis.spamhausDbl
      : process.env.AGENT_SAFETY_DNSBL === "1";

  const remoteApiTimeout = input?.timeouts?.remoteApi ?? 5000;

  return {
    patternsDir,
    feedsDir,
    strict,
    localFeeds,
    remoteApis: {
      urlhaus,
      googleSafeBrowsing,
      spamhausDbl,
    },
    timeouts: {
      remoteApi: remoteApiTimeout,
    },
  };
}
