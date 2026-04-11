// src/index.ts
export { createSafetyChecker, createSafetyCheckerAsync } from "./factory.js";
export type {
  SafetyCheckerConfig,
  SafetyChecker,
  CheckResult,
  CheckDecision,
  UrlCheckResult,
  PathCheckResult,
  ContentCheckResult,
  FeedStatus,
  FeedInfo,
  ResolvedConfig,
} from "./types.js";
