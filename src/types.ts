// src/types.ts

export type CheckDecision = "allow" | "deny" | "ask";

export interface CheckResult {
  decision: CheckDecision;
  matchedPattern?: string;
  source?: string;
  reason?: string;
}

export interface UrlCheckResult extends CheckResult {
  url: string;
  tier?: "blocklist" | "feed" | "api";
  feedName?: string;
  threatType?: string;
  threatDetail?: string;
  /** Names of remote APIs that failed (timeout, network error, etc.) and fell back to allow. */
  remoteErrors?: string[];
}

export interface PathCheckResult extends CheckResult {
  filePath: string;
  section?: "deny" | "ask";
}

export interface ContentCheckResult extends CheckResult {
  matchedPatterns: string[];
  matchCount: number;
}

export interface FeedInfo {
  name: string;
  path: string;
  entryCount: number;
  ageSeconds: number;
  stale: boolean;
}

export interface FeedStatus {
  status: "ok" | "stale" | "no-feeds" | "no-feeds-dir";
  feedCount: number;
  staleFeedCount: number;
  feeds: FeedInfo[];
}

export interface SafetyCheckerConfig {
  patternsDir?: string;
  feedsDir?: string;
  strict?: boolean;
  localFeeds?: boolean;
  remoteApis?: {
    urlhaus?: boolean;
    googleSafeBrowsing?: string;
    spamhausDbl?: boolean;
  };
  timeouts?: {
    remoteApi?: number;
  };
}

export interface ResolvedConfig {
  patternsDir: string;
  feedsDir: string;
  strict: boolean;
  localFeeds: boolean;
  remoteApis: {
    urlhaus: boolean;
    googleSafeBrowsing: string | undefined;
    spamhausDbl: boolean;
  };
  timeouts: {
    remoteApi: number;
  };
}

export interface SafetyChecker {
  checkCommand(command: string): CheckResult;
  checkUrl(url: string): Promise<UrlCheckResult>;
  checkPath(filePath: string): PathCheckResult;
  checkContentSecrets(content: string): ContentCheckResult;
  checkContentInjection(content: string): ContentCheckResult;
  checkSearchQuery(query: string): ContentCheckResult;
  feedStatus(): FeedStatus;
  reload(): void;
  reloadAsync(): Promise<void>;
  readonly config: Readonly<ResolvedConfig>;
}
