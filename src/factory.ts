// src/factory.ts
import { join, resolve } from "node:path";
import { checkCommand } from "./checkers/command.js";
import { scanContent } from "./checkers/content.js";
import { checkPath } from "./checkers/path.js";
import { checkSearchQuery } from "./checkers/search-query.js";
import { type RemoteApiClient, checkUrl } from "./checkers/url.js";
import { resolveConfig } from "./config.js";
import { type LoadedFeeds, loadFeeds, loadFeedsAsync } from "./feeds/loader.js";
import { getFeedStatus } from "./feeds/status.js";
import {
  type CompiledPatternSet,
  loadPatternFile,
  loadPatternFileAsync,
} from "./patterns/loader.js";
import {
  type SensitivePathSet,
  loadSensitivePaths,
  loadSensitivePathsAsync,
} from "./patterns/sensitive-paths.js";
import { checkGoogleSafeBrowsing } from "./remote/google-safe-browsing.js";
import { checkSpamhausDbl } from "./remote/spamhaus-dbl.js";
import { checkUrlhaus } from "./remote/urlhaus.js";
import type {
  CheckResult,
  ContentCheckResult,
  FeedStatus,
  PathCheckResult,
  SafetyChecker,
  SafetyCheckerConfig,
  UrlCheckResult,
} from "./types.js";

interface LoadedPatterns {
  bashDeny: CompiledPatternSet;
  blocklist: CompiledPatternSet;
  secrets: CompiledPatternSet;
  injection: CompiledPatternSet;
  searchLeak: CompiledPatternSet;
  sensitivePaths: SensitivePathSet;
}

function loadAllPatterns(patternsDir: string): LoadedPatterns {
  return {
    bashDeny: loadPatternFile(join(patternsDir, "bash-deny.txt"), "i"),
    blocklist: loadPatternFile(join(patternsDir, "webfetch-domain-blocklist.txt"), "i"),
    secrets: loadPatternFile(join(patternsDir, "secrets-patterns.txt"), "im"),
    injection: loadPatternFile(join(patternsDir, "injection-patterns.txt"), "im"),
    searchLeak: loadPatternFile(join(patternsDir, "websearch-leak-patterns.txt"), "im"),
    sensitivePaths: loadSensitivePaths(join(patternsDir, "sensitive-paths.txt")),
  };
}

async function loadAllPatternsAsync(patternsDir: string): Promise<LoadedPatterns> {
  const [bashDeny, blocklist, secrets, injection, searchLeak, sensitivePaths] = await Promise.all([
    loadPatternFileAsync(join(patternsDir, "bash-deny.txt"), "i"),
    loadPatternFileAsync(join(patternsDir, "webfetch-domain-blocklist.txt"), "i"),
    loadPatternFileAsync(join(patternsDir, "secrets-patterns.txt"), "im"),
    loadPatternFileAsync(join(patternsDir, "injection-patterns.txt"), "im"),
    loadPatternFileAsync(join(patternsDir, "websearch-leak-patterns.txt"), "im"),
    loadSensitivePathsAsync(join(patternsDir, "sensitive-paths.txt")),
  ]);
  return { bashDeny, blocklist, secrets, injection, searchLeak, sensitivePaths };
}

function buildRemoteClients(config: ReturnType<typeof resolveConfig>): RemoteApiClient[] {
  const clients: RemoteApiClient[] = [];

  if (config.remoteApis.urlhaus) {
    clients.push({
      name: "urlhaus",
      check: (url, _domain, timeout) => checkUrlhaus(url, timeout),
    });
  }

  if (config.remoteApis.googleSafeBrowsing) {
    const key = config.remoteApis.googleSafeBrowsing;
    clients.push({
      name: "google-safe-browsing",
      check: (url, _domain, timeout) => checkGoogleSafeBrowsing(url, key, timeout),
    });
  }

  if (config.remoteApis.spamhausDbl) {
    clients.push({
      name: "spamhaus-dbl",
      check: (_url, domain, timeout) => checkSpamhausDbl(domain, timeout),
    });
  }

  return clients;
}

export function createSafetyChecker(input?: SafetyCheckerConfig): SafetyChecker {
  const config = resolveConfig(input);
  let patterns = loadAllPatterns(config.patternsDir);
  let feedsData = loadFeeds(config.feedsDir);
  const remoteClients = buildRemoteClients(config);

  const checker: SafetyChecker = {
    get config() {
      return config as Readonly<typeof config>;
    },

    checkCommand(command: string): CheckResult {
      return checkCommand(command, patterns.bashDeny);
    },

    checkUrl(url: string): Promise<UrlCheckResult> {
      return checkUrl(
        url,
        patterns.blocklist,
        feedsData.feeds,
        config.localFeeds,
        remoteClients,
        config.timeouts.remoteApi,
      );
    },

    checkPath(filePath: string): PathCheckResult {
      // Resolve to absolute path so patterns anchored with ^/ match correctly
      const absPath = resolve(filePath);
      return checkPath(absPath, patterns.sensitivePaths, config.strict);
    },

    checkContentSecrets(content: string): ContentCheckResult {
      return scanContent(content, patterns.secrets);
    },

    checkContentInjection(content: string): ContentCheckResult {
      return scanContent(content, patterns.injection);
    },

    checkSearchQuery(query: string): ContentCheckResult {
      return checkSearchQuery(query, patterns.searchLeak);
    },

    feedStatus(): FeedStatus {
      return getFeedStatus(config.feedsDir, feedsData.feeds);
    },

    reload(): void {
      patterns = loadAllPatterns(config.patternsDir);
      feedsData = loadFeeds(config.feedsDir);
    },

    async reloadAsync(): Promise<void> {
      const [newPatterns, newFeedsData] = await Promise.all([
        loadAllPatternsAsync(config.patternsDir),
        loadFeedsAsync(config.feedsDir),
      ]);
      patterns = newPatterns;
      feedsData = newFeedsData;
    },
  };

  return checker;
}

export async function createSafetyCheckerAsync(
  input?: SafetyCheckerConfig,
): Promise<SafetyChecker> {
  const config = resolveConfig(input);
  let patterns = await loadAllPatternsAsync(config.patternsDir);
  let feedsData = await loadFeedsAsync(config.feedsDir);
  const remoteClients = buildRemoteClients(config);

  const checker: SafetyChecker = {
    get config() {
      return config as Readonly<typeof config>;
    },

    checkCommand(command: string): CheckResult {
      return checkCommand(command, patterns.bashDeny);
    },

    checkUrl(url: string): Promise<UrlCheckResult> {
      return checkUrl(
        url,
        patterns.blocklist,
        feedsData.feeds,
        config.localFeeds,
        remoteClients,
        config.timeouts.remoteApi,
      );
    },

    checkPath(filePath: string): PathCheckResult {
      const absPath = resolve(filePath);
      return checkPath(absPath, patterns.sensitivePaths, config.strict);
    },

    checkContentSecrets(content: string): ContentCheckResult {
      return scanContent(content, patterns.secrets);
    },

    checkContentInjection(content: string): ContentCheckResult {
      return scanContent(content, patterns.injection);
    },

    checkSearchQuery(query: string): ContentCheckResult {
      return checkSearchQuery(query, patterns.searchLeak);
    },

    feedStatus(): FeedStatus {
      return getFeedStatus(config.feedsDir, feedsData.feeds);
    },

    reload(): void {
      patterns = loadAllPatterns(config.patternsDir);
      feedsData = loadFeeds(config.feedsDir);
    },

    async reloadAsync(): Promise<void> {
      const [newPatterns, newFeedsData] = await Promise.all([
        loadAllPatternsAsync(config.patternsDir),
        loadFeedsAsync(config.feedsDir),
      ]);
      patterns = newPatterns;
      feedsData = newFeedsData;
    },
  };

  return checker;
}
