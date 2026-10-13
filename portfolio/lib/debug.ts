// Guarded debug logger. Off by default.
// Enable with NEXT_PUBLIC_DEBUG=true (build and browser) or ?debug=1 in the browser.
// Used by the cursor, the work index, the lens key, and the content gates during the build.

type Level = "log" | "warn" | "info";

const ENV_FLAG = process.env.NEXT_PUBLIC_DEBUG === "true";

function queryFlag(): boolean {
  if (typeof window === "undefined") return false;
  try {
    const params = new URLSearchParams(window.location.search);
    if (params.get("debug") === "1") {
      window.sessionStorage.setItem("portfolio:debug", "1");
      return true;
    }
    return window.sessionStorage.getItem("portfolio:debug") === "1";
  } catch {
    return false;
  }
}

export function debugEnabled(): boolean {
  return ENV_FLAG || queryFlag();
}

function emit(level: Level, scope: string, args: unknown[]) {
  if (!debugEnabled()) return;
  const prefix = `[portfolio:${scope}]`;
  // eslint-disable-next-line no-console
  console[level](prefix, ...args);
}

export const debug = {
  log: (scope: string, ...args: unknown[]) => emit("log", scope, args),
  info: (scope: string, ...args: unknown[]) => emit("info", scope, args),
  warn: (scope: string, ...args: unknown[]) => emit("warn", scope, args),
};

// Build-time logging for content gates. Always on during `next build` so that nothing is
// excluded silently, printed once per excluded record.
const seen = new Set<string>();
export function buildLog(message: string) {
  if (typeof window !== "undefined") return;
  if (seen.has(message)) return;
  seen.add(message);
  // eslint-disable-next-line no-console
  console.log(`[portfolio:content] ${message}`);
}
