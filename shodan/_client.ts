import { z } from "npm:zod@4.3.6";

/**
 * Shared client, schema, and context types for the `@dougschaefer/shodan`
 * model.
 *
 * Shodan is an internet-wide scan database (https://www.shodan.io). This model
 * talks to its REST API at `https://api.shodan.io` plus the keyless InternetDB
 * service at `https://internetdb.shodan.io`. Authentication is a single API key
 * passed as the `key` query parameter on every REST call; InternetDB needs no
 * key at all.
 *
 * Every method here is passive OSINT: it reads Shodan's existing index. The one
 * exception is `requestScan`, which asks Shodan to (re)scan IP addresses you
 * own and spends scan credits. Nothing in this model connects to, logs into, or
 * exploits a third-party device.
 *
 * The API key lives in `globalArguments` and resolves from vault, e.g.:
 *   apiKey: ${{ vault.get(asei, shodan-api-key) }}
 *
 * Plain `fetch` (HTTPS + JSON) is used, so the bundle has no native deps.
 */

/** Connection + credentials for one Shodan account. */
export const ShodanGlobalArgsSchema = z.object({
  apiKey: z.string().meta({ sensitive: true }).describe(
    "Shodan API key. Use: ${{ vault.get(<vault>, shodan-api-key) }}",
  ),
  baseUrl: z.string().default("https://api.shodan.io").describe(
    "Base URL of the Shodan REST API",
  ),
  internetDbUrl: z.string().default("https://internetdb.shodan.io").describe(
    "Base URL of the keyless Shodan InternetDB service",
  ),
  timeoutMs: z.number().int().default(30000).describe(
    "Per-request timeout in milliseconds",
  ),
});

/** Resolved connection + credentials for one Shodan account. */
export type ShodanGlobalArgs = z.infer<typeof ShodanGlobalArgsSchema>;

/** Trim any trailing slashes from a configured base URL. */
function trimSlash(url: string): string {
  return url.replace(/\/+$/, "");
}

/**
 * Low-level Shodan REST request. Resolves the JSON (or text) body and throws on
 * a non-2xx status, surfacing Shodan's `{ "error": ... }` message. The API key
 * is appended to the query string here so callers never handle it. `form`, when
 * present, is sent as an `application/x-www-form-urlencoded` body (used by the
 * scan-request endpoint).
 */
export async function shodanRequest(
  g: ShodanGlobalArgs,
  method: string,
  path: string,
  opts: { query?: Record<string, string>; form?: Record<string, string> } = {},
): Promise<{ status: number; data: unknown }> {
  const url = new URL(trimSlash(g.baseUrl) + path);
  url.searchParams.set("key", g.apiKey);
  if (opts.query) {
    for (const [k, v] of Object.entries(opts.query)) {
      if (v !== undefined && v !== "") url.searchParams.set(k, String(v));
    }
  }
  const headers: Record<string, string> = { accept: "application/json" };
  let body: string | undefined;
  if (opts.form) {
    headers["content-type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(opts.form).toString();
  }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), g.timeoutMs);
  let res: Response;
  try {
    res = await fetch(url, { method, headers, body, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
  const text = await res.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!res.ok) {
    const msg = errorMessage(data) ?? text.slice(0, 300);
    throw new Error(`Shodan ${method} ${path} -> HTTP ${res.status}: ${msg}`);
  }
  return { status: res.status, data };
}

/**
 * Keyless InternetDB lookup for one IP. Returns the parsed body, or `null` when
 * Shodan has no information for the address (a 404 with a `detail` message,
 * which is a normal "nothing here" answer, not an error).
 */
export async function internetDbLookup(
  g: ShodanGlobalArgs,
  ip: string,
): Promise<unknown | null> {
  const url = `${trimSlash(g.internetDbUrl)}/${encodeURIComponent(ip)}`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), g.timeoutMs);
  let res: Response;
  try {
    res = await fetch(url, {
      headers: { accept: "application/json" },
      signal: ctrl.signal,
    });
  } finally {
    clearTimeout(timer);
  }
  const text = await res.text();
  if (res.status === 404) return null;
  if (!res.ok) {
    throw new Error(
      `InternetDB ${ip} -> HTTP ${res.status}: ${text.slice(0, 200)}`,
    );
  }
  return text ? JSON.parse(text) : null;
}

/** Pull Shodan's `{ "error": "..." }` message out of a response body, if present. */
function errorMessage(data: unknown): string | undefined {
  if (data && typeof data === "object") {
    const e = (data as Record<string, unknown>).error;
    if (typeof e === "string") return e;
    const d = (data as Record<string, unknown>).detail;
    if (typeof d === "string") return d;
  }
  return undefined;
}

/** A Shodan search/host banner trimmed to the fields worth showing on a screen. */
export interface ShodanDevice {
  ip: string;
  port: number;
  transport: string;
  org: string;
  isp: string;
  asn: string;
  product: string;
  version: string;
  os: string;
  hostnames: string[];
  domains: string[];
  city: string;
  country: string;
  countryCode: string;
  httpTitle: string;
  httpServer: string;
  vulns: string[];
  tags: string[];
  hasScreenshot: boolean;
  timestamp: string;
}

/** Map one raw Shodan match/banner object to the trimmed {@link ShodanDevice} shape. */
export function mapDevice(raw: unknown): ShodanDevice {
  const m = (raw ?? {}) as Record<string, unknown>;
  const loc = (m.location ?? {}) as Record<string, unknown>;
  const http = (m.http ?? {}) as Record<string, unknown>;
  const opts = (m.opts ?? {}) as Record<string, unknown>;
  const str = (
    v: unknown,
  ): string => (v === undefined || v === null ? "" : String(v));
  const arr = (v: unknown): string[] =>
    Array.isArray(v) ? v.map((x) => String(x)) : [];
  return {
    ip: str(m.ip_str),
    port: Number(m.port ?? 0),
    transport: str(m.transport),
    org: str(m.org),
    isp: str(m.isp),
    asn: str(m.asn),
    product: str(m.product),
    version: str(m.version),
    os: str(m.os),
    hostnames: arr(m.hostnames),
    domains: arr(m.domains),
    city: str(loc.city),
    country: str(loc.country_name),
    countryCode: str(loc.country_code),
    httpTitle: str(http.title),
    httpServer: str(http.server),
    vulns: m.vulns && typeof m.vulns === "object" && !Array.isArray(m.vulns)
      ? Object.keys(m.vulns as Record<string, unknown>)
      : arr(m.vulns),
    tags: arr(m.tags),
    hasScreenshot: Boolean(opts.screenshot) ||
      Boolean((m as Record<string, unknown>).screenshot),
    timestamp: str(m.timestamp),
  };
}

/**
 * Flatten Shodan's facet structure (`{ facet: [{ count, value }, ...] }`) into a
 * plain record so it is easy to read off a workflow output.
 */
export function mapFacets(
  raw: unknown,
): Record<string, Array<{ value: string; count: number }>> {
  const out: Record<string, Array<{ value: string; count: number }>> = {};
  if (raw && typeof raw === "object") {
    for (
      const [facet, rows] of Object.entries(raw as Record<string, unknown>)
    ) {
      if (Array.isArray(rows)) {
        out[facet] = rows.map((r) => {
          const o = (r ?? {}) as Record<string, unknown>;
          return { value: String(o.value ?? ""), count: Number(o.count ?? 0) };
        });
      }
    }
  }
  return out;
}

/**
 * Compose a Shodan search query from a base query plus optional `city` and
 * `country` convenience filters, so a recon run can be scoped to a place
 * without the caller hand-writing Shodan filter syntax.
 */
export function composeQuery(
  query: string,
  city?: string,
  country?: string,
): string {
  const parts = [query.trim()];
  if (city && city.trim()) parts.push(`city:${JSON.stringify(city.trim())}`);
  if (country && country.trim()) {
    parts.push(`country:${JSON.stringify(country.trim())}`);
  }
  return parts.filter((p) => p.length > 0).join(" ");
}

/**
 * Turn a Shodan query into a short, name-safe slug used to name the data
 * instance a method writes. Callers prefix it per method (e.g. `search-`,
 * `count-`) so different methods never collide on one data name.
 */
export function slugify(query: string, fallback = "all"): string {
  return query.replace(/[^a-zA-Z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(
    0,
    40,
  ) || fallback;
}

/** Minimal shape of the swamp method context this model uses. */
export interface MethodContext {
  globalArgs: ShodanGlobalArgs;
  logger: {
    info: (msg: string, props?: Record<string, unknown>) => void;
    warning: (msg: string, props?: Record<string, unknown>) => void;
  };
  writeResource: (
    spec: string,
    instance: string,
    data: Record<string, unknown>,
  ) => Promise<DataHandle>;
}

/** Reference returned by `writeResource`, returned from a method's execute. */
export interface DataHandle {
  name: string;
  specName: string;
}
