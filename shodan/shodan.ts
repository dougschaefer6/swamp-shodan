import { z } from "npm:zod@4.3.6";
import {
  composeQuery,
  type DataHandle,
  internetDbLookup,
  mapDevice,
  mapFacets,
  type MethodContext,
  ShodanGlobalArgsSchema,
  shodanRequest,
  slugify,
} from "./_client.ts";

/**
 * `@dougschaefer/shodan` model — queries the Shodan internet-wide scan database
 * (https://www.shodan.io) to find and profile internet-exposed devices.
 *
 * It authenticates with a single API key (resolved from vault) and reads
 * Shodan's existing index: `accountInfo` reports the plan and remaining query
 * and scan credits; `search` runs a Shodan search and returns trimmed device
 * records (IP, org, product, location, open port, CVEs) plus optional facet
 * rollups; `count` returns totals and facets without spending query credits;
 * `host` pulls the full banner history for one IP; and `internetdb` does a
 * keyless lookup of open ports, CPEs, tags, and known CVEs for one IP.
 *
 * Every one of those is passive OSINT. `requestScan` is the one active method:
 * it asks Shodan to (re)scan IP addresses you own and spends scan credits. The
 * model never connects to, logs into, or exploits a third-party device.
 *
 * Connection facts and the API key live in `globalArguments` so one model
 * definition is one Shodan account and the secret resolves from vault.
 */
export const model = {
  type: "@dougschaefer/shodan",
  version: "2026.06.16.1",
  globalArguments: ShodanGlobalArgsSchema,
  resources: {
    account: {
      description: "Shodan plan and remaining query/scan credits",
      schema: z.object({
        plan: z.string(),
        queryCredits: z.number(),
        scanCredits: z.number(),
        monitoredIps: z.number(),
        unlocked: z.boolean(),
        https: z.boolean(),
        telnet: z.boolean(),
        raw: z.unknown(),
        capturedAt: z.iso.datetime(),
      }),
      lifetime: "1d",
      garbageCollection: 5,
    },
    searchResult: {
      description: "Trimmed Shodan search results with optional facet rollups",
      schema: z.object({
        query: z.string(),
        total: z.number(),
        page: z.number(),
        returned: z.number(),
        truncated: z.boolean(),
        devices: z.array(z.unknown()),
        facets: z.record(z.string(), z.unknown()),
        capturedAt: z.iso.datetime(),
      }),
      lifetime: "7d",
      garbageCollection: 10,
    },
    countResult: {
      description:
        "Shodan result count + facets (does not spend query credits)",
      schema: z.object({
        query: z.string(),
        total: z.number(),
        facets: z.record(z.string(), z.unknown()),
        capturedAt: z.iso.datetime(),
      }),
      lifetime: "7d",
      garbageCollection: 10,
    },
    host: {
      description: "Full Shodan profile for a single IP address",
      schema: z.object({
        ip: z.string(),
        ports: z.array(z.number()),
        hostnames: z.array(z.string()),
        org: z.string(),
        isp: z.string(),
        country: z.string(),
        city: z.string(),
        os: z.string(),
        vulns: z.array(z.string()),
        lastUpdate: z.string(),
        services: z.array(z.unknown()),
        raw: z.unknown(),
        capturedAt: z.iso.datetime(),
      }),
      lifetime: "7d",
      garbageCollection: 5,
    },
    internetdb: {
      description:
        "Keyless InternetDB summary for a single IP (ports, CPEs, CVEs, tags)",
      schema: z.object({
        ip: z.string(),
        found: z.boolean(),
        ports: z.array(z.number()),
        cpes: z.array(z.string()),
        hostnames: z.array(z.string()),
        tags: z.array(z.string()),
        vulns: z.array(z.string()),
        capturedAt: z.iso.datetime(),
      }),
      lifetime: "7d",
      garbageCollection: 5,
    },
    scanRequest: {
      description:
        "Result of requesting an on-demand Shodan scan (spends scan credits)",
      schema: z.object({
        scanId: z.string(),
        ips: z.string(),
        count: z.number(),
        creditsLeft: z.number(),
        requestedAt: z.iso.datetime(),
      }),
      lifetime: "30d",
      garbageCollection: 10,
    },
  },
  methods: {
    accountInfo: {
      description:
        "Report the Shodan plan and remaining query/scan credits. Read-only; validates the API key.",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: MethodContext,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const { data } = await shodanRequest(
          context.globalArgs,
          "GET",
          "/api-info",
        );
        const d = (data ?? {}) as Record<string, unknown>;
        const handle = await context.writeResource("account", "account", {
          plan: String(d.plan ?? ""),
          queryCredits: Number(d.query_credits ?? 0),
          scanCredits: Number(d.scan_credits ?? 0),
          monitoredIps: Number(d.monitored_ips ?? 0),
          unlocked: Boolean(d.unlocked ?? false),
          https: Boolean(d.https ?? false),
          telnet: Boolean(d.telnet ?? false),
          raw: d,
          capturedAt: new Date().toISOString(),
        });
        context.logger.info(
          "Shodan plan '{plan}': {q} query credits, {s} scan credits left",
          {
            plan: String(d.plan ?? "?"),
            q: Number(d.query_credits ?? 0),
            s: Number(d.scan_credits ?? 0),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    search: {
      description:
        "Run a Shodan search and return trimmed device records plus optional facet rollups. Spends one query credit per page of 100 results.",
      arguments: z.object({
        query: z.string().describe(
          'Shodan search query, e.g. product:"Crestron" or "AMX NetLinx"',
        ),
        city: z.string().optional().describe("Optional city filter to append"),
        country: z.string().optional().describe(
          "Optional 2-letter country code filter to append",
        ),
        facets: z.string().optional().describe(
          "Comma-separated facets for rollups, e.g. country,org,product",
        ),
        page: z.number().int().default(1).describe(
          "Result page (100 per page)",
        ),
        limit: z.number().int().default(100).describe(
          "Cap the number of device records returned (1-100)",
        ),
      }),
      execute: async (
        args: {
          query: string;
          city?: string;
          country?: string;
          facets?: string;
          page: number;
          limit: number;
        },
        context: MethodContext,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const q = composeQuery(args.query, args.city, args.country);
        context.logger.info("Shodan search: {q} (page {page})", {
          q,
          page: args.page,
        });
        const { data } = await shodanRequest(
          context.globalArgs,
          "GET",
          "/shodan/host/search",
          {
            query: {
              query: q,
              facets: args.facets ?? "",
              page: String(args.page),
              minify: "false",
            },
          },
        );
        const d = (data ?? {}) as Record<string, unknown>;
        const matches = Array.isArray(d.matches) ? d.matches : [];
        const cap = Math.max(1, Math.min(100, args.limit));
        const devices = matches.slice(0, cap).map(mapDevice);
        const handle = await context.writeResource(
          "searchResult",
          `search-${slugify(q)}`,
          {
            query: q,
            total: Number(d.total ?? 0),
            page: args.page,
            returned: devices.length,
            truncated: Number(d.total ?? 0) > devices.length,
            devices,
            facets: mapFacets(d.facets),
            capturedAt: new Date().toISOString(),
          },
        );
        context.logger.info("{n} device(s) returned of {total} total", {
          n: devices.length,
          total: Number(d.total ?? 0),
        });
        return { dataHandles: [handle] };
      },
    },
    count: {
      description:
        "Return the total number of results for a Shodan query plus facet rollups, WITHOUT spending query credits. Ideal for 'how many exposed worldwide' stats.",
      arguments: z.object({
        query: z.string().describe("Shodan search query"),
        city: z.string().optional().describe("Optional city filter to append"),
        country: z.string().optional().describe(
          "Optional 2-letter country code filter to append",
        ),
        facets: z.string().optional().describe(
          "Comma-separated facets for rollups, e.g. country,org,product,port",
        ),
      }),
      execute: async (
        args: {
          query: string;
          city?: string;
          country?: string;
          facets?: string;
        },
        context: MethodContext,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const q = composeQuery(args.query, args.city, args.country);
        const { data } = await shodanRequest(
          context.globalArgs,
          "GET",
          "/shodan/host/count",
          {
            query: { query: q, facets: args.facets ?? "" },
          },
        );
        const d = (data ?? {}) as Record<string, unknown>;
        const handle = await context.writeResource(
          "countResult",
          `count-${slugify(q)}`,
          {
            query: q,
            total: Number(d.total ?? 0),
            facets: mapFacets(d.facets),
            capturedAt: new Date().toISOString(),
          },
        );
        context.logger.info("{total} results for {q}", {
          total: Number(d.total ?? 0),
          q,
        });
        return { dataHandles: [handle] };
      },
    },
    host: {
      description:
        "Pull the full Shodan profile for one IP address: open ports, services/banners, hostnames, and known CVEs. Read-only.",
      arguments: z.object({
        ip: z.string().describe("IP address to look up"),
        history: z.boolean().default(false).describe(
          "Include historical banners",
        ),
      }),
      execute: async (
        args: { ip: string; history: boolean },
        context: MethodContext,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const { data } = await shodanRequest(
          context.globalArgs,
          "GET",
          `/shodan/host/${encodeURIComponent(args.ip)}`,
          { query: { history: String(args.history), minify: "false" } },
        );
        const d = (data ?? {}) as Record<string, unknown>;
        const services = Array.isArray(d.data) ? d.data.map(mapDevice) : [];
        const vulns = Array.isArray(d.vulns)
          ? d.vulns.map((v) => String(v))
          : d.vulns && typeof d.vulns === "object"
          ? Object.keys(d.vulns as Record<string, unknown>)
          : [];
        const handle = await context.writeResource("host", `host-${args.ip}`, {
          ip: String(d.ip_str ?? args.ip),
          ports: Array.isArray(d.ports) ? d.ports.map((p) => Number(p)) : [],
          hostnames: Array.isArray(d.hostnames)
            ? d.hostnames.map((h) => String(h))
            : [],
          org: String(d.org ?? ""),
          isp: String(d.isp ?? ""),
          country: String(d.country_name ?? ""),
          city: String(d.city ?? ""),
          os: String(d.os ?? ""),
          vulns,
          lastUpdate: String(d.last_update ?? ""),
          services,
          raw: d,
          capturedAt: new Date().toISOString(),
        });
        context.logger.info(
          "{ip}: {ports} open port(s), {vulns} known CVE(s)",
          {
            ip: String(d.ip_str ?? args.ip),
            ports: Array.isArray(d.ports) ? d.ports.length : 0,
            vulns: vulns.length,
          },
        );
        return { dataHandles: [handle] };
      },
    },
    internetdb: {
      description:
        "Keyless InternetDB lookup for one IP: open ports, CPEs, hostnames, tags, and known CVEs. No API key or query credits used.",
      arguments: z.object({
        ip: z.string().describe("IP address to look up"),
      }),
      execute: async (
        args: { ip: string },
        context: MethodContext,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const data = await internetDbLookup(context.globalArgs, args.ip);
        const d = (data ?? {}) as Record<string, unknown>;
        const found = data !== null;
        const arr = (v: unknown): string[] =>
          Array.isArray(v) ? v.map((x) => String(x)) : [];
        const handle = await context.writeResource(
          "internetdb",
          `idb-${args.ip}`,
          {
            ip: String(d.ip ?? args.ip),
            found,
            ports: Array.isArray(d.ports) ? d.ports.map((p) => Number(p)) : [],
            cpes: arr(d.cpes),
            hostnames: arr(d.hostnames),
            tags: arr(d.tags),
            vulns: arr(d.vulns),
            capturedAt: new Date().toISOString(),
          },
        );
        context.logger.info("InternetDB {ip}: {found}", {
          ip: args.ip,
          found: found ? "data found" : "no data",
        });
        return { dataHandles: [handle] };
      },
    },
    requestScan: {
      description:
        "Ask Shodan to scan IP addresses ON DEMAND. ACTIVE: spends scan credits and only use against IPs you are authorized to scan. Pass a comma-separated list of IPs or CIDR ranges.",
      arguments: z.object({
        ips: z.string().describe("Comma-separated IPs or CIDR ranges to scan"),
      }),
      execute: async (
        args: { ips: string },
        context: MethodContext,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        context.logger.warning("Requesting on-demand Shodan scan of {ips}", {
          ips: args.ips,
        });
        const { data } = await shodanRequest(
          context.globalArgs,
          "POST",
          "/shodan/scan",
          {
            form: { ips: args.ips },
          },
        );
        const d = (data ?? {}) as Record<string, unknown>;
        const handle = await context.writeResource(
          "scanRequest",
          String(d.id ?? "scan"),
          {
            scanId: String(d.id ?? ""),
            ips: args.ips,
            count: Number(d.count ?? 0),
            creditsLeft: Number(d.credits_left ?? 0),
            requestedAt: new Date().toISOString(),
          },
        );
        context.logger.info(
          "Scan {id} requested: {count} IP(s), {left} scan credits left",
          {
            id: String(d.id ?? "?"),
            count: Number(d.count ?? 0),
            left: Number(d.credits_left ?? 0),
          },
        );
        return { dataHandles: [handle] };
      },
    },
  },
};
