import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import {
  composeQuery,
  type DataHandle,
  internetDbLookup,
  mapDevice,
  mapFacets,
  type MethodContext,
  type ShodanGlobalArgs,
  shodanRequest,
  slugify,
} from "./_client.ts";
import { model } from "./shodan.ts";

const g: ShodanGlobalArgs = {
  apiKey: "test-key",
  baseUrl: "https://api.shodan.io",
  internetDbUrl: "https://internetdb.shodan.io",
  timeoutMs: 5000,
};

/** Swap `globalThis.fetch` for a stub; returns a restore function. */
function mockFetch(
  handler: (url: string, init?: RequestInit) => { status: number; body: string },
): () => void {
  const original = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const { status, body } = handler(url, init);
    return Promise.resolve(new Response(body, { status }));
  }) as typeof fetch;
  return () => {
    globalThis.fetch = original;
  };
}

/** A fake method context that records every `writeResource` call. */
function fakeContext(): {
  ctx: MethodContext;
  writes: Array<{ spec: string; name: string; data: Record<string, unknown> }>;
} {
  const writes: Array<{ spec: string; name: string; data: Record<string, unknown> }> = [];
  const ctx: MethodContext = {
    globalArgs: g,
    logger: { info: () => {}, warning: () => {} },
    writeResource: (spec, name, data): Promise<DataHandle> => {
      writes.push({ spec, name, data });
      return Promise.resolve({ name, specName: spec });
    },
  };
  return { ctx, writes };
}

// deno-lint-ignore no-explicit-any
const methods = model.methods as Record<string, any>;

Deno.test("model exposes the expected methods and type", () => {
  assertEquals(model.type, "@dougschaefer/shodan");
  for (const m of ["accountInfo", "search", "count", "host", "internetdb", "requestScan"]) {
    assert(m in methods, `missing method ${m}`);
  }
});

Deno.test("accountInfo maps Shodan credit fields", async () => {
  const restore = mockFetch(() => ({
    status: 200,
    body: JSON.stringify({ plan: "dev", query_credits: 100, scan_credits: 100, unlocked: true }),
  }));
  const { ctx, writes } = fakeContext();
  try {
    await methods.accountInfo.execute({}, ctx);
  } finally {
    restore();
  }
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "account");
  assertEquals(writes[0].data.queryCredits, 100);
  assertEquals(writes[0].data.unlocked, true);
});

Deno.test("search maps devices, flags truncation, and names the instance per method", async () => {
  const restore = mockFetch((url) => {
    assert(url.includes("/shodan/host/search"));
    return {
      status: 200,
      body: JSON.stringify({
        total: 260,
        matches: [
          { ip_str: "192.0.2.10", port: 8081, product: "Crestron TSW-750", location: { city: "Palm Desert" } },
        ],
        facets: { org: [{ value: "Example ISP", count: 47 }] },
      }),
    };
  });
  const { ctx, writes } = fakeContext();
  try {
    await methods.search.execute(
      { query: 'product:"Crestron"', country: "US", page: 1, limit: 25 },
      ctx,
    );
  } finally {
    restore();
  }
  assertEquals(writes[0].spec, "searchResult");
  assert(writes[0].name.startsWith("search-"));
  assertEquals(writes[0].data.total, 260);
  assertEquals(writes[0].data.returned, 1);
  assertEquals(writes[0].data.truncated, true);
});

Deno.test("count names its instance distinctly from search", async () => {
  const restore = mockFetch(() => ({
    status: 200,
    body: JSON.stringify({ total: 260, facets: {} }),
  }));
  const { ctx, writes } = fakeContext();
  try {
    await methods.count.execute({ query: 'product:"Crestron"', country: "US" }, ctx);
  } finally {
    restore();
  }
  assertEquals(writes[0].spec, "countResult");
  assert(writes[0].name.startsWith("count-"));
});

Deno.test("a failing API call throws before any data is written", async () => {
  const restore = mockFetch(() => ({
    status: 401,
    body: JSON.stringify({ error: "Invalid API key" }),
  }));
  const { ctx, writes } = fakeContext();
  try {
    await assertRejects(() => methods.accountInfo.execute({}, ctx), Error, "401");
  } finally {
    restore();
  }
  assertEquals(writes.length, 0);
});

Deno.test("composeQuery appends city and country filters with quoting", () => {
  assertEquals(composeQuery('product:"Crestron"'), 'product:"Crestron"');
  assertEquals(
    composeQuery("webex", "Indianapolis", "US"),
    'webex city:"Indianapolis" country:"US"',
  );
  assertEquals(composeQuery("webex", "", ""), "webex");
});

Deno.test("slugify normalizes, truncates, and falls back", () => {
  assertEquals(slugify('product:"Crestron" country:"US"'), "product-Crestron-country-US");
  assertEquals(slugify("   "), "all");
  assert(slugify("x".repeat(80)).length <= 40);
});

Deno.test("mapDevice extracts fields and tolerates missing data", () => {
  const dev = mapDevice({
    ip_str: "192.0.2.10",
    port: 8081,
    location: { country_code: "US" },
    vulns: { "CVE-2019-3929": {} },
  });
  assertEquals(dev.ip, "192.0.2.10");
  assertEquals(dev.countryCode, "US");
  assertEquals(dev.vulns, ["CVE-2019-3929"]);
  const empty = mapDevice({});
  assertEquals(empty.ip, "");
  assertEquals(empty.vulns, []);
});

Deno.test("mapFacets flattens facet rows and tolerates non-objects", () => {
  const f = mapFacets({ org: [{ value: "Acme", count: 5 }] });
  assertEquals(f.org, [{ value: "Acme", count: 5 }]);
  assertEquals(mapFacets(null), {});
});

Deno.test("internetDbLookup returns null on 404 and parses on 200", async () => {
  let restore = mockFetch(() => ({ status: 404, body: '{"detail":"No information"}' }));
  try {
    assertEquals(await internetDbLookup(g, "192.0.2.1"), null);
  } finally {
    restore();
  }
  restore = mockFetch(() => ({ status: 200, body: JSON.stringify({ ip: "192.0.2.2", ports: [22, 80] }) }));
  try {
    const r = await internetDbLookup(g, "192.0.2.2") as { ip: string; ports: number[] };
    assertEquals(r.ports, [22, 80]);
  } finally {
    restore();
  }
});
