// Anti-DNS-Poisoning probe v2 (Trace Capture / Ata Notarial)
// 5 resolvers DoH independentes + consenso por prefixo (/24 · /48) e por ASN
// (Team Cymru via DoH). Tolera 1-2 timeouts e elimina falso-positivo de CDN/anycast.
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': '*, authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
  'Access-Control-Max-Age': '86400',
};

interface ResolverResult {
  resolver: string;
  ips: string[];
  error?: string;
  rttMs: number;
}

type ConsensusLevel = 'consensus_strong' | 'consensus_anycast' | 'consensus_partial' | 'divergent';

const RESOLVERS: Array<{ name: string; url: (host: string, type: string) => string }> = [
  { name: 'dns.google',          url: (h, t) => `https://dns.google/resolve?name=${encodeURIComponent(h)}&type=${t}` },
  { name: 'cloudflare-dns.com',  url: (h, t) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(h)}&type=${t}` },
  { name: 'dns.quad9.net',       url: (h, t) => `https://dns.quad9.net/dns-query?name=${encodeURIComponent(h)}&type=${t}` },
  { name: 'doh.opendns.com',     url: (h, t) => `https://doh.opendns.com/dns-query?name=${encodeURIComponent(h)}&type=${t}` },
  { name: 'dns.adguard-dns.com', url: (h, t) => `https://dns.adguard-dns.com/dns-query?name=${encodeURIComponent(h)}&type=${t}` },
];

async function doh(resolver: { name: string; url: (h: string, t: string) => string }, name: string, type: 'A' | 'AAAA'): Promise<ResolverResult> {
  const t0 = Date.now();
  try {
    const r = await fetch(resolver.url(name, type), {
      headers: { Accept: 'application/dns-json' },
      signal: AbortSignal.timeout(5000),
    });
    if (!r.ok) return { resolver: resolver.name, ips: [], error: `HTTP ${r.status}`, rttMs: Date.now() - t0 };
    const ct = r.headers.get('content-type') || '';
    if (!ct.includes('json')) {
      await r.body?.cancel();
      return { resolver: resolver.name, ips: [], error: `non-json: ${ct}`, rttMs: Date.now() - t0 };
    }
    const j = await r.json();
    const wantType = type === 'A' ? 1 : 28;
    const ips = (j.Answer || [])
      .filter((a: { type: number }) => a.type === wantType)
      .map((a: { data: string }) => a.data);
    return { resolver: resolver.name, ips, rttMs: Date.now() - t0 };
  } catch (e) {
    return { resolver: resolver.name, ips: [], error: e instanceof Error ? e.message : 'fail', rttMs: Date.now() - t0 };
  }
}

async function fetchOriginHeaders(url: string) {
  try {
    const r = await fetch(url, { method: 'HEAD', redirect: 'follow', signal: AbortSignal.timeout(8000) });
    const h: Record<string, string> = {};
    for (const [k, v] of r.headers) {
      if (['server', 'strict-transport-security', 'content-security-policy', 'x-frame-options', 'content-type'].includes(k.toLowerCase())) {
        h[k.toLowerCase()] = v;
      }
    }
    return { status: r.status, headers: h, finalUrl: r.url };
  } catch (e) {
    return { status: 0, headers: {}, error: e instanceof Error ? e.message : 'fail' };
  }
}

// ── Agrupamento por prefixo ────────────────────────────────────────────
function v4Prefix24(ip: string): string | null {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/);
  return m ? `${m[1]}.${m[2]}.${m[3]}.0/24` : null;
}
function v6Prefix48(ip: string): string | null {
  if (!ip.includes(':')) return null;
  // Expande forma comprimida e pega primeiros 3 hextets
  const parts = ip.split('::');
  let groups: string[];
  if (parts.length === 2) {
    const left = parts[0] ? parts[0].split(':') : [];
    const right = parts[1] ? parts[1].split(':') : [];
    const fill = 8 - left.length - right.length;
    groups = [...left, ...Array(fill).fill('0'), ...right];
  } else {
    groups = ip.split(':');
  }
  if (groups.length < 3) return null;
  return `${groups[0]}:${groups[1]}:${groups[2]}::/48`;
}

// ── Lookup ASN via Team Cymru sobre DoH (Google) ───────────────────────
const asnCache = new Map<string, string | null>();
async function asnForV4(ip: string): Promise<string | null> {
  if (asnCache.has(ip)) return asnCache.get(ip)!;
  const rev = ip.split('.').reverse().join('.');
  try {
    const r = await fetch(`https://dns.google/resolve?name=${rev}.origin.asn.cymru.com&type=TXT`, {
      headers: { Accept: 'application/dns-json' },
      signal: AbortSignal.timeout(3000),
    });
    const j = await r.json();
    const txt = j?.Answer?.[0]?.data as string | undefined;
    // Formato: "AS_NUM | prefix | country | rir | date"
    const m = txt?.replace(/"/g, '').split('|')[0]?.trim();
    const asn = m && /^\d+/.test(m) ? `AS${m.split(/\s+/)[0]}` : null;
    asnCache.set(ip, asn);
    return asn;
  } catch {
    asnCache.set(ip, null);
    return null;
  }
}

// ── Cálculo de consenso ────────────────────────────────────────────────
async function computeConsensus(a4: ResolverResult[], a6: ResolverResult[]): Promise<{
  level: ConsensusLevel;
  consensus_ips: string[];
  prefix_groups: Record<string, string[]>; // prefix → resolvers
  asn_groups: Record<string, string[]>;    // ASN → resolvers
  responding_resolvers: number;
  /**
   * F-07 (laudo Jun/2026): true quando o host respondeu apenas IPv6
   * (Cymru não cobre lookup ASN reverso IPv6 via DoH). Neste cenário o
   * consenso se apoia apenas em prefixo /48 — perito do juízo deve estar
   * ciente dessa limitação ao avaliar a prova anti-DNS-poisoning.
   */
  ipv6_asn_limitation: boolean;
}> {
  const v4Responding = a4.filter((r) => r.ips.length > 0);
  const v6Responding = a6.filter((r) => r.ips.length > 0);
  const respondingResolvers = new Set([...v4Responding, ...v6Responding].map((r) => r.resolver)).size;

  // Gate conservador: exigimos pelo menos 2 resolvers DoH respondendo antes
  // de declarar qualquer nível de consenso. Vários DoH públicos (OpenDNS,
  // AdGuard, Quad9) retornam HTTP 400/non-json a partir de runtimes serverless
  // — por isso o limiar de "maioria estrita (3/5)" gerava 'consensus_partial'
  // mesmo quando Google + Cloudflare concordavam. 2/5 ainda é suficiente para
  // detecção de poisoning porque exige convergência cruzada entre operadores
  // independentes (Google × Cloudflare × Quad9 × OpenDNS × AdGuard).
  if (respondingResolvers < 2) {
    return {
      level: 'consensus_partial',
      consensus_ips: [],
      prefix_groups: {},
      asn_groups: {},
      responding_resolvers: respondingResolvers,
      ipv6_asn_limitation: v4Responding.length === 0 && v6Responding.length > 0,
    };
  }


  // 1) Consenso forte por prefixo /24 ou /48
  const prefixGroups: Record<string, Set<string>> = {};
  for (const r of v4Responding) {
    for (const ip of r.ips) {
      const p = v4Prefix24(ip);
      if (!p) continue;
      (prefixGroups[p] ||= new Set()).add(r.resolver);
    }
  }
  for (const r of v6Responding) {
    for (const ip of r.ips) {
      const p = v6Prefix48(ip);
      if (!p) continue;
      (prefixGroups[p] ||= new Set()).add(r.resolver);
    }
  }
  const sharedPrefixes = Object.entries(prefixGroups).filter(([, s]) => s.size >= 2);
  if (sharedPrefixes.length > 0) {
    const ips = new Set<string>();
    for (const [prefix] of sharedPrefixes) {
      for (const r of v4Responding) for (const ip of r.ips) if (v4Prefix24(ip) === prefix) ips.add(ip);
      for (const r of v6Responding) for (const ip of r.ips) if (v6Prefix48(ip) === prefix) ips.add(ip);
    }
    return {
      level: 'consensus_strong',
      consensus_ips: [...ips].sort(),
      prefix_groups: Object.fromEntries(sharedPrefixes.map(([k, s]) => [k, [...s]])),
      asn_groups: {},
      responding_resolvers: respondingResolvers,
      ipv6_asn_limitation: v4Responding.length === 0 && v6Responding.length > 0,
    };
  }

  // 2) Consenso por ASN (CDN/anycast) — só v4 (Cymru não cobre v6 bem por DoH)
  if (v4Responding.length >= 2) {
    const resolverAsns: Record<string, Set<string>> = {}; // ASN → resolvers
    for (const r of v4Responding) {
      const asns = await Promise.all(r.ips.map((ip) => asnForV4(ip)));
      const uniq = new Set(asns.filter((a): a is string => !!a));
      for (const a of uniq) (resolverAsns[a] ||= new Set()).add(r.resolver);
    }
    const sharedAsns = Object.entries(resolverAsns).filter(([, s]) => s.size >= 2);
    if (sharedAsns.length > 0) {
      const ips = new Set<string>();
      for (const r of v4Responding) for (const ip of r.ips) ips.add(ip);
      return {
        level: 'consensus_anycast',
        consensus_ips: [...ips].sort(),
        prefix_groups: {},
        asn_groups: Object.fromEntries(sharedAsns.map(([k, s]) => [k, [...s]])),
        responding_resolvers: respondingResolvers,
      ipv6_asn_limitation: v4Responding.length === 0 && v6Responding.length > 0,
      };
    }
  }

  // 3) Gate já tratado no topo (< 2 resolvers respondendo).


  // 4) Divergência real
  return {
    level: 'divergent',
    consensus_ips: [],
    prefix_groups: {},
    asn_groups: {},
    responding_resolvers: respondingResolvers,
      ipv6_asn_limitation: v4Responding.length === 0 && v6Responding.length > 0,
  };
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  try {
    const { url } = await req.json();
    if (!url || typeof url !== 'string') throw new Error('Missing url');
    const u = new URL(url);
    const host = u.hostname;

    const [a4Results, a6Results, origin] = await Promise.all([
      Promise.all(RESOLVERS.map((r) => doh(r, host, 'A'))),
      Promise.all(RESOLVERS.map((r) => doh(r, host, 'AAAA'))),
      fetchOriginHeaders(url),
    ]);

    const cons = await computeConsensus(a4Results, a6Results);
    const dnsConsensus = cons.level === 'consensus_strong' || cons.level === 'consensus_anycast';

    return new Response(
      JSON.stringify({
        host,
        dns_consensus: dnsConsensus,                 // back-compat
        dns_consensus_level: cons.level,             // novo: 4 níveis
        responding_resolvers: cons.responding_resolvers,
        consensus_ips: cons.consensus_ips,
        consensus_detail: {
          prefix_groups: cons.prefix_groups,
          asn_groups: cons.asn_groups,
        },
        resolver_chain: { a: a4Results, aaaa: a6Results },
        origin,
        captured_at_utc: new Date().toISOString(),
        method: 'DoH (RFC 8484 JSON) — Google + Cloudflare + Quad9 + OpenDNS + AdGuard · consenso por /24·/48 + ASN (Team Cymru)',
      }),
      { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
    );
  } catch (e) {
    return new Response(
      JSON.stringify({ error: e instanceof Error ? e.message : 'unknown' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
    );
  }
});
