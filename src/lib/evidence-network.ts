/**
 * Tipos e helpers para os blocos "Integridade DNS" e "Metadados Técnicos de Rede"
 * usados pelo Trace Capture (anti-DNS-Poisoning / paridade ISO 27037).
 */

export interface ResolverResult {
  resolver: string;
  ips: string[];
  error?: string;
  rttMs: number;
}

export type DnsConsensusLevel =
  | 'consensus_strong'   // mesmo prefixo /24 ou /48 em ≥2 resolvers
  | 'consensus_anycast'  // mesmo ASN em ≥2 resolvers (CDN/anycast)
  | 'consensus_partial'  // ≤1 resolver respondeu
  | 'divergent';         // ASNs diferentes — possível DNS poisoning

export interface DnsIntegrity {
  host: string;
  dns_consensus: boolean;                  // back-compat (strong|anycast = true)
  dns_consensus_level?: DnsConsensusLevel; // novo, opcional p/ caches antigos
  responding_resolvers?: number;
  consensus_ips: string[];
  resolver_chain: { a: ResolverResult[]; aaaa: ResolverResult[] };
  origin: {
    status: number;
    headers?: Record<string, string>;
    finalUrl?: string;
    error?: string;
  };
  captured_at_utc: string;
  method: string;
}

export interface AsnRecord {
  ip: string;
  asn?: string;
  as_org?: string;
  country?: string;
  prefix?: string;
  error?: string;
}

export interface NetworkMetadata {
  host: string;
  registrable_domain: string;
  rdap: {
    handle?: string;
    ldhName?: string;
    status?: string[];
    events?: Record<string, string>;
    nameservers?: string[];
    registrar?: string;
    error?: string;
  };
  dns: Record<'A' | 'AAAA' | 'MX' | 'NS' | 'TXT' | 'CAA', { data: string; ttl: number }[]>;
  asn?: AsnRecord[];
  tls:
    | {
        subject?: unknown;
        issuer?: unknown;
        validFrom?: string;
        validTo?: string;
        serialNumber?: string;
        san?: string[];
        error?: string;
      }
    | { error: string };
  captured_at_utc: string;
}

export function countMetadataPoints(net?: NetworkMetadata | null, dns?: DnsIntegrity | null): number {
  let n = 0;
  if (net) {
    if (net.rdap && !('error' in net.rdap)) n += 6;
    for (const k of ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA'] as const) {
      n += (net.dns?.[k]?.length || 0);
    }
    if (net.tls && !('error' in net.tls)) n += 5;
  }
  if (dns) {
    n += (dns.resolver_chain?.a?.length || 0) + (dns.resolver_chain?.aaaa?.length || 0);
    n += Object.keys(dns.origin?.headers || {}).length;
  }
  return n;
}
