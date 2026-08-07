// Network metadata coletor (Trace Capture / Ata Notarial)
// RDAP (registrante), DNS records, certificado TLS via crt.sh (CT logs).
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': '*, authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
  'Access-Control-Max-Age': '86400',
};

// Sufixos públicos de 2 níveis mais comuns (PSL reduzido).
// Sem isso, "academiadeforensedigital.com.br" vira "com.br" no RDAP — bug crítico.
const TWO_LEVEL_TLDS = new Set([
  // Brasil
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br', 'mil.br', 'jus.br',
  'leg.br', 'mp.br', 'adv.br', 'eng.br', 'arq.br', 'med.br', 'blog.br',
  // Reino Unido
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'net.uk',
  // Austrália
  'com.au', 'net.au', 'org.au', 'gov.au', 'edu.au',
  // Argentina / México / etc.
  'com.ar', 'com.mx', 'com.co', 'com.pe', 'com.ve', 'com.uy',
  'co.jp', 'co.kr', 'co.in', 'co.za', 'co.nz',
]);

function getRegistrableDomain(host: string): string {
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  const last2 = parts.slice(-2).join('.');
  if (TWO_LEVEL_TLDS.has(last2)) {
    return parts.slice(-3).join('.');
  }
  return last2;
}

async function rdap(domain: string) {
  // .br precisa do servidor RDAP do registro.br
  const endpoints = domain.endsWith('.br')
    ? [`https://rdap.registro.br/domain/${domain}`, `https://rdap.org/domain/${domain}`]
    : [`https://rdap.org/domain/${domain}`];

  for (const ep of endpoints) {
    try {
      const r = await fetch(ep, {
        headers: { Accept: 'application/rdap+json' },
        signal: AbortSignal.timeout(8000),
      });
      if (!r.ok) continue;
      const j = await r.json();
      const events: Record<string, string> = {};
      for (const e of j.events || []) events[e.eventAction] = e.eventDate;
      const ns = (j.nameservers || []).map((n: { ldhName: string }) => n.ldhName);
      const registrar = (j.entities || []).find((e: { roles?: string[] }) => e.roles?.includes('registrar'));
      const registrarName = registrar?.vcardArray?.[1]?.find((f: unknown[]) => f[0] === 'fn')?.[3];
      // Registrante (registro.br expõe 'registrant')
      const registrant = (j.entities || []).find((e: { roles?: string[] }) => e.roles?.includes('registrant'));
      const registrantName = registrant?.vcardArray?.[1]?.find((f: unknown[]) => f[0] === 'fn')?.[3];
      const registrantHandle = registrant?.handle;
      return {
        source: ep,
        handle: j.handle,
        ldhName: j.ldhName,
        status: j.status,
        events,
        nameservers: ns,
        registrar: registrarName,
        registrant: registrantName,
        registrant_handle: registrantHandle,
      };
    } catch {
      // tenta próximo endpoint
    }
  }
  return { error: 'rdap unreachable' };
}

async function dohRecords(host: string, type: string) {
  try {
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`, {
      headers: { Accept: 'application/dns-json' },
      signal: AbortSignal.timeout(5000),
    });
    if (!r.ok) return [];
    const ct = r.headers.get('content-type') || '';
    if (!ct.includes('json')) { await r.body?.cancel(); return []; }
    const j = await r.json();
    return (j.Answer || []).map((a: { data: string; TTL: number }) => ({ data: a.data, ttl: a.TTL }));
  } catch {
    return [];
  }
}

// ASN/AS Org via Team Cymru DNS (DoH TXT). Sem chave, gratuito, autoritativo.
// Ex.: IP 1.2.3.4 → query TXT 4.3.2.1.origin.asn.cymru.com
//        → "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
async function asnLookup(ip: string): Promise<{ asn?: string; as_org?: string; country?: string; prefix?: string; error?: string }> {
  try {
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return { error: 'ipv6 ou inválido' };
    const reversed = ip.split('.').reverse().join('.');
    const q = `${reversed}.origin.asn.cymru.com`;
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(q)}&type=TXT`, {
      headers: { Accept: 'application/dns-json' },
      signal: AbortSignal.timeout(4000),
    });
    if (!r.ok) return { error: `asn doh ${r.status}` };
    const j = await r.json();
    const txt = (j.Answer || [])[0]?.data?.replace(/^"|"$/g, '') || '';
    if (!txt) return { error: 'sem TXT' };
    // "ASN | prefix | country | registry | allocated"
    const [asn, prefix, country] = txt.split('|').map((s: string) => s.trim());
    // Org lookup: TXT AS<asn>.asn.cymru.com → "ASN | country | registry | allocated | as-org"
    let asOrg: string | undefined;
    try {
      const r2 = await fetch(`https://cloudflare-dns.com/dns-query?name=AS${asn}.asn.cymru.com&type=TXT`, {
        headers: { Accept: 'application/dns-json' },
        signal: AbortSignal.timeout(4000),
      });
      const j2 = await r2.json();
      const t2 = (j2.Answer || [])[0]?.data?.replace(/^"|"$/g, '') || '';
      asOrg = t2.split('|').map((s: string) => s.trim())[4];
    } catch { /* ignore */ }
    return { asn: `AS${asn}`, as_org: asOrg, country, prefix };
  } catch (e) {
    return { error: e instanceof Error ? e.message : 'asn fail' };
  }
}

// CT-log lookup: tenta CertSpotter primeiro (rápido), depois crt.sh como fallback.
async function tlsCertViaCT(host: string) {
  // 1) CertSpotter — bem mais rápido que crt.sh, sem auth para uso leve.
  try {
    const r = await fetch(
      `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(host)}&include_subdomains=false&match_wildcards=true&expand=dns_names&expand=issuer&expand=cert`,
      { signal: AbortSignal.timeout(8000) },
    );
    if (r.ok) {
      const list = await r.json() as Array<{
        id?: string;
        dns_names?: string[];
        issuer?: { name?: string; friendly_name?: string };
        not_before?: string;
        not_after?: string;
        cert?: { sha256?: string };
      }>;
      if (Array.isArray(list) && list.length > 0) {
        const sorted = [...list].sort((a, b) => (b.not_after || '').localeCompare(a.not_after || ''));
        const c = sorted[0];
        const now = new Date();
        const validTo = c.not_after ? new Date(c.not_after) : null;
        return {
          source: 'CertSpotter (Certificate Transparency)',
          subject: c.dns_names?.[0],
          issuer: c.issuer?.friendly_name || c.issuer?.name,
          validFrom: c.not_before,
          validTo: c.not_after,
          san: c.dns_names,
          fingerprint_sha256: c.cert?.sha256,
          currently_valid: validTo ? validTo > now : null,
          ct_log_id: c.id,
        };
      }
    }
  } catch { /* tenta crt.sh */ }

  // 2) crt.sh — fallback (lento mas exaustivo).
  try {
    const r = await fetch(`https://crt.sh/?q=${encodeURIComponent(host)}&output=json`, {
      signal: AbortSignal.timeout(20000),
    });
    if (!r.ok) return { error: `crt.sh HTTP ${r.status}`, source: 'crt.sh' };
    const list = await r.json() as Array<{
      issuer_name?: string;
      common_name?: string;
      name_value?: string;
      not_before?: string;
      not_after?: string;
      serial_number?: string;
      id?: number;
    }>;
    if (!Array.isArray(list) || list.length === 0) {
      return { error: 'no certs in CT logs', source: 'crt.sh' };
    }
    const sorted = [...list].sort((a, b) => (b.not_after || '').localeCompare(a.not_after || ''));
    const c = sorted[0];
    const now = new Date();
    const validTo = c.not_after ? new Date(c.not_after) : null;
    return {
      source: 'crt.sh (Certificate Transparency)',
      subject: c.common_name,
      issuer: c.issuer_name,
      validFrom: c.not_before,
      validTo: c.not_after,
      serialNumber: c.serial_number,
      san: c.name_value?.split(/\n/).filter(Boolean),
      currently_valid: validTo ? validTo > now : null,
      ct_log_id: c.id,
    };
  } catch (e) {
    return { error: e instanceof Error ? e.message : 'tls fail', source: 'ct-logs' };
  }
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  try {
    const { url } = await req.json();
    if (!url || typeof url !== 'string') throw new Error('Missing url');
    const u = new URL(url);
    const host = u.hostname;
    const registrable = getRegistrableDomain(host);

    const [rdapInfo, a, aaaa, mx, ns, txt, caa, tls] = await Promise.all([
      rdap(registrable),
      dohRecords(host, 'A'),
      dohRecords(host, 'AAAA'),
      dohRecords(registrable, 'MX'),
      dohRecords(registrable, 'NS'),
      dohRecords(registrable, 'TXT'),
      dohRecords(registrable, 'CAA'),
      u.protocol === 'https:' ? tlsCertViaCT(host) : Promise.resolve({ error: 'http (no TLS)' }),
    ]);

    // ASN lookup para até 3 primeiros IPs A (paralelo, tolerante a falha).
    const ipsToProbe = (a as { data: string }[]).slice(0, 3).map((r) => r.data);
    const asnResults = await Promise.all(ipsToProbe.map((ip) => asnLookup(ip)));
    const asn = ipsToProbe.map((ip, i) => ({ ip, ...asnResults[i] }));

    // Revocation check — honest documentation: CT log presence ≠ revogação.
    // Verificação OCSP/CRL completa requer parser ASN.1 do certificado X.509.
    // Aqui apenas registramos o método aplicado, sem alegar verificação além do real.
    const tlsWithRevocation = (tls as { error?: string }).error
      ? tls
      : {
          ...tls,
          revocation_check: {
            method: 'ct_log_presence_only',
            note: 'Presença ativa em logs CT (CertSpotter/crt.sh). Verificação OCSP/CRL não foi executada pelo coletor; recomenda-se reexecutar manualmente via openssl s_client antes da audiência se houver indício de revogação.',
            checked_at_utc: new Date().toISOString(),
          },
        };

    return new Response(
      JSON.stringify({
        host,
        registrable_domain: registrable,
        rdap: rdapInfo,
        dns: { A: a, AAAA: aaaa, MX: mx, NS: ns, TXT: txt, CAA: caa },
        asn,
        tls: tlsWithRevocation,
        captured_at_utc: new Date().toISOString(),
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
