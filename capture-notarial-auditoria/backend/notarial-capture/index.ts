// CORS allowlist (defesa em profundidade — JWT do Supabase continua sendo a auth primária).
const ALLOWED_ORIGIN_PATTERNS: Array<string | RegExp> = [
  'https://www.trace-hub.com',
  'https://trace-hub.com',
  'https://tracehub.lovable.app',
  /^https:\/\/[a-z0-9-]+\.lovable\.app$/i,
  /^https:\/\/[a-z0-9-]+\.lovableproject\.com$/i,
  /^http:\/\/localhost(:\d+)?$/i,
];

function corsFor(req: Request): Record<string, string> | null {
  const origin = req.headers.get('origin') || '';
  if (!origin) {
    return {
      'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Vary': 'Origin',
    };
  }
  const allowed = ALLOWED_ORIGIN_PATTERNS.some((p) =>
    typeof p === 'string' ? p === origin : p.test(origin),
  );
  if (!allowed) return null;
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Vary': 'Origin',
  };
}

interface CaptureRequest {
  url: string;
  previous_evidence_hash?: string | null;
}

async function sha256Hex(input: string | Uint8Array): Promise<string> {
  const buf = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function sha512Hex(input: string | Uint8Array): Promise<string> {
  const buf = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  const hash = await crypto.subtle.digest('SHA-512', buf);
  return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

interface NtpResult {
  iso: string;
  source: string;
  response_hash: string | null;
  response_excerpt: string | null;
}

async function getNtpTimestamp(): Promise<NtpResult> {
  const sources = [
    { url: 'https://timeapi.io/api/Time/current/zone?timeZone=UTC', extract: (j: any) => j.dateTime, label: 'timeapi.io (UTC)' },
    { url: 'https://worldtimeapi.org/api/timezone/Etc/UTC', extract: (j: any) => j.utc_datetime, label: 'worldtimeapi.org (UTC)' },
  ];
  for (const src of sources) {
    try {
      const r = await fetch(src.url, { signal: AbortSignal.timeout(4000) });
      if (!r.ok) continue;
      const body = await r.text();
      const j = JSON.parse(body);
      const ts = src.extract(j);
      if (!ts) continue;
      const response_hash = await sha256Hex(body);
      const response_excerpt = body.slice(0, 512);
      return { iso: new Date(ts).toISOString(), source: src.label, response_hash, response_excerpt };
    } catch {
      // try next
    }
  }
  return { iso: new Date().toISOString(), source: 'local server (fallback)', response_hash: null, response_excerpt: null };
}

// ============================================================================
// Reachability probe — DoH + HEAD + Wayback. Nunca lança.
// ============================================================================
type DohRecord = {
  resolver: 'cloudflare-1.1.1.1' | 'google-8.8.8.8';
  endpoint: string;
  status: 'ok' | 'nxdomain' | 'error';
  records: string[];
  raw_excerpt: string;
  response_hash: string | null;
  http_status: number | null;
  error?: string;
};

async function dohQuery(resolver: DohRecord['resolver'], endpoint: string, host: string): Promise<DohRecord> {
  try {
    const r = await fetch(endpoint, {
      headers: { 'Accept': 'application/dns-json' },
      signal: AbortSignal.timeout(5000),
    });
    const body = await r.text();
    const response_hash = await sha256Hex(body);
    let parsed: { Status?: number; Answer?: Array<{ data: string; type: number }> } = {};
    try { parsed = JSON.parse(body); } catch { /* ignore */ }
    // DNS Status codes: 0 = NOERROR, 3 = NXDOMAIN
    const dnsStatus = parsed.Status;
    const aRecords = (parsed.Answer || []).filter((a) => a.type === 1).map((a) => a.data);
    let status: DohRecord['status'] = 'error';
    if (dnsStatus === 0 && aRecords.length > 0) status = 'ok';
    else if (dnsStatus === 3 || (dnsStatus === 0 && aRecords.length === 0)) status = 'nxdomain';
    return {
      resolver,
      endpoint,
      status,
      records: aRecords,
      raw_excerpt: body.slice(0, 512),
      response_hash,
      http_status: r.status,
    };
  } catch (e) {
    return {
      resolver,
      endpoint,
      status: 'error',
      records: [],
      raw_excerpt: '',
      response_hash: null,
      http_status: null,
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

async function waybackAvailability(url: string): Promise<{ available: boolean; closest_url?: string; closest_timestamp?: string; raw_excerpt?: string; response_hash?: string | null; error?: string }> {
  try {
    const r = await fetch(`https://archive.org/wayback/available?url=${encodeURIComponent(url)}`, {
      signal: AbortSignal.timeout(7000),
    });
    const body = await r.text();
    const response_hash = await sha256Hex(body);
    const j = JSON.parse(body) as { archived_snapshots?: { closest?: { available?: boolean; url?: string; timestamp?: string } } };
    const closest = j.archived_snapshots?.closest;
    return {
      available: Boolean(closest?.available && closest.url),
      closest_url: closest?.url,
      closest_timestamp: closest?.timestamp,
      raw_excerpt: body.slice(0, 512),
      response_hash,
    };
  } catch (e) {
    return { available: false, error: e instanceof Error ? e.message : String(e) };
  }
}

interface Reachability {
  reachable: boolean;
  reason: 'dns_nxdomain' | 'connection_refused' | 'timeout' | 'tls_error' | 'http_ok' | 'http_error' | 'unknown';
  http_status: number | null;
  http_error_message: string | null;
  head_attempt: { ok: boolean; error?: string };
  dns: { cloudflare: DohRecord; google: DohRecord };
  dns_consensus: 'offline' | 'partial' | 'online';
  wayback: Awaited<ReturnType<typeof waybackAvailability>>;
  probed_at: string;
}

function classifyFetchError(msg: string): Reachability['reason'] {
  const m = msg.toLowerCase();
  if (m.includes('dns error') || m.includes('failed to lookup') || m.includes('nodename') || m.includes('enotfound')) return 'dns_nxdomain';
  if (m.includes('connection refused') || m.includes('econnrefused')) return 'connection_refused';
  if (m.includes('timed out') || m.includes('timeout') || m.includes('deadline')) return 'timeout';
  if (m.includes('tls') || m.includes('certificate') || m.includes('ssl')) return 'tls_error';
  return 'unknown';
}

async function probeReachability(url: string): Promise<Reachability> {
  const host = new URL(url).hostname;
  const probedAt = new Date().toISOString();

  const [headRes, cfDoh, googleDoh, wb] = await Promise.all([
    fetch(url, {
      method: 'HEAD',
      redirect: 'follow',
      signal: AbortSignal.timeout(8000),
      headers: { 'User-Agent': 'Mozilla/5.0 trace-hub-notarial-probe/1.0' },
    }).then(
      (r) => ({ ok: true as const, status: r.status }),
      (e) => ({ ok: false as const, error: e instanceof Error ? e.message : String(e) }),
    ),
    dohQuery('cloudflare-1.1.1.1', `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`, host),
    dohQuery('google-8.8.8.8', `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`, host),
    waybackAvailability(url),
  ]);

  const cfOk = cfDoh.status === 'ok';
  const gOk = googleDoh.status === 'ok';
  let dns_consensus: Reachability['dns_consensus'];
  if (cfOk && gOk) dns_consensus = 'online';
  else if (!cfOk && !gOk) dns_consensus = 'offline';
  else dns_consensus = 'partial';

  let reachable = false;
  let reason: Reachability['reason'] = 'unknown';
  let http_status: number | null = null;
  let http_error_message: string | null = null;

  if (headRes.ok) {
    http_status = headRes.status;
    if (headRes.status < 500) {
      reachable = true;
      reason = 'http_ok';
    } else {
      reachable = dns_consensus !== 'offline';
      reason = 'http_error';
    }
  } else {
    http_error_message = headRes.error;
    reason = classifyFetchError(headRes.error);
    // Se DNS resolve mas HEAD falhou por timeout/refused, ainda consideramos
    // tentar uma captura GET completa (alguns servidores rejeitam HEAD).
    reachable = dns_consensus === 'online' && (reason === 'timeout' || reason === 'unknown');
    if (dns_consensus === 'offline') reason = 'dns_nxdomain';
  }

  return {
    reachable,
    reason,
    http_status,
    http_error_message,
    head_attempt: headRes.ok ? { ok: true } : { ok: false, error: headRes.error },
    dns: { cloudflare: cfDoh, google: googleDoh },
    dns_consensus,
    wayback: wb,
    probed_at: probedAt,
  };
}

interface ScreenshotResult {
  base64: string;
  contentType: string;
  bytes: Uint8Array;
  providerRequestId: string | null;
  providerHeadersHash: string;
  providerEdgeRegion: Record<string, string>;
  fetchedAt: string;
}

async function captureScreenshot(url: string, accessKey: string): Promise<ScreenshotResult> {
  const attempts = [
    { full_page: 'true', block_ads: 'true', block_cookie_banners: 'true', timeout: '60', ignore_host_errors: 'true' },
    { full_page: 'false', block_ads: 'true', block_cookie_banners: 'false', timeout: '45', ignore_host_errors: 'true' },
    { full_page: 'false', block_ads: 'false', block_cookie_banners: 'false', timeout: '30', ignore_host_errors: 'true' },
  ];

  let lastErr = '';
  for (let i = 0; i < attempts.length; i++) {
    const opts = attempts[i];
    const params = new URLSearchParams({
      access_key: accessKey,
      url,
      format: 'jpg',
      image_quality: '85',
      cache: 'false',
      viewport_width: '1280',
      viewport_height: '800',
      ...opts,
    });
    try {
      const res = await fetch(`https://api.screenshotone.com/take?${params.toString()}`, { signal: AbortSignal.timeout(75000) });
      if (!res.ok) {
        const errText = await res.text().catch(() => '');
        lastErr = `ScreenshotOne ${res.status}: ${errText.slice(0, 200)}`;
        console.warn(`[notarial-capture] attempt ${i + 1} failed: ${lastErr}`);
        if (i < attempts.length - 1) {
          await new Promise((r) => setTimeout(r, 1500 * (i + 1)));
          continue;
        }
        throw new Error(lastErr);
      }
      const buf = new Uint8Array(await res.arrayBuffer());
      let bin = '';
      const chunk = 0x8000;
      for (let j = 0; j < buf.length; j += chunk) {
        bin += String.fromCharCode.apply(null, Array.from(buf.subarray(j, j + chunk)));
      }
      const provenanceKeys = ['x-request-id', 'x-screenshot-id', 'date', 'content-type', 'content-length', 'server'];
      const provenance: Record<string, string> = {};
      for (const k of provenanceKeys) {
        const v = res.headers.get(k);
        if (v) provenance[k] = v;
      }
      const edgeKeys = ['cf-ray', 'cf-cache-status', 'x-amz-cf-pop', 'x-amz-cf-id', 'x-amzn-trace-id', 'via', 'x-served-by'];
      const providerEdgeRegion: Record<string, string> = {};
      for (const k of edgeKeys) {
        const v = res.headers.get(k);
        if (v) providerEdgeRegion[k] = v;
      }
      const providerHeadersHash = await sha256Hex(JSON.stringify({ ...provenance, ...providerEdgeRegion }));
      const providerRequestId = res.headers.get('x-request-id') || res.headers.get('x-screenshot-id');
      return {
        base64: btoa(bin),
        contentType: res.headers.get('content-type') || 'image/jpeg',
        bytes: buf,
        providerRequestId,
        providerHeadersHash,
        providerEdgeRegion,
        fetchedAt: new Date().toISOString(),
      };
    } catch (e) {
      lastErr = e instanceof Error ? e.message : String(e);
      console.warn(`[notarial-capture] attempt ${i + 1} error: ${lastErr}`);
      if (i < attempts.length - 1) {
        await new Promise((r) => setTimeout(r, 1500 * (i + 1)));
        continue;
      }
    }
  }
  throw new Error(lastErr || 'Screenshot capture failed');
}

interface PageDetails {
  finalUrl: string;
  status: number;
  headers: Record<string, string>;
  html: string;
  htmlHash: string;
  htmlTruncated: boolean;
  htmlFullSize: number;
  title?: string;
  description?: string;
}

async function fetchPageDetails(url: string): Promise<PageDetails> {
  const res = await fetch(url, {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8',
    },
    redirect: 'follow',
    signal: AbortSignal.timeout(20000),
  });
  const html = await res.text();
  const HTML_CAP = 1_500_000;
  const htmlTruncated = html.length > HTML_CAP;
  const cappedHtml = htmlTruncated ? html.slice(0, HTML_CAP) : html;
  const htmlHash = await sha256Hex(cappedHtml);
  const headersObj: Record<string, string> = {};
  res.headers.forEach((v, k) => { headersObj[k] = v; });
  const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  const descMatch = html.match(/<meta[^>]+name=["']description["'][^>]*content=["']([^"']+)["']/i)
                 || html.match(/<meta[^>]+property=["']og:description["'][^>]*content=["']([^"']+)["']/i);
  return {
    finalUrl: res.url || url,
    status: res.status,
    headers: headersObj,
    html: cappedHtml,
    htmlHash,
    htmlTruncated,
    htmlFullSize: html.length,
    title: titleMatch?.[1]?.trim(),
    description: descMatch?.[1]?.trim(),
  };
}

async function fetchRenderedDomHash(url: string, accessKey: string): Promise<{ hash: string | null; bytes: number; source: string; error?: string }> {
  try {
    const params = new URLSearchParams({
      access_key: accessKey,
      url,
      response_type: 'json',
      metadata_html: 'true',
      block_ads: 'true',
      delay: '3',
      timeout: '45',
      ignore_host_errors: 'true',
      viewport_width: '1280',
      viewport_height: '800',
    });
    const r = await fetch(`https://api.screenshotone.com/take?${params.toString()}`, {
      signal: AbortSignal.timeout(60000),
    });
    if (!r.ok) return { hash: null, bytes: 0, source: 'screenshotone.metadata_html', error: `HTTP ${r.status}` };
    const j = await r.json() as { html?: string };
    if (!j.html) return { hash: null, bytes: 0, source: 'screenshotone.metadata_html', error: 'no html field' };
    const hash = await sha256Hex(j.html);
    return { hash, bytes: j.html.length, source: 'screenshotone.metadata_html (rendered post-JS)' };
  } catch (e) {
    return { hash: null, bytes: 0, source: 'screenshotone.metadata_html', error: e instanceof Error ? e.message : 'fail' };
  }
}

function humanReason(r: Reachability): string {
  switch (r.reason) {
    case 'dns_nxdomain': return 'Domínio não resolve em DNS público (NXDOMAIN)';
    case 'connection_refused': return 'Conexão recusada pelo servidor de origem';
    case 'timeout': return 'Servidor de origem não respondeu dentro do tempo limite';
    case 'tls_error': return 'Falha de handshake TLS/SSL';
    case 'http_error': return `Servidor respondeu com erro HTTP ${r.http_status ?? '5xx'}`;
    case 'http_ok': return `Servidor respondeu HTTP ${r.http_status}`;
    default: return r.http_error_message || 'Indisponibilidade de origem indeterminada';
  }
}

Deno.serve(async (req) => {
  const cors = corsFor(req);
  if (!cors) {
    return new Response(JSON.stringify({ error: 'Origin not allowed' }), {
      status: 403, headers: { 'Content-Type': 'application/json' },
    });
  }
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });

  try {
    const accessKey = Deno.env.get('SCREENSHOTONE_ACCESS_KEY');
    if (!accessKey) {
      return new Response(JSON.stringify({ error: 'SCREENSHOTONE_ACCESS_KEY missing' }), {
        status: 500, headers: { ...cors, 'Content-Type': 'application/json' },
      });
    }

    const body = (await req.json()) as CaptureRequest;
    if (!body?.url || typeof body.url !== 'string') {
      return new Response(JSON.stringify({ error: 'Missing url' }), {
        status: 400, headers: { ...cors, 'Content-Type': 'application/json' },
      });
    }

    let parsed: URL;
    try { parsed = new URL(body.url); } catch {
      return new Response(JSON.stringify({ error: 'Invalid URL' }), {
        status: 400, headers: { ...cors, 'Content-Type': 'application/json' },
      });
    }
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return new Response(JSON.stringify({ error: 'Only http/https' }), {
        status: 400, headers: { ...cors, 'Content-Type': 'application/json' },
      });
    }

    const operatorIp = req.headers.get('cf-connecting-ip')
      || req.headers.get('x-real-ip')
      || (req.headers.get('x-forwarded-for') || '').split(',')[0].trim()
      || 'unknown';

    const requestId = crypto.randomUUID();

    const [ntp, reachability] = await Promise.all([
      getNtpTimestamp(),
      probeReachability(body.url),
    ]);

    const previousEvidenceHash = (typeof body.previous_evidence_hash === 'string'
      && /^[0-9a-f]{64}$/i.test(body.previous_evidence_hash))
      ? body.previous_evidence_hash.toLowerCase()
      : null;

    const isOffline = !reachability.reachable && reachability.dns_consensus !== 'online';

    // ========== CAMINHO OFFLINE — Ata de Indisponibilidade ==========
    if (isOffline) {
      const waybackSuggestion = reachability.wayback.available
        ? { url: reachability.wayback.closest_url!, timestamp: reachability.wayback.closest_timestamp! }
        : null;

      const offlineSummary = humanReason(reachability)
        + ` (Cloudflare 1.1.1.1: ${reachability.dns.cloudflare.status.toUpperCase()}, Google 8.8.8.8: ${reachability.dns.google.status.toUpperCase()})`
        + (waybackSuggestion ? ` · Snapshot Wayback mais próximo: ${waybackSuggestion.timestamp}` : ' · Sem snapshot no Wayback Machine');

      const evidencePayload = JSON.stringify({
        site_status: 'offline',
        original_url: body.url,
        timestamp: ntp.iso,
        timestamp_source: ntp.source,
        timestamp_response_hash: ntp.response_hash,
        reachability,
        operator_ip: operatorIp,
        request_id: requestId,
        previous_evidence_hash: previousEvidenceHash,
      });
      const [evidenceHash, evidenceHashSha512] = await Promise.all([
        sha256Hex(evidencePayload),
        sha512Hex(evidencePayload),
      ]);

      const watermarkText = `TraceHub · INDISPONIBILIDADE · ${evidenceHash.slice(0, 16)}…${evidenceHash.slice(-8)} · ${ntp.iso}`;

      return new Response(JSON.stringify({
        site_status: 'offline',
        offline_evidence: reachability,
        offline_summary: offlineSummary,
        wayback_suggestion: waybackSuggestion,
        original_url: body.url,
        final_url: body.url,
        timestamp: ntp.iso,
        timestamp_source: ntp.source,
        timestamp_response_hash: ntp.response_hash,
        timestamp_response_excerpt: ntp.response_excerpt,
        http_status: reachability.http_status ?? 0,
        http_headers: {},
        security_headers: {
          'strict-transport-security': null,
          'content-security-policy': null,
          'x-frame-options': null,
          'x-content-type-options': null,
          'referrer-policy': null,
          'server': null,
          'set-cookie-present': false,
        },
        page_title: null,
        page_description: null,
        screenshot_base64: null,
        screenshot_mime: null,
        screenshot_hash: null,
        screenshot_warning: `Ata de Indisponibilidade — ${offlineSummary}. Nenhuma captura visual foi gerada porque o servidor de origem não respondeu.`,
        screenshot_provider: null,
        screenshot_provider_request_id: null,
        screenshot_provider_headers_hash: null,
        screenshot_provider_edge_region: null,
        screenshot_fetched_at: null,
        rendered_dom: { hash: null, bytes: 0, source: 'skipped (site offline)', error: 'site_offline' },
        previous_evidence_hash: previousEvidenceHash,
        watermark_text: watermarkText,
        html_hash: await sha256Hex(''),
        html_size: 0,
        html_truncated: false,
        html_full_size: 0,
        operator_ip: operatorIp,
        request_id: requestId,
        evidence_hash: evidenceHash,
        evidence_hash_sha512: evidenceHashSha512,
        evidence_hash_algorithm: 'SHA-256 + SHA-512 (FIPS 180-4)',
        evidence_payload: evidencePayload,
        capture_env: {
          user_agent: 'Mozilla/5.0 trace-hub-notarial-probe/1.0',
          viewport_width: 1280,
          viewport_height: 800,
          device_scale_factor: 1,
          browser_engine: 'N/A (site offline — reachability probe only)',
          collector: 'trace-hub-edge-fn/notarial-capture (offline mode)',
        },
      }), { status: 200, headers: { ...cors, 'Content-Type': 'application/json' } });
    }

    // ========== CAMINHO NORMAL — site no ar ==========
    const [shotResult, pageResult, renderedDom] = await Promise.all([
      captureScreenshot(body.url, accessKey).then(
        (s) => ({ ok: true as const, value: s }),
        (e) => ({ ok: false as const, error: e instanceof Error ? e.message : String(e) }),
      ),
      fetchPageDetails(body.url).then(
        (p) => ({ ok: true as const, value: p }),
        (e) => ({ ok: false as const, error: e instanceof Error ? e.message : String(e) }),
      ),
      fetchRenderedDomHash(body.url, accessKey),
    ]);

    const page: PageDetails = pageResult.ok ? pageResult.value : {
      finalUrl: body.url,
      status: 0,
      headers: {},
      html: '',
      htmlHash: await sha256Hex(''),
      htmlTruncated: false,
      htmlFullSize: 0,
    };
    const pageWarning = pageResult.ok ? null : `Coleta de HTML falhou (${pageResult.error}). Demais artefatos preservados.`;

    const screenshotHash = shotResult.ok ? await sha256Hex(shotResult.value.bytes) : null;
    let screenshotWarning: string | null = shotResult.ok ? null : `Captura visual indisponível (${shotResult.error}). Evidência HTML preservada.`;
    if (pageWarning) screenshotWarning = screenshotWarning ? `${screenshotWarning} | ${pageWarning}` : pageWarning;
    if (page.status >= 400) {
      const httpWarn = `Resposta HTTP ${page.status}: o screenshot preserva a página de erro/bloqueio retornada pelo servidor de origem, não o conteúdo original da publicação.`;
      screenshotWarning = screenshotWarning ? `${screenshotWarning} | ${httpWarn}` : httpWarn;
    }

    const partialCapture = !shotResult.ok || !pageResult.ok;
    const siteStatus: 'online' | 'partial' = partialCapture ? 'partial' : 'online';

    const h = page.headers || {};
    const securityHeaders = {
      'strict-transport-security': h['strict-transport-security'] || null,
      'content-security-policy': h['content-security-policy'] || null,
      'x-frame-options': h['x-frame-options'] || null,
      'x-content-type-options': h['x-content-type-options'] || null,
      'referrer-policy': h['referrer-policy'] || null,
      'server': h['server'] || null,
      'set-cookie-present': Boolean(h['set-cookie']),
    };

    const evidencePayload = JSON.stringify({
      site_status: siteStatus,
      original_url: body.url,
      final_url: page.finalUrl,
      timestamp: ntp.iso,
      timestamp_source: ntp.source,
      timestamp_response_hash: ntp.response_hash,
      http_status: page.status,
      html_hash: page.htmlHash,
      html_truncated: page.htmlTruncated,
      html_full_size: page.htmlFullSize,
      rendered_dom_hash: renderedDom.hash,
      rendered_dom_size: renderedDom.bytes,
      rendered_dom_source: renderedDom.source,
      screenshot_hash: screenshotHash,
      screenshot_provider: shotResult.ok ? 'screenshotone.com' : null,
      screenshot_provider_request_id: shotResult.ok ? shotResult.value.providerRequestId : null,
      screenshot_provider_headers_hash: shotResult.ok ? shotResult.value.providerHeadersHash : null,
      screenshot_provider_edge_region: shotResult.ok ? shotResult.value.providerEdgeRegion : null,
      screenshot_fetched_at: shotResult.ok ? shotResult.value.fetchedAt : null,
      security_headers: securityHeaders,
      reachability,
      operator_ip: operatorIp,
      request_id: requestId,
      previous_evidence_hash: previousEvidenceHash,
    });
    const [evidenceHash, evidenceHashSha512] = await Promise.all([
      sha256Hex(evidencePayload),
      sha512Hex(evidencePayload),
    ]);

    const watermarkText = `TraceHub · ${evidenceHash.slice(0, 16)}…${evidenceHash.slice(-8)} · ${ntp.iso}`;

    return new Response(JSON.stringify({
      site_status: siteStatus,
      offline_evidence: null,
      wayback_suggestion: reachability.wayback.available
        ? { url: reachability.wayback.closest_url!, timestamp: reachability.wayback.closest_timestamp! }
        : null,
      reachability,
      original_url: body.url,
      final_url: page.finalUrl,
      timestamp: ntp.iso,
      timestamp_source: ntp.source,
      timestamp_response_hash: ntp.response_hash,
      timestamp_response_excerpt: ntp.response_excerpt,
      http_status: page.status,
      http_headers: page.headers,
      security_headers: securityHeaders,
      page_title: page.title,
      page_description: page.description,
      screenshot_base64: shotResult.ok ? shotResult.value.base64 : null,
      screenshot_mime: shotResult.ok ? shotResult.value.contentType : null,
      screenshot_hash: screenshotHash,
      screenshot_warning: screenshotWarning,
      screenshot_provider: shotResult.ok ? 'screenshotone.com' : null,
      screenshot_provider_request_id: shotResult.ok ? shotResult.value.providerRequestId : null,
      screenshot_provider_headers_hash: shotResult.ok ? shotResult.value.providerHeadersHash : null,
      screenshot_provider_edge_region: shotResult.ok ? shotResult.value.providerEdgeRegion : null,
      screenshot_fetched_at: shotResult.ok ? shotResult.value.fetchedAt : null,
      rendered_dom: renderedDom,
      previous_evidence_hash: previousEvidenceHash,
      watermark_text: watermarkText,
      html_hash: page.htmlHash,
      html_size: page.html.length,
      html_truncated: page.htmlTruncated,
      html_full_size: page.htmlFullSize,
      operator_ip: operatorIp,
      request_id: requestId,
      evidence_hash: evidenceHash,
      evidence_hash_sha512: evidenceHashSha512,
      evidence_hash_algorithm: 'SHA-256 + SHA-512 (FIPS 180-4)',
      evidence_payload: evidencePayload,
      capture_env: {
        user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        viewport_width: 1280,
        viewport_height: 800,
        device_scale_factor: 1,
        browser_engine: 'Chromium headless (ScreenshotOne)',
        collector: 'trace-hub-edge-fn/notarial-capture',
      },
    }), { status: 200, headers: { ...cors, 'Content-Type': 'application/json' } });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    console.error('[notarial-capture] fatal:', msg);
    return new Response(JSON.stringify({ error: msg }), {
      status: 500, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }
});
