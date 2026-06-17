// Sealed Proxy — fetches a remote URL server-side with locked UA, calculates
// SHA-256 of the response body, registers a 'network' event in the chain,
// and returns the response to the iframe with strict CSP injected.
//
// For HTML responses: rewrites absolute/relative URLs to flow through this
// proxy (so subresources are also captured + hashed). For non-HTML: returns
// as-is with same CSP container.
//
// This is the heart of the "ambiente lacrado": every byte rendered in the
// operator's iframe was first audited by us and is hash-recorded.

import { createClient } from "jsr:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "*, authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};

const LOCKED_UA =
  "Mozilla/5.0 (X11; Linux x86_64) TraceHubSealedCapture/1.0 (forensic) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

const GENESIS = "0".repeat(64);
const MAX_BODY_BYTES = 5 * 1024 * 1024; // 5 MB hard cap

const STRICT_CSP =
  "default-src 'self' data: blob: https:; " +
  "script-src 'unsafe-inline' 'unsafe-eval' https:; " +
  "style-src 'unsafe-inline' https: data:; " +
  "img-src data: blob: https:; " +
  "font-src data: https:; " +
  "frame-ancestors *; " +
  "form-action 'none'; " +
  "object-src 'none';";

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function buildProxyUrl(sessionId: string, target: string, token: string, opaque: boolean): string {
  const base =
    Deno.env.get("SUPABASE_URL")! + "/functions/v1/sealed-proxy";
  const param = opaque ? "t" : "token";
  return `${base}?sid=${encodeURIComponent(sessionId)}&u=${encodeURIComponent(target)}&${param}=${encodeURIComponent(token)}`;
}

function rewriteHtml(html: string, sessionId: string, baseUrl: string, token: string, opaque: boolean): string {
  // Remove <base> tags (we'll inject our own)
  let out = html.replace(/<base\b[^>]*>/gi, "");

  // Rewrite href/src/srcset/action attributes that look like http(s) or relative
  const attrRe = /\b(href|src|action|formaction|poster|data-src)\s*=\s*("([^"]*)"|'([^']*)')/gi;
  out = out.replace(attrRe, (full, attr, _q, dq, sq) => {
    const val = dq ?? sq ?? "";
    if (!val || val.startsWith("javascript:") || val.startsWith("data:") || val.startsWith("blob:") || val.startsWith("#") || val.startsWith("mailto:")) {
      return full;
    }
    try {
      const abs = new URL(val, baseUrl).toString();
      const proxied = buildProxyUrl(sessionId, abs, token, opaque);
      return `${attr}="${proxied}"`;
    } catch {
      return full;
    }
  });


  // Inject head banner indicating sealed environment + neutralize service workers
  const banner = `<script>
    if ('serviceWorker' in navigator) { try { navigator.serviceWorker.getRegistrations().then(rs => rs.forEach(r => r.unregister())); } catch(e){} }
    Object.defineProperty(navigator, 'serviceWorker', { get: () => undefined });
    window.__TRACEHUB_SEALED__ = true;
  </script>`;
  if (/<head[^>]*>/i.test(out)) {
    out = out.replace(/<head[^>]*>/i, (m) => `${m}${banner}`);
  } else {
    out = banner + out;
  }
  return out;
}

async function logNetworkEvent(opts: {
  sessionId: string;
  userId: string;
  url: string;
  method: string;
  status: number;
  contentType: string;
  byteLength: number;
  bodyHash: string;
}) {
  const admin = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  );
  const { data: last } = await admin
    .from("sealed_capture_events")
    .select("seq,event_hash")
    .eq("session_id", opts.sessionId)
    .order("seq", { ascending: false })
    .limit(1)
    .maybeSingle();
  const prev_hash = last?.event_hash ?? GENESIS;
  const seq = (last?.seq ?? 0) + 1;
  const created_at = new Date().toISOString();
  const payload = {
    url: opts.url,
    method: opts.method,
    status: opts.status,
    content_type: opts.contentType,
    byte_length: opts.byteLength,
    body_sha256: opts.bodyHash,
  };
  const payload_sha256 = await sha256Hex(
    new TextEncoder().encode(JSON.stringify(payload)),
  );
  const event_hash = await sha256Hex(
    new TextEncoder().encode(`${prev_hash}|${payload_sha256}|${created_at}`),
  );
  await admin.from("sealed_capture_events").insert({
    session_id: opts.sessionId,
    user_id: opts.userId,
    seq,
    event_type: "network",
    payload,
    payload_sha256,
    prev_hash,
    event_hash,
    created_at,
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const url = new URL(req.url);
    const sessionId = url.searchParams.get("sid");
    const target = url.searchParams.get("u");
    if (!sessionId || !target) {
      return new Response("sid and u query params required", {
        status: 400,
        headers: corsHeaders,
      });
    }

    // Auth: aceita token opaco efêmero (?t=) — preferencial — OU, como fallback
    // legado, JWT em Authorization header ou ?token=. O token opaco elimina o
    // vazamento de JWT longo em logs/histórico (F-02 do laudo v2).
    const opaque = url.searchParams.get("t");
    const auth = req.headers.get("Authorization");
    const queryToken = url.searchParams.get("token");
    const jwt = auth ? auth.replace("Bearer ", "") : queryToken;

    const admin = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );

    let userId: string | null = null;
    let proxyAuthToken = ""; // token to embed in rewritten URLs

    if (opaque) {
      // SHA-256 lookup, ttl check
      const hashBuf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(opaque));
      const tokenHash = Array.from(new Uint8Array(hashBuf)).map((b) => b.toString(16).padStart(2, "0")).join("");
      const { data: row } = await admin
        .from("sealed_proxy_tokens")
        .select("user_id, session_id, expires_at")
        .eq("token_hash", tokenHash)
        .maybeSingle();
      if (!row || new Date(row.expires_at) < new Date() || row.session_id !== sessionId) {
        return new Response("Unauthorized", { status: 401, headers: corsHeaders });
      }
      userId = row.user_id;
      proxyAuthToken = opaque;
    } else if (jwt) {
      const userClient = createClient(
        Deno.env.get("SUPABASE_URL")!,
        Deno.env.get("SUPABASE_ANON_KEY")!,
      );
      const { data: { user }, error: authErr } = await userClient.auth.getUser(jwt);
      if (authErr || !user) {
        return new Response("Unauthorized", { status: 401, headers: corsHeaders });
      }
      userId = user.id;
      proxyAuthToken = jwt;
    } else {
      return new Response("Unauthorized", { status: 401, headers: corsHeaders });
    }

    // Reconfirm session ownership + open status (defense in depth)
    const { data: sess } = await admin
      .from("sealed_capture_sessions")
      .select("user_id,status")
      .eq("id", sessionId)
      .maybeSingle();
    if (!sess || sess.user_id !== userId || sess.status !== "open") {
      return new Response("Session unavailable", { status: 403, headers: corsHeaders });
    }



    // Fetch target with locked UA
    const upstream = await fetch(target, {
      method: "GET",
      redirect: "follow",
      headers: {
        "User-Agent": LOCKED_UA,
        Accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
      },
    });

    const contentType = upstream.headers.get("content-type") ?? "";
    const buf = new Uint8Array(await upstream.arrayBuffer());
    if (buf.byteLength > MAX_BODY_BYTES) {
      return new Response(
        `Resource too large (${buf.byteLength} bytes, max ${MAX_BODY_BYTES})`,
        { status: 413, headers: corsHeaders },
      );
    }
    const bodyHash = await sha256Hex(buf);

    // Log event (don't await failures hard)
    try {
      await logNetworkEvent({
        sessionId,
        userId: userId!,
        url: upstream.url,
        method: "GET",
        status: upstream.status,
        contentType,
        byteLength: buf.byteLength,
        bodyHash,
      });
    } catch (e) {
      console.error("logNetworkEvent failed:", e);
    }

    const isHtml = /text\/html|application\/xhtml/i.test(contentType);
    let outBytes: Uint8Array = buf;
    let outType = contentType || "application/octet-stream";

    if (isHtml) {
      const html = new TextDecoder("utf-8").decode(buf);
      const rewritten = rewriteHtml(html, sessionId, upstream.url, proxyAuthToken, !!opaque);
      outBytes = new TextEncoder().encode(rewritten);
      outType = "text/html; charset=utf-8";
    }


    return new Response(outBytes, {
      status: upstream.status,
      headers: {
        ...corsHeaders,
        "Content-Type": outType,
        "Content-Security-Policy": STRICT_CSP,
        // F-02 (laudo Jun/2026): bloqueia vazamento do JWT via cabeçalho Referer
        // quando o iframe carrega sub-recursos externos. O token na query string
        // é Supabase access token de curta duração (validado por auth.getUser).
        "Referrer-Policy": "no-referrer",
        "X-Sealed-Body-Sha256": bodyHash,
        "X-Sealed-Upstream-Url": upstream.url,
        "Cache-Control": "no-store",
      },
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Unknown error";
    console.error("sealed-proxy:", msg);
    return new Response(`Proxy error: ${msg}`, {
      status: 500,
      headers: corsHeaders,
    });
  }
});
