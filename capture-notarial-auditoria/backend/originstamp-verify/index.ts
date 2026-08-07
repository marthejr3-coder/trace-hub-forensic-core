// Notarial Verify — consulta status de confirmação Bitcoin do .ots emitido.
// Mantém o nome "originstamp-verify" por compatibilidade com o frontend.
//
// Estratégia: tenta fazer "upgrade" do .ots junto aos calendários públicos
// OpenTimestamps. Se o calendário já anexou prova Bitcoin, retorna confirmado.
import { createClient } from "jsr:@supabase/supabase-js@2";
import OpenTimestamps from "npm:opentimestamps@0.4.9";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "*, authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version, x-region",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
  "Access-Control-Max-Age": "86400",
  "Vary": "Origin, Access-Control-Request-Headers",
};

const CALENDARS = [
  "https://a.pool.opentimestamps.org",
  "https://b.pool.opentimestamps.org",
  "https://alice.btc.calendar.opentimestamps.org",
];

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-f]/gi, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

interface Body {
  evidence_hash?: string;
  timestamp_id?: string; // alias antigo: também aceitamos o hash aqui
  ots_base64?: string;
}

function base64ToBytes(base64: string): Uint8Array {
  const bin = atob(base64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Consulta um explorer Bitcoin público (mempool.space com fallback
 * blockstream.info) para obter block_hash, merkle_root e block_time
 * de uma altura. Ambos são explorers de nodes Bitcoin INDEPENDENTES
 * do Trace Hub — satisfaz o pilar de REPRODUTIBILIDADE (ISO 27037).
 */
async function fetchBlockMetadata(height: number): Promise<{
  block_hash: string | null;
  block_merkle_root: string | null;
  block_time: string | null;
} | null> {
  const sources = [
    { hashUrl: `https://mempool.space/api/block-height/${height}`, blockUrl: (h: string) => `https://mempool.space/api/block/${h}` },
    { hashUrl: `https://blockstream.info/api/block-height/${height}`, blockUrl: (h: string) => `https://blockstream.info/api/block/${h}` },
  ];
  for (const src of sources) {
    try {
      const hRes = await fetch(src.hashUrl);
      if (!hRes.ok) continue;
      const hash = (await hRes.text()).trim();
      if (!/^[0-9a-f]{64}$/.test(hash)) continue;
      const bRes = await fetch(src.blockUrl(hash));
      if (!bRes.ok) return { block_hash: hash, block_merkle_root: null, block_time: null };
      const b = await bRes.json();
      const timestampSec = typeof b?.timestamp === "number" ? b.timestamp : null;
      return {
        block_hash: hash,
        block_merkle_root: b?.merkle_root ?? b?.mrkl_root ?? null,
        block_time: timestampSec ? new Date(timestampSec * 1000).toISOString() : null,
      };
    } catch (e) {
      console.warn("[originstamp-verify] block metadata source falhou:", (e as Error).message);
    }
  }
  return null;
}

function detectBitcoinAttestation(buf: Uint8Array) {
  const TAG = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
  let confirmed = false;
  let blockHeight: number | null = null;

  for (let i = 0; i + TAG.length <= buf.length; i++) {
    let ok = true;
    for (let j = 0; j < TAG.length; j++) {
      if (buf[i + j] !== TAG[j]) { ok = false; break; }
    }
    if (!ok) continue;

    confirmed = true;
    try {
      let off = i + TAG.length;
      while (off < buf.length && (buf[off] & 0x80)) off++;
      off++;
      let h = 0; let shift = 0;
      while (off < buf.length) {
        const b = buf[off++];
        h |= (b & 0x7f) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
        // F-06 (laudo Jun/2026): clamp seguro de varint. Block height Bitcoin
        // cabe em 4 bytes (atual ~900k). Se shift > 28, payload está malformado —
        // não devolvemos altura potencialmente errada.
        if (shift > 28) { h = 0; break; }
      }
      if (h > 0) blockHeight = h;
    } catch { /* ignore */ }
    break;
  }

  return { confirmed, blockHeight };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    const token = authHeader.replace("Bearer ", "");
    const supa = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
    );
    const { data: { user }, error: authError } = await supa.auth.getUser(token);
    if (authError || !user) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const body = (await req.json().catch(() => ({}))) as Body;
    const candidate = (body.evidence_hash || body.timestamp_id || "").trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(candidate)) {
      return new Response(
        JSON.stringify({ error: "evidence_hash (SHA-256 hex 64 chars) required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } },
      );
    }

    if (body.ots_base64) {
      try {
        const Context = (OpenTimestamps as any).Context;
        const DetachedTimestampFile = (OpenTimestamps as any).DetachedTimestampFile;
        const ctx = new Context.StreamDeserialization(base64ToBytes(body.ots_base64));
        const detached = DetachedTimestampFile.deserialize(ctx);
        const changed = await (OpenTimestamps as any).upgrade(detached);
        const upgradedBytes = detached.serializeToBytes();
        const { confirmed, blockHeight } = detectBitcoinAttestation(upgradedBytes);
        const otsSha256 = await sha256Hex(upgradedBytes);
        let blockMeta: Awaited<ReturnType<typeof fetchBlockMetadata>> = null;
        if (confirmed && blockHeight) blockMeta = await fetchBlockMetadata(blockHeight);

        return new Response(JSON.stringify({
          success: true,
          evidence_hash: candidate,
          confirmed,
          confirmed_at: confirmed ? new Date().toISOString() : null,
          block_height: blockHeight,
          block_hash: blockMeta?.block_hash ?? null,
          block_merkle_root: blockMeta?.block_merkle_root ?? null,
          block_time: blockMeta?.block_time ?? null,
          ots_sha256: otsSha256,
          calendars: CALENDARS,
          upgraded_ots_base64: bytesToBase64(upgradedBytes),
          checks: [{
            calendar: "ots-upgrade",
            confirmed,
            block_height: blockHeight,
            note: changed ? "prova .ots atualizada com sucesso" : "prova .ots consultada sem mudanças"
          }],
          notice: confirmed
            ? `Confirmação Bitcoin via OpenTimestamps detectada${blockHeight ? ` (bloco #${blockHeight})` : ""}.`
            : "Arquivo .ots consultado, mas ainda sem bloco Bitcoin confirmado.",
        }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
      } catch (e) {
        console.warn("originstamp-verify upgrade warning:", e instanceof Error ? e.message : String(e));
      }
    }

    const digest = hexToBytes(candidate);
    const checks: Array<{ calendar: string; confirmed: boolean; note?: string }> = [];

    // Tenta consultar `/timestamp/<digest_hex>` em cada calendário. Se o calendário
    // já tem prova Bitcoin agregada, devolve um blob com a árvore Merkle até o
    // bloco. Se ainda não, devolve 404. Esse comportamento é o mesmo usado
    // pelo `ots upgrade` da CLI oficial.
    for (const cal of CALENDARS) {
      try {
        const r = await fetch(`${cal}/timestamp/${candidate}`, {
          method: "GET",
          headers: { "Accept": "application/octet-stream" },
        });
        if (r.status === 200) {
          const buf = new Uint8Array(await r.arrayBuffer());
          const { confirmed, blockHeight } = detectBitcoinAttestation(buf);
          checks.push({ calendar: cal, confirmed, ...(blockHeight ? { block_height: blockHeight } : {}) } as any);
        } else if (r.status === 404) {
          checks.push({ calendar: cal, confirmed: false, note: "ainda não agregado" });
        } else {
          checks.push({ calendar: cal, confirmed: false, note: `HTTP ${r.status}` });
        }
      } catch (e) {
        checks.push({ calendar: cal, confirmed: false, note: (e as Error).message });
      }
    }

    const confirmed = checks.some((c) => c.confirmed);
    const block_height = (checks.find((c: any) => c.block_height) as any)?.block_height ?? null;
    const blockMeta = confirmed && block_height ? await fetchBlockMetadata(block_height) : null;

    return new Response(
      JSON.stringify({
        success: true,
        evidence_hash: candidate,
        confirmed,
        confirmed_at: confirmed ? new Date().toISOString() : null,
        block_height,
        block_hash: blockMeta?.block_hash ?? null,
        block_merkle_root: blockMeta?.block_merkle_root ?? null,
        block_time: blockMeta?.block_time ?? null,
        calendars: CALENDARS,
        checks,
        notice: confirmed
          ? `Confirmação Bitcoin via OpenTimestamps detectada${block_height ? ` (bloco #${block_height})` : ""}.`
          : "Ainda aguardando bloco Bitcoin (1-6h após selagem). RFC 3161 já é prova suficiente.",
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } },
    );
  } catch (e) {
    const message = e instanceof Error ? e.message : "Unknown error";
    console.error("originstamp-verify (OTS) error:", message);
    return new Response(JSON.stringify({ error: message }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
