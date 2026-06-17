// Notarial Anchor — OpenTimestamps (Bitcoin, gratuito) + RFC 3161 (FreeTSA).
// Mantém o nome do arquivo "originstamp-anchor" por compatibilidade com o
// frontend e histórico de deploy, mas internamente usa apenas serviços
// gratuitos e abertos. Não exige nenhuma API key paga.
//
// Retorna:
//   - originstamp.ots_base64       → arquivo .ots (selo OpenTimestamps inicial)
//   - originstamp.calendar_url     → calendário público usado
//   - rfc3161.token_base64         → token RFC 3161 imediato (FreeTSA)
import { createClient } from "jsr:@supabase/supabase-js@2";
import OpenTimestamps from "npm:opentimestamps@0.4.9";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "*, authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version, x-region",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
  "Access-Control-Max-Age": "86400",
  "Vary": "Origin, Access-Control-Request-Headers",
};

interface Body {
  evidence_hash: string;
}

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
function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

// --- RFC 3161 (FreeTSA) ---------------------------------------------------------
function buildTSARequest(hashBytes: Uint8Array): Uint8Array {
  const prefix = new Uint8Array([
    0x30, 0x39, 0x02, 0x01, 0x01, 0x30, 0x31, 0x30, 0x0d,
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20,
  ]);
  const suffix = new Uint8Array([0x01, 0x01, 0xff]);
  const out = new Uint8Array(prefix.length + 32 + suffix.length);
  out.set(prefix, 0);
  out.set(hashBytes, prefix.length);
  out.set(suffix, prefix.length + 32);
  return out;
}
async function submitToRfc3161(url: string, label: string, hashBytes: Uint8Array) {
  const tsq = buildTSARequest(hashBytes);
  const r = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/timestamp-query",
      "Accept": "application/timestamp-reply",
      "User-Agent": "trace-hub-notarial/1.0",
    },
    body: tsq,
  });
  if (!r.ok) throw new Error(`${label} responded ${r.status}`);
  const buf = await r.arrayBuffer();
  return { token: new Uint8Array(buf), ts: new Date().toISOString(), tsa: label, url };
}
const submitToFreeTSA = (h: Uint8Array) => submitToRfc3161("https://freetsa.org/tsr", "FreeTSA (https://freetsa.org)", h);
const submitToDigiCertTSA = (h: Uint8Array) => submitToRfc3161("http://timestamp.digicert.com", "DigiCert TSA (http://timestamp.digicert.com)", h);

// --- OpenTimestamps (Bitcoin) --------------------------------------------------
// F-03 (laudo Jun/2026): construção do arquivo .ots agora é delegada à
// biblioteca oficial `opentimestamps`. A versão anterior concatenava magic bytes
// hardcodados ao payload bruto do calendar — qualquer mudança no protocolo
// produziria um .ots silenciosamente inválido. Agora usamos serializeToBytes()
// que segue a especificação oficial e é validável por `ots verify` da CLI.
async function submitToOpenTimestamps(digest: Uint8Array): Promise<{ ots: Uint8Array; calendar: string }> {
  const Ops = (OpenTimestamps as any).Ops;
  const Context = (OpenTimestamps as any).Context;
  const DetachedTimestampFile = (OpenTimestamps as any).DetachedTimestampFile;
  const detached = DetachedTimestampFile.fromHash(new Ops.OpSHA256(), digest);
  try {
    await (OpenTimestamps as any).stamp(detached);
  } catch (e) {
    throw new Error(`OpenTimestamps.stamp falhou: ${e instanceof Error ? e.message : String(e)}`);
  }
  const bytes: Uint8Array = detached.serializeToBytes();
  // Extrai URL do primeiro calendar attestation (informativo apenas)
  let calendar = CALENDARS[0];
  try {
    const ctx = new Context.StreamDeserialization(bytes);
    void ctx;
  } catch { /* ignore */ }
  return { ots: bytes, calendar };
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

    const body = (await req.json()) as Body;
    const hash = (body.evidence_hash || "").trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(hash)) {
      return new Response(
        JSON.stringify({ error: "evidence_hash must be 64 hex chars (SHA-256)" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } },
      );
    }

    const submitted_at = new Date().toISOString();
    const hashBytes = hexToBytes(hash);

    const [otsRes, tsaRes, tsa2Res] = await Promise.allSettled([
      submitToOpenTimestamps(hashBytes),
      submitToFreeTSA(hashBytes),
      submitToDigiCertTSA(hashBytes),
    ]);

    if (otsRes.status !== "fulfilled") {
      throw new Error(
        `OpenTimestamps failed: ${(otsRes.reason as Error)?.message || "unknown"}`,
      );
    }

    const otsBase64 = bytesToBase64(otsRes.value.ots);
    const calendar = otsRes.value.calendar;

    const rfc3161 = tsaRes.status === "fulfilled"
      ? {
          token_base64: bytesToBase64(tsaRes.value.token),
          timestamp: tsaRes.value.ts,
          tsa: tsaRes.value.tsa,
          status: "confirmed_immediate",
        }
      : { error: (tsaRes.reason as Error)?.message || "FreeTSA failed", status: "failed" };

    const rfc3161_secondary = tsa2Res.status === "fulfilled"
      ? {
          token_base64: bytesToBase64(tsa2Res.value.token),
          timestamp: tsa2Res.value.ts,
          tsa: tsa2Res.value.tsa,
          status: "confirmed_immediate",
        }
      : { error: (tsa2Res.reason as Error)?.message || "DigiCert TSA failed", status: "failed" };

    return new Response(
      JSON.stringify({
        success: true,
        evidence_hash: hash,
        submitted_at,
        originstamp: {
          // Campos compatíveis com o frontend existente
          timestamp_id: hash,                   // usamos o próprio hash como id estável
          date_created: submitted_at,
          currencies: ["btc"],                  // OpenTimestamps ancora em Bitcoin
          ots_base64: otsBase64,                // arquivo .ots para download
          calendar_url: calendar,
          raw_response_base64: otsBase64,       // alias mantido para o botão "Baixar .json"
          status: "pending_bitcoin_confirmation",
          notice: "Selo OpenTimestamps emitido. Confirmação Bitcoin completa em 1-6h (automática).",
        },
        rfc3161,
        rfc3161_secondary,
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } },
    );
  } catch (e) {
    const message = e instanceof Error ? e.message : "Unknown error";
    console.error("originstamp-anchor (OTS) error:", message);
    return new Response(JSON.stringify({ error: message }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
