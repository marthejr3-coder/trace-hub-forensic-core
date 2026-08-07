// check-bitcoin-anchors — robô multi-ferramenta de confirmação Bitcoin.
//
// Percorre `bitcoin_anchor_watch` (registros criados pela função
// `originstamp-anchor`, usada por TODAS as ferramentas que ancoram hash:
// Capture Notarial, Capture Link, Sessão Selada, Gravação de Tela, laudos de
// metadados, WhatsApp forense…), tenta o upgrade do arquivo .ots e, ao detectar
// a prova em bloco Bitcoin:
//   1. grava o resultado de volta na ferramenta de origem;
//   2. envia e-mail ao usuário com a Certidão de Ancoragem e o .ots atualizado.
//
// Agendado via pg_cron a cada 30 min. Auth: x-cron-secret OU Bearer anon/service.
import { createClient } from "jsr:@supabase/supabase-js@2";
import OpenTimestamps from "npm:opentimestamps@0.4.9";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "*, authorization, x-cron-secret, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const MAX_HOURS_BEFORE_FAILED = 96;
const BATCH_SIZE = 40;

const TOOL_LABEL: Record<string, string> = {
  ata_notarial: "Capture Notarial (Ata Notarial Digital)",
  capture_link: "Capture Link",
  sealed_capture: "Sessão Selada",
  gravacao_tela: "Gravação de Tela",
  metadados: "Laudo de Metadados",
  whatsapp: "Validação WhatsApp",
  desconhecido: "Trace Hub",
};

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-f]/gi, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}
function nextCheckAfterSeconds(attempts: number): number {
  return Math.min(300 * Math.pow(2, attempts), 21600);
}
async function hmacSign(secret: string, payload: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Parser binário da attestation Bitcoin (mesmo de originstamp-verify).
function detectBitcoinAttestation(buf: Uint8Array): { confirmed: boolean; blockHeight: number | null } {
  const TAG = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
  for (let i = 0; i + TAG.length <= buf.length; i++) {
    let ok = true;
    for (let j = 0; j < TAG.length; j++) {
      if (buf[i + j] !== TAG[j]) { ok = false; break; }
    }
    if (!ok) continue;
    let blockHeight: number | null = null;
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
        if (shift > 28) { h = 0; break; }
      }
      if (h > 0) blockHeight = h;
    } catch { /* ignore */ }
    return { confirmed: true, blockHeight };
  }
  return { confirmed: false, blockHeight: null };
}

interface Watch {
  id: string;
  user_id: string | null;
  tool: string;
  ref_id: string | null;
  ref_label: string | null;
  evidence_hash: string;
  ots_base64: string | null;
  status: string;
  attempts: number;
  last_check_at: string | null;
  notify_email: string | null;
  notified_at: string | null;
  created_at: string;
}

/** Grava a confirmação de volta na ferramenta de origem. Best-effort. */
async function writeBackToTool(supa: any, w: Watch, block: number | null, upgraded: string, confirmedAt: string) {
  try {
    if (w.tool === "ata_notarial") {
      await supa.from("forensic_report_stamps").insert({
        user_id: w.user_id,
        evidence_hash: w.evidence_hash,
        kind: "bitcoin_confirmation",
        status: "confirmed_bitcoin",
        bitcoin_block_height: block,
        payload: {
          ots_base64: upgraded,
          ots_confirmed_at: confirmedAt,
          bitcoin_block_height: block,
          explorer_url: block ? `https://mempool.space/block/${block}` : null,
          source: "check-bitcoin-anchors",
        },
      });
    } else if (w.tool === "capture_link") {
      await supa.from("capture_link_timestamp_proofs")
        .update({
          status: "confirmed_bitcoin",
          ots_base64: upgraded,
          ots_confirmed_at: confirmedAt,
          verified_at: confirmedAt,
          bitcoin_block_height: block,
          explorer_url: block ? `https://mempool.space/block/${block}` : null,
        })
        .eq("hash_sha256", w.evidence_hash);
    } else if (w.tool === "evidence_cripto") {
      await supa.from("evidence_cripto_collections")
        .update({
          ots_status: "confirmed",
          ots_upgraded_base64: upgraded,
          ots_bitcoin_block: block,
          ots_confirmed_at: confirmedAt,
        })
        .eq("package_sha256", w.evidence_hash);
    }
  } catch (e) {
    console.error("[write-back] falhou", w.tool, e instanceof Error ? e.message : e);
  }
}

async function notifyConfirmed(supa: any, w: Watch, block: number | null, confirmedAt: string) {
  const secret = Deno.env.get("OTS_DOWNLOAD_SECRET") || "";
  const appUrl = Deno.env.get("APP_URL") || "https://www.trace-hub.com";
  const sig = await hmacSign(secret, w.id);
  const certUrl = `${appUrl}/ancoragem/${w.id}?token=${sig}`;
  const otsUrl = `${Deno.env.get("SUPABASE_URL")}/functions/v1/anchor-proof-download?id=${w.id}&token=${sig}&mode=ots`;
  const recipient = w.notify_email;
  if (!recipient) return;

  try {
    await supa.functions.invoke("send-transactional-email", {
      body: {
        templateName: "bitcoin-anchor-confirmed",
        recipientEmail: recipient,
        idempotencyKey: `anchor-confirmed-${w.id}`,
        templateData: {
          toolLabel: TOOL_LABEL[w.tool] ?? TOOL_LABEL.desconhecido,
          refLabel: w.ref_label,
          evidenceHash: w.evidence_hash,
          bitcoinBlock: block,
          confirmedAt: new Date(confirmedAt).toLocaleString("pt-BR"),
          explorerUrl: block ? `https://mempool.space/block/${block}` : null,
          certUrl,
          otsUrl,
        },
      },
    });
    await supa.from("bitcoin_anchor_watch")
      .update({ notified_at: new Date().toISOString() })
      .eq("id", w.id);
  } catch (e) {
    console.error("notify failed:", e instanceof Error ? e.message : e);
  }
}

async function processWatch(supa: any, w: Watch): Promise<string> {
  const Ops = (OpenTimestamps as any).Ops;
  const DetachedTimestampFile = (OpenTimestamps as any).DetachedTimestampFile;
  const Context = (OpenTimestamps as any).Context;
  const now = new Date().toISOString();

  // Sem .ots ainda → emite o selo agora (start automático de fato)
  if (!w.ots_base64) {
    try {
      const detached = DetachedTimestampFile.fromHash(new Ops.OpSHA256(), hexToBytes(w.evidence_hash));
      await (OpenTimestamps as any).stamp(detached);
      await supa.from("bitcoin_anchor_watch").update({
        ots_base64: bytesToBase64(detached.serializeToBytes()),
        status: "processing",
        attempts: w.attempts + 1,
        last_check_at: now,
        error: null,
      }).eq("id", w.id);
      return "stamped";
    } catch (e) {
      await supa.from("bitcoin_anchor_watch").update({
        attempts: w.attempts + 1,
        last_check_at: now,
        error: (e instanceof Error ? e.message : String(e)).slice(0, 500),
      }).eq("id", w.id);
      return "stamp_failed";
    }
  }

  try {
    const ctx = new Context.StreamDeserialization(base64ToBytes(w.ots_base64));
    const detached = DetachedTimestampFile.deserialize(ctx);
    await (OpenTimestamps as any).upgrade(detached);
    const upgradedBytes: Uint8Array = detached.serializeToBytes();
    const { confirmed, blockHeight } = detectBitcoinAttestation(upgradedBytes);
    const upgraded = bytesToBase64(upgradedBytes);

    if (confirmed) {
      const confirmedAt = now;
      await supa.from("bitcoin_anchor_watch").update({
        status: "confirmed",
        upgraded_ots_base64: upgraded,
        ots_base64: upgraded,
        bitcoin_block_height: blockHeight,
        confirmed_at: confirmedAt,
        attempts: w.attempts + 1,
        last_check_at: now,
        error: null,
      }).eq("id", w.id);
      await writeBackToTool(supa, w, blockHeight, upgraded, confirmedAt);
      if (!w.notified_at) await notifyConfirmed(supa, w, blockHeight, confirmedAt);
      return "confirmed";
    }

    await supa.from("bitcoin_anchor_watch").update({
      status: "processing",
      ots_base64: upgraded,
      attempts: w.attempts + 1,
      last_check_at: now,
    }).eq("id", w.id);
    return "still_processing";
  } catch (e) {
    await supa.from("bitcoin_anchor_watch").update({
      attempts: w.attempts + 1,
      last_check_at: now,
      error: (e instanceof Error ? e.message : String(e)).slice(0, 500),
    }).eq("id", w.id);
    return "upgrade_failed";
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  const cronSecret = req.headers.get("x-cron-secret");
  const authBearer = (req.headers.get("Authorization") || "").replace("Bearer ", "");
  const expectedCron = Deno.env.get("OTS_CRON_SECRET");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const ok = (cronSecret && expectedCron && cronSecret === expectedCron)
    || (authBearer && (authBearer === serviceKey || authBearer === anonKey));
  if (!ok) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  const supa = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  );

  const now = new Date();
  const failedCutoff = new Date(now.getTime() - MAX_HOURS_BEFORE_FAILED * 3600_000);

  const { data: candidates, error } = await supa
    .from("bitcoin_anchor_watch")
    .select("id,user_id,tool,ref_id,ref_label,evidence_hash,ots_base64,status,attempts,last_check_at,notify_email,notified_at,created_at")
    .in("status", ["pending", "processing"])
    .order("last_check_at", { ascending: true, nullsFirst: true })
    .limit(BATCH_SIZE);

  if (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  const eligible = (candidates || []).filter((w: Watch) => {
    if (!w.last_check_at) return true;
    return now.getTime() - new Date(w.last_check_at).getTime() >= nextCheckAfterSeconds(w.attempts) * 1000;
  });

  let confirmed = 0, stamped = 0, stillProcessing = 0, failed = 0;

  for (const w of eligible) {
    if (new Date(w.created_at) < failedCutoff) {
      const errMsg = "Bloco Bitcoin não confirmado após 96h";
      await supa.from("bitcoin_anchor_watch").update({
        status: "failed",
        failed_at: now.toISOString(),
        last_check_at: now.toISOString(),
        attempts: w.attempts + 1,
        error: errMsg,
      }).eq("id", w.id);
      if (w.notify_email && !w.notified_at) {
        try {
          await supa.functions.invoke("send-transactional-email", {
            body: {
              templateName: "evidence-cripto-bitcoin-failed",
              recipientEmail: w.notify_email,
              idempotencyKey: `anchor-failed-${w.id}`,
              templateData: {
                collectionId: w.evidence_hash.slice(0, 16),
                collectionLabel: w.ref_label ?? TOOL_LABEL[w.tool] ?? null,
                collectedAt: new Date(w.created_at).toLocaleString("pt-BR"),
                error: errMsg,
              },
            },
          });
          await supa.from("bitcoin_anchor_watch")
            .update({ notified_at: new Date().toISOString() }).eq("id", w.id);
        } catch { /* best-effort */ }
      }
      failed++;
      continue;
    }

    const outcome = await processWatch(supa, w);
    if (outcome === "confirmed") confirmed++;
    else if (outcome === "stamped") stamped++;
    else if (outcome === "still_processing") stillProcessing++;
  }

  return new Response(JSON.stringify({
    processed: eligible.length, confirmed, stamped, stillProcessing, failed,
  }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
});
