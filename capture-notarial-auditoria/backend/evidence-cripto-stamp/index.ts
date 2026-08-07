// Evidence Cripto — selo temporal síncrono rápido.
//
// 1. RFC 3161 (FreeTSA, fallback DigiCert) — bloqueante, ≤ 6s.
// 2. OpenTimestamps.stamp — tentativa síncrona com timeout curto (~5s).
//    Se passar, status='processing' já com .ots inicial.
//    Se exceder o timeout, status='pending' e o worker terminará depois.
// 3. INSERT na evidence_cripto_collections e devolve collection_id +
//    rfc3161 imediato pro frontend liberar o download.
import { createClient } from "jsr:@supabase/supabase-js@2";
import OpenTimestamps from "npm:opentimestamps@0.4.9";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "*, authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

interface Body {
  package_sha256: string;
  pdf_sha256?: string;
  collection_label?: string;
  victim_email?: string;
}

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

// --- RFC 3161 ---------------------------------------------------------------
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
async function submitRfc3161(url: string, tsa: string, hashBytes: Uint8Array, timeoutMs: number) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/timestamp-query",
        "Accept": "application/timestamp-reply",
        "User-Agent": "trace-hub-evidence-cripto/1.0",
      },
      body: buildTSARequest(hashBytes),
      signal: ctrl.signal,
    });
    if (!r.ok) throw new Error(`${tsa} responded ${r.status}`);
    const buf = await r.arrayBuffer();
    return { token: new Uint8Array(buf), tsa, url };
  } finally {
    clearTimeout(t);
  }
}

async function tryRfc3161(hashBytes: Uint8Array) {
  try {
    return await submitRfc3161("https://freetsa.org/tsr", "FreeTSA", hashBytes, 6000);
  } catch (e) {
    console.warn("FreeTSA failed, trying DigiCert:", e instanceof Error ? e.message : e);
    return await submitRfc3161("http://timestamp.digicert.com", "DigiCert", hashBytes, 6000);
  }
}

// --- OpenTimestamps (best-effort, com timeout) -----------------------------
async function tryOpenTimestamps(digest: Uint8Array, timeoutMs: number): Promise<Uint8Array | null> {
  try {
    const Ops = (OpenTimestamps as any).Ops;
    const DetachedTimestampFile = (OpenTimestamps as any).DetachedTimestampFile;
    const detached = DetachedTimestampFile.fromHash(new Ops.OpSHA256(), digest);
    const stamped = (OpenTimestamps as any).stamp(detached);
    const winner = await Promise.race([
      stamped.then(() => detached.serializeToBytes() as Uint8Array),
      new Promise<null>((resolve) => setTimeout(() => resolve(null), timeoutMs)),
    ]);
    return winner ?? null;
  } catch (e) {
    console.warn("OpenTimestamps stamp falhou no síncrono:", e instanceof Error ? e.message : e);
    return null;
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const auth = req.headers.get("Authorization");
    if (!auth) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    const token = auth.replace("Bearer ", "");
    const supaUser = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
    );
    const { data: { user }, error: authError } = await supaUser.auth.getUser(token);
    if (authError || !user) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const body = (await req.json()) as Body;
    const hash = (body.package_sha256 || "").trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(hash)) {
      return new Response(JSON.stringify({ error: "package_sha256 must be 64 hex chars" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    const pdfHash = (body.pdf_sha256 || "").trim().toLowerCase() || null;
    if (pdfHash && !/^[0-9a-f]{64}$/.test(pdfHash)) {
      return new Response(JSON.stringify({ error: "pdf_sha256 must be 64 hex chars" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const hashBytes = hexToBytes(hash);
    const notifyEmail = (body.victim_email || user.email || "").trim();
    if (!notifyEmail) {
      return new Response(JSON.stringify({ error: "no email available for notifications" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // RFC 3161 imediato (bloqueante) + OTS best-effort em paralelo
    const [rfcRes, otsBytes] = await Promise.all([
      tryRfc3161(hashBytes).catch((e) => ({ error: e instanceof Error ? e.message : String(e) })),
      tryOpenTimestamps(hashBytes, 5000),
    ]);

    const rfcOk = (rfcRes as any).token instanceof Uint8Array;
    const tsrBase64 = rfcOk ? bytesToBase64((rfcRes as any).token) : null;
    const rfcTsa = rfcOk ? (rfcRes as any).tsa : null;

    if (!rfcOk) {
      // RFC 3161 é o piso mínimo — se falhar, não bloqueia o usuário mas registramos coleta como pending
      console.warn("RFC 3161 falhou:", (rfcRes as any).error);
    }

    const otsStatus = otsBytes ? "processing" : "pending";
    const otsBase64 = otsBytes ? bytesToBase64(otsBytes) : null;

    const supaService = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );
    const { data: inserted, error: insertErr } = await supaService
      .from("evidence_cripto_collections")
      .insert({
        user_id: user.id,
        collection_label: body.collection_label || null,
        victim_email: body.victim_email || null,
        notify_email: notifyEmail,
        package_sha256: hash,
        pdf_sha256: pdfHash,
        rfc3161_tsr_base64: tsrBase64,
        rfc3161_tsa: rfcTsa,
        rfc3161_stamped_at: rfcOk ? new Date().toISOString() : null,
        ots_status: otsStatus,
        ots_pending_base64: otsBase64,
      })
      .select("id, rfc3161_stamped_at, ots_status")
      .single();

    if (insertErr) {
      console.error("insert error:", insertErr);
      return new Response(JSON.stringify({ error: insertErr.message }), {
        status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({
      success: true,
      collection_id: inserted.id,
      rfc3161: rfcOk ? { tsa: rfcTsa, tsr_base64: tsrBase64, stamped_at: inserted.rfc3161_stamped_at } : { error: (rfcRes as any).error },
      ots_status: inserted.ots_status,
    }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    console.error("evidence-cripto-stamp error:", message);
    return new Response(JSON.stringify({ error: message }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
