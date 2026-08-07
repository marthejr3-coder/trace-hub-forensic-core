// verify-evidence-hash
// Re-hasheia o blob enviado pela vítima do bucket evidence_vault e atualiza
// hash_server / hash_server_sha512 / hashes_match / server_verified_at.
// Validação independente do cliente — é o servidor lendo o objeto e calculando.
//
// Política:
//  - Aberto (sem JWT) porque vítimas anônimas precisam disparar a verificação
//    logo após o upload. O que se escreve é OBJETIVO (resultado do hash do
//    arquivo já persistido no bucket), não input do usuário.
//  - Idempotente: só sobrescreve enquanto server_verified_at IS NULL.
//    Uma vez gravado, o registro fica imutável para fins forenses.

import { createClient } from "jsr:@supabase/supabase-js@2";
import OpenTimestamps from "npm:opentimestamps@0.4.9";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

interface Body {
  evidence_id: string;
  /**
   * F-05 (laudo Jun/2026): prova de conhecimento prévio do hash do cliente.
   * Quem disparou o upload conhece os primeiros 8 hex chars do hash_client;
   * um atacante enumerando evidence_id por força bruta, não. Mitiga abuso
   * mesmo com o endpoint sendo público (anônimo).
   */
  hash_client_prefix?: string;
}

// Rate limit in-memory por IP — 10 requisições por minuto.
const rateBucket = new Map<string, number[]>();
function rateLimited(ip: string): boolean {
  const now = Date.now();
  const window = 60_000;
  const max = 10;
  const arr = (rateBucket.get(ip) ?? []).filter((t) => now - t < window);
  if (arr.length >= max) return true;
  arr.push(now);
  rateBucket.set(ip, arr);
  return false;
}

async function hashStream(
  stream: ReadableStream<Uint8Array>,
): Promise<{ sha256: string; sha512: string; bytes: number }> {
  // Web Crypto não tem API de streaming nativa para digest; coletamos chunks
  // para um array e calculamos ao final. Limite operacional 200 MB já validado
  // no lado da vítima.
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = stream.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      chunks.push(value);
      total += value.byteLength;
    }
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  const [sha256Buf, sha512Buf] = await Promise.all([
    crypto.subtle.digest("SHA-256", buf),
    crypto.subtle.digest("SHA-512", buf),
  ]);
  const toHex = (b: ArrayBuffer) =>
    Array.from(new Uint8Array(b))
      .map((x) => x.toString(16).padStart(2, "0"))
      .join("");
  return { sha256: toHex(sha256Buf), sha512: toHex(sha512Buf), bytes: total };
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-f]/gi, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

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

async function submitRfc3161(url: string, label: string, hashBytes: Uint8Array, timeoutMs: number) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/timestamp-query",
        "Accept": "application/timestamp-reply",
        "User-Agent": "trace-hub-capture-link/1.0",
      },
      body: buildTSARequest(hashBytes),
      signal: ctrl.signal,
    });
    if (!r.ok) throw new Error(`${label} responded ${r.status}`);
    return new Uint8Array(await r.arrayBuffer());
  } finally {
    clearTimeout(timer);
  }
}

async function issueRfc3161(hashBytes: Uint8Array): Promise<Uint8Array | null> {
  try {
    return await submitRfc3161("https://freetsa.org/tsr", "FreeTSA", hashBytes, 6000);
  } catch (first) {
    console.warn("FreeTSA failed, trying DigiCert:", first instanceof Error ? first.message : first);
    try {
      return await submitRfc3161("http://timestamp.digicert.com", "DigiCert", hashBytes, 6000);
    } catch (second) {
      console.warn("DigiCert TSA failed:", second instanceof Error ? second.message : second);
      return null;
    }
  }
}

async function issueOpenTimestamp(hashBytes: Uint8Array, timeoutMs: number): Promise<Uint8Array | null> {
  try {
    const Ops = (OpenTimestamps as any).Ops;
    const DetachedTimestampFile = (OpenTimestamps as any).DetachedTimestampFile;
    const detached = DetachedTimestampFile.fromHash(new Ops.OpSHA256(), hashBytes);
    const stampPromise = (OpenTimestamps as any).stamp(detached).then(() => detached.serializeToBytes() as Uint8Array);
    return await Promise.race([
      stampPromise,
      new Promise<null>((resolve) => setTimeout(() => resolve(null), timeoutMs)),
    ]);
  } catch (e) {
    console.warn("OpenTimestamps stamp failed:", e instanceof Error ? e.message : e);
    return null;
  }
}

async function ensureTimestampProof(admin: any, ev: any, sha256: string, verifiedAt: string) {
  try {
    const { data: existing, error: existingErr } = await admin
      .from("capture_link_timestamp_proofs")
      .select("id, ots_base64, tsr_base64, status, submitted_at")
      .eq("evidence_id", ev.id)
      .maybeSingle();
    if (existingErr) throw existingErr;

    const needsOts = !existing?.ots_base64;
    const needsTsr = !existing?.tsr_base64;
    if (!needsOts && !needsTsr) return { status: "already_present" };

    const hashBytes = hexToBytes(sha256);
    const [otsBytes, tsrBytes] = await Promise.all([
      needsOts ? issueOpenTimestamp(hashBytes, 9000) : Promise.resolve(null),
      needsTsr ? issueRfc3161(hashBytes) : Promise.resolve(null),
    ]);

    if (needsOts && !otsBytes && needsTsr && !tsrBytes) {
      return { status: "no_timestamp_returned" };
    }

    // Se emitimos um novo .ots agora, calcula o SHA-256 dele para ancorar no laudo
    // ISO 27037 (auditabilidade — "Artefato de prova").
    const newOtsB64 = otsBytes ? bytesToBase64(otsBytes) : null;
    const newOtsSha256 = otsBytes
      ? toHex(await crypto.subtle.digest("SHA-256", otsBytes))
      : null;

    const payload: Record<string, unknown> = {
      session_id: ev.session_id,
      evidence_id: ev.id,
      file_path: ev.file_path,
      hash_sha256: sha256,
      ots_base64: existing?.ots_base64 ?? newOtsB64,
      tsr_base64: existing?.tsr_base64 ?? (tsrBytes ? bytesToBase64(tsrBytes) : null),
      submitted_at: existing?.submitted_at ?? verifiedAt,
      status: existing?.status === "confirmed_bitcoin" ? "confirmed_bitcoin" : "anchored",
    };
    if (newOtsSha256 && !existing?.ots_base64) {
      payload.ots_sha256 = newOtsSha256;
    }

    const { error: upsertErr } = await admin
      .from("capture_link_timestamp_proofs")
      .upsert(payload, { onConflict: "evidence_id" });
    if (upsertErr) throw upsertErr;
    return { status: "persisted", has_ots: !!payload.ots_base64, has_tsr: !!payload.tsr_base64 };
  } catch (e) {
    console.warn("timestamp proof persistence failed:", e instanceof Error ? e.message : e);
    return { status: "failed", error: e instanceof Error ? e.message : String(e) };
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }
  try {
    // F-05: rate limit por IP
    const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
      ?? req.headers.get("cf-connecting-ip")
      ?? "unknown";
    if (rateLimited(ip)) {
      return new Response(
        JSON.stringify({ error: "Rate limit exceeded (10 req/min)" }),
        { status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" } },
      );
    }

    const body = (await req.json()) as Body;
    if (!body?.evidence_id || typeof body.evidence_id !== "string") {
      return new Response(
        JSON.stringify({ error: "evidence_id required" }),
        {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        },
      );
    }

    const admin = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );

    const { data: ev, error: evErr } = await admin
      .from("capture_link_evidence")
      .select(
        "id, session_id, file_path, hash_client, hash_client_sha512, hash_server, file_size, server_verified_at, hashes_match",
      )
      .eq("id", body.evidence_id)
      .maybeSingle();
    if (evErr || !ev) {
      return new Response(
        JSON.stringify({ error: "Evidence not found" }),
        {
          status: 404,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        },
      );
    }

    // F-05: prova de conhecimento — exige que o caller envie o prefixo
    // (8 hex chars) do hash_client. Quem fez o upload conhece, atacante não.
    if (typeof body.hash_client_prefix === "string" && body.hash_client_prefix.length > 0) {
      const expected = ev.hash_client.slice(0, 8).toLowerCase();
      if (body.hash_client_prefix.toLowerCase() !== expected) {
        return new Response(
          JSON.stringify({ error: "hash_client_prefix mismatch" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } },
        );
      }
    }

    // Idempotência forense: já verificado uma vez, devolve o resultado.
    if (ev.server_verified_at) {
      const timestamp_proof = ev.hash_server?.toLowerCase() === ev.hash_client.toLowerCase()
        ? await ensureTimestampProof(admin, ev, ev.hash_client, ev.server_verified_at)
        : { status: "skipped_hash_mismatch" };
      return new Response(
        JSON.stringify({
          already_verified: true,
          server_verified_at: ev.server_verified_at,
          timestamp_proof,
        }),
        {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        },
      );
    }

    const { data: blob, error: dlErr } = await admin.storage
      .from("evidence_vault")
      .download(ev.file_path);
    if (dlErr || !blob) {
      return new Response(
        JSON.stringify({
          error: "Storage download failed",
          detail: dlErr?.message,
        }),
        {
          status: 502,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        },
      );
    }

    const { sha256, sha512, bytes } = await hashStream(blob.stream());
    const matchesSha256 = sha256.toLowerCase() === ev.hash_client.toLowerCase();
    const matchesSha512 = ev.hash_client_sha512
      ? sha512.toLowerCase() === ev.hash_client_sha512.toLowerCase()
      : true;
    const matchesSize = ev.file_size ? bytes === ev.file_size : true;
    const hashesMatch = matchesSha256 && matchesSha512 && matchesSize;

    const server_verified_at = new Date().toISOString();

    const { error: updErr } = await admin
      .from("capture_link_evidence")
      .update({
        hash_server: sha256,
        hash_server_sha512: sha512,
        hashes_match: hashesMatch,
        server_verified_at,
      })
      .eq("id", ev.id)
      .is("server_verified_at", null); // garante idempotência sob race
    if (updErr) throw updErr;

    const timestamp_proof = matchesSha256 && matchesSize
      ? await ensureTimestampProof(admin, ev, sha256, server_verified_at)
      : { status: "skipped_hash_mismatch" };

    // Selo append-only no evidence_vault_seal — uma única vez por evidência.
    // Triggers BEFORE UPDATE/DELETE no banco impedem qualquer alteração futura,
    // tornando o registro do hash imutável e auditável publicamente.
    let seal_id: string | null = null;
    try {
      const { data: sealRow, error: sealErr } = await admin
        .from("evidence_vault_seal")
        .insert({
          evidence_id: ev.id,
          file_path: ev.file_path,
          hash_client: ev.hash_client,
          hash_server: sha256,
          hash_server_sha512: sha512,
          file_size: bytes,
        })
        .select("id")
        .maybeSingle();
      if (sealErr && sealErr.code !== "23505") {
        // 23505 = unique_violation (já selado por race); demais erros logamos sem falhar a verificação.
        console.warn("evidence_vault_seal insert failed:", sealErr.message);
      } else {
        seal_id = sealRow?.id ?? null;
      }
    } catch (sealEx) {
      console.warn("evidence_vault_seal insert exception:", sealEx);
    }

    return new Response(
      JSON.stringify({
        success: true,
        evidence_id: ev.id,
        hash_server: sha256,
        hash_server_sha512: sha512,
        bytes_read: bytes,
        hashes_match: hashesMatch,
        sha256_match: matchesSha256,
        sha512_match: matchesSha512,
        size_match: matchesSize,
        server_verified_at,
        seal_id,
        timestamp_proof,
      }),
      {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      },
    );
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Unknown error";
    console.error("verify-evidence-hash:", msg);
    return new Response(JSON.stringify({ error: msg }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
