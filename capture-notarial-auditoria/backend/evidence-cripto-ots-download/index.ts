// evidence-cripto-ots-download — devolve o arquivo .ots (upgraded) confirmado
// para uma coleta, autorizado por token HMAC enviado no link do e-mail.
import { createClient } from "jsr:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "*, authorization, content-type",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
};

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function hmacSign(secret: string, payload: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  const url = new URL(req.url);
  const id = url.searchParams.get("id");
  const token = url.searchParams.get("token");
  if (!id || !token) {
    return new Response("missing id or token", { status: 400, headers: corsHeaders });
  }

  const secret = Deno.env.get("OTS_DOWNLOAD_SECRET") || "";
  const expected = await hmacSign(secret, id);
  if (!timingSafeEqual(token, expected)) {
    return new Response("invalid token", { status: 403, headers: corsHeaders });
  }

  const supa = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  );
  const { data, error } = await supa
    .from("evidence_cripto_collections")
    .select("ots_upgraded_base64, ots_status, package_sha256")
    .eq("id", id)
    .single();

  if (error || !data) {
    return new Response("not found", { status: 404, headers: corsHeaders });
  }
  if (data.ots_status !== "confirmed" || !data.ots_upgraded_base64) {
    return new Response("ots not yet confirmed", { status: 409, headers: corsHeaders });
  }

  const bytes = base64ToBytes(data.ots_upgraded_base64);
  return new Response(bytes, {
    status: 200,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/octet-stream",
      "Content-Disposition": `attachment; filename="evidence-cripto-${data.package_sha256.slice(0, 12)}.ots"`,
    },
  });
});
