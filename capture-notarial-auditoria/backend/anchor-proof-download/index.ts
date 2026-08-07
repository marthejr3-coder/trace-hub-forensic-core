// anchor-proof-download — serve o .ots atualizado (mode=ots) ou os dados da
// ancoragem confirmada (mode=data) para a página pública /ancoragem/:id.
// Autorizado por token HMAC enviado no e-mail de confirmação.
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
  const mode = url.searchParams.get("mode") || "data";
  if (!id || !token) {
    return new Response(JSON.stringify({ error: "missing id or token" }), {
      status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  const secret = Deno.env.get("OTS_DOWNLOAD_SECRET") || "";
  const expected = await hmacSign(secret, id);
  if (!timingSafeEqual(token, expected)) {
    return new Response(JSON.stringify({ error: "invalid token" }), {
      status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  const supa = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  );
  const { data, error } = await supa
    .from("bitcoin_anchor_watch")
    .select("id,tool,ref_id,ref_label,evidence_hash,ots_base64,upgraded_ots_base64,tsr_base64,status,bitcoin_block_height,confirmed_at,created_at,payload")
    .eq("id", id)
    .maybeSingle();

  if (error || !data) {
    return new Response(JSON.stringify({ error: "not found" }), {
      status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  if (mode === "ots") {
    const b64 = data.upgraded_ots_base64 ?? data.ots_base64;
    if (!b64) {
      return new Response(JSON.stringify({ error: "ots not available yet" }), {
        status: 409, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    return new Response(base64ToBytes(b64), {
      status: 200,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/octet-stream",
        "Content-Disposition": `attachment; filename="ancoragem-${data.evidence_hash.slice(0, 12)}.ots"`,
      },
    });
  }

  if (mode === "tsr") {
    if (!data.tsr_base64) {
      return new Response(JSON.stringify({ error: "tsr not available" }), {
        status: 409, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    return new Response(base64ToBytes(data.tsr_base64), {
      status: 200,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/timestamp-reply",
        "Content-Disposition": `attachment; filename="ancoragem-${data.evidence_hash.slice(0, 12)}.tsr"`,
      },
    });
  }

  return new Response(JSON.stringify({ ok: true, anchor: data }), {
    status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
});
