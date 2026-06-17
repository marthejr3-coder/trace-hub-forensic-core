// sealed-proxy-token — emite token efêmero opaco para o sealed-proxy.
//
// Substitui o uso de JWT longo na query string do iframe (F-02 do laudo v2).
// Cliente troca um JWT (no header) por um token opaco de 32 bytes, escopo
// (user_id, session_id), TTL 5 minutos. Armazenamos apenas SHA-256 do token.
//
// Resposta: { token, expires_at }

import { createClient } from "jsr:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "*, authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const TTL_MS = 5 * 60 * 1000;

function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256Hex(text: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const auth = req.headers.get("Authorization");
    if (!auth?.startsWith("Bearer ")) {
      return Response.json({ error: "unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const token = auth.replace("Bearer ", "");
    const userClient = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
    );
    const { data: { user }, error: uErr } = await userClient.auth.getUser(token);
    if (uErr || !user) {
      return Response.json({ error: "unauthorized" }, { status: 401, headers: corsHeaders });
    }

    const { session_id } = await req.json();
    if (!session_id) {
      return Response.json({ error: "session_id required" }, { status: 400, headers: corsHeaders });
    }

    const admin = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );

    const { data: session } = await admin
      .from("sealed_capture_sessions")
      .select("user_id, status")
      .eq("id", session_id)
      .maybeSingle();
    if (!session || session.user_id !== user.id || session.status !== "open") {
      return Response.json({ error: "session unavailable" }, { status: 403, headers: corsHeaders });
    }

    const raw = new Uint8Array(32);
    crypto.getRandomValues(raw);
    const opaque = b64url(raw);
    const token_hash = await sha256Hex(opaque);
    const expires_at = new Date(Date.now() + TTL_MS).toISOString();

    const { error: insErr } = await admin.from("sealed_proxy_tokens").insert({
      token_hash,
      session_id,
      user_id: user.id,
      expires_at,
    });
    if (insErr) {
      return Response.json({ error: insErr.message }, { status: 500, headers: corsHeaders });
    }

    // Best-effort cleanup of stale tokens (no await needed for correctness).
    admin.from("sealed_proxy_tokens").delete().lt("expires_at", new Date().toISOString())
      .then(() => {}, () => {});

    return Response.json({ token: opaque, expires_at }, { headers: corsHeaders });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return Response.json({ error: msg }, { status: 500, headers: corsHeaders });
  }
});
