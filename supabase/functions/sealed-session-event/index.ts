// Sealed Capture — registra um evento na cadeia encadeada da sessão.
// Calcula payload_sha256, valida prev_hash contra o último evento da sessão,
// calcula event_hash = sha256(prev_hash || payload_sha256 || created_at_iso)
// e insere via service_role (clientes não podem escrever direto na tabela).
import { createClient } from "jsr:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "*, authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const GENESIS = "0".repeat(64);

type EventType =
  | "navigation"
  | "screenshot"
  | "fullpage"
  | "network"
  | "console"
  | "user_action"
  | "close";

interface Body {
  session_id: string;
  event_type: EventType;
  payload: Record<string, unknown>;
}

async function sha256Hex(input: string | Uint8Array): Promise<string> {
  const bytes =
    typeof input === "string" ? new TextEncoder().encode(input) : input;
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const auth = req.headers.get("Authorization");
    if (!auth) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    const token = auth.replace("Bearer ", "");

    const userClient = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
    );
    const { data: { user }, error: authErr } = await userClient.auth.getUser(token);
    if (authErr || !user) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const body = (await req.json()) as Body;
    if (!body?.session_id || !body?.event_type) {
      return new Response(JSON.stringify({ error: "session_id and event_type required" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const admin = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );

    // Confirma que a sessão pertence ao user e ainda está aberta
    const { data: session, error: sErr } = await admin
      .from("sealed_capture_sessions")
      .select("id,user_id,status")
      .eq("id", body.session_id)
      .maybeSingle();
    if (sErr || !session) {
      return new Response(JSON.stringify({ error: "Session not found" }), {
        status: 404,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    if (session.user_id !== user.id) {
      return new Response(JSON.stringify({ error: "Forbidden" }), {
        status: 403,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    if (session.status !== "open") {
      return new Response(JSON.stringify({ error: "Session is not open" }), {
        status: 409,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Busca último evento para obter prev_hash e seq
    const { data: last } = await admin
      .from("sealed_capture_events")
      .select("seq,event_hash")
      .eq("session_id", body.session_id)
      .order("seq", { ascending: false })
      .limit(1)
      .maybeSingle();

    const prev_hash = last?.event_hash ?? GENESIS;
    const seq = (last?.seq ?? 0) + 1;
    const created_at = new Date().toISOString();
    const payloadStr = JSON.stringify(body.payload ?? {});
    const payload_sha256 = await sha256Hex(payloadStr);
    const event_hash = await sha256Hex(
      `${prev_hash}|${payload_sha256}|${created_at}`,
    );

    const { error: iErr } = await admin.from("sealed_capture_events").insert({
      session_id: body.session_id,
      user_id: user.id,
      seq,
      event_type: body.event_type,
      payload: body.payload ?? {},
      payload_sha256,
      prev_hash,
      event_hash,
      created_at,
    });
    if (iErr) {
      return new Response(JSON.stringify({ error: iErr.message }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response(
      JSON.stringify({ success: true, seq, prev_hash, event_hash, created_at }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } },
    );
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Unknown error";
    console.error("sealed-session-event:", msg);
    return new Response(JSON.stringify({ error: msg }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
